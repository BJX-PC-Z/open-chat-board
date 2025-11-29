from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.sql import func
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
from typing import Optional

# 数据库配置
SQLALCHEMY_DATABASE_URL = "sqlite:///./chat_board.db"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# 数据库模型
class Admin(Base):
    __tablename__ = "admins"
    id = Column(Integer, primary_key=True, index=True)
    admin_id = Column(String(50), unique=True, index=True)
    password = Column(String(100))
    is_super = Column(Boolean, default=False)  # 第一管理员标识
    created_at = Column(DateTime, server_default=func.now())

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text)
    author_type = Column(String(20), default="visitor")  # visitor/admin
    author_id = Column(String(50))  # 游客为"visitor"，管理员为admin_id
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())
    is_deleted = Column(Boolean, default=False)

# 数据校验模型
class AdminLogin(BaseModel):
    admin_id: str
    password: str

class AdminCreate(BaseModel):  # 第一管理员创建新管理员用
    admin_id: str
    password: str

class AdminUpdate(BaseModel):  # 管理员修改自身信息用
    old_admin_id: str
    old_password: str
    new_admin_id: Optional[str] = None
    new_password: Optional[str] = None

class MessageCreate(BaseModel):
    content: str = Field(min_length=1, max_length=5000)

class MessageUpdate(BaseModel):
    message_id: int
    new_content: str = Field(min_length=1, max_length=5000)

class MessageDelete(BaseModel):
    message_id: int

# 认证配置
SECRET_KEY = "chat_board_secret_key_2025"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="admin/login")

# 密码工具函数
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password[:72])  # 限制密码长度（bcrypt要求）

# 管理员认证依赖
def get_current_admin(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无法验证凭据",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        admin_id: str = payload.get("sub")
        if admin_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    admin = db.query(Admin).filter(Admin.admin_id == admin_id).first()
    if admin is None:
        raise credentials_exception
    return admin

# 第一管理员权限依赖
def is_super_admin(current_admin: Admin = Depends(get_current_admin)):
    if not current_admin.is_super:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="需要第一管理员权限"
        )
    return current_admin

# 主程序
app = FastAPI(title="开放聊天板API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 初始化数据库和第一管理员
Base.metadata.create_all(bind=engine)
@app.on_event("startup")
def create_super_admin():
    db = next(get_db())
    # 检查第一管理员是否已存在
    super_admin = db.query(Admin).filter(Admin.admin_id == "BA00001-1730962007").first()
    if not super_admin:
        # 创建第一管理员（固定账号密码）
        hashed_password = get_password_hash("173096qyy11451420122007")
        new_super_admin = Admin(
            admin_id="BA00001-1730962007",
            password=hashed_password,
            is_super=True  # 标记为第一管理员
        )
        db.add(new_super_admin)
        db.commit()
    db.close()

# 管理员接口
@app.post("/admin/login")
def admin_login(admin: AdminLogin, db: Session = Depends(get_db)):
    """管理员登录"""
    db_admin = db.query(Admin).filter(Admin.admin_id == admin.admin_id).first()
    if not db_admin or not verify_password(admin.password, db_admin.password):
        raise HTTPException(status_code=401, detail="账号ID或密码错误")
    # 生成令牌
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = jwt.encode(
        {
            "sub": db_admin.admin_id,
            "exp": datetime.utcnow() + access_token_expires,
            "is_super": db_admin.is_super
        },
        SECRET_KEY,
        algorithm=ALGORITHM
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "admin_id": db_admin.admin_id,
        "is_super": db_admin.is_super
    }

@app.post("/admin/create")
def create_admin(
    new_admin: AdminCreate,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(is_super_admin)  # 仅第一管理员可创建
):
    """创建新管理员（仅第一管理员可用）"""
    if db.query(Admin).filter(Admin.admin_id == new_admin.admin_id).first():
        raise HTTPException(status_code=400, detail="管理员账号已存在")
    hashed_password = get_password_hash(new_admin.password)
    admin = Admin(
        admin_id=new_admin.admin_id,
        password=hashed_password,
        is_super=False  # 新创建的是普通管理员
    )
    db.add(admin)
    db.commit()
    return {"message": "管理员创建成功", "admin_id": admin.admin_id}

@app.put("/admin/update")
def update_admin(
    update_info: AdminUpdate,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin)  # 所有管理员可修改自身信息
):
    """修改管理员自身账号/密码"""
    # 验证原账号密码
    if (current_admin.admin_id != update_info.old_admin_id or 
        not verify_password(update_info.old_password, current_admin.password)):
        raise HTTPException(status_code=401, detail="原账号ID或密码错误")
    # 修改账号
    if update_info.new_admin_id:
        if db.query(Admin).filter(Admin.admin_id == update_info.new_admin_id).first():
            raise HTTPException(status_code=400, detail="新账号ID已存在")
        current_admin.admin_id = update_info.new_admin_id
    # 修改密码
    if update_info.new_password:
        current_admin.password = get_password_hash(update_info.new_password)
    db.commit()
    return {"message": "信息更新成功", "new_admin_id": current_admin.admin_id}

# 留言接口
@app.post("/message/create")
def create_message(
    message: MessageCreate,
    db: Session = Depends(get_db),
    current_admin: Optional[Admin] = Depends(get_current_admin)  # 可选：登录时为管理员，否则为游客
):
    """创建留言（游客/管理员均可）"""
    if current_admin:  # 管理员留言
        author_type = "admin"
        author_id = current_admin.admin_id
    else:  # 游客留言
        author_type = "visitor"
        author_id = "visitor"
    db_message = Message(
        content=message.content,
        author_type=author_type,
        author_id=author_id
    )
    db.add(db_message)
    db.commit()
    return {
        "message_id": db_message.id,
        "content": db_message.content,
        "created_at": db_message.created_at
    }

@app.get("/message/list")
def get_message_list(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """获取所有留言（所有人可见）"""
    messages = db.query(Message).filter(
        Message.is_deleted == False
    ).order_by(
        Message.created_at.desc()
    ).offset(skip).limit(limit).all()
    return [
        {
            "id": msg.id,
            "content": msg.content,
            "author_type": msg.author_type,
            "author_id": msg.author_id,
            "created_at": msg.created_at,
            "updated_at": msg.updated_at
        } for msg in messages
    ]

@app.put("/message/update")
def update_message(
    update_info: MessageUpdate,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin)
):
    """修改留言（权限控制）"""
    message = db.query(Message).filter(
        Message.id == update_info.message_id,
        Message.is_deleted == False
    ).first()
    if not message:
        raise HTTPException(status_code=404, detail="留言不存在或已被删除")
    
    # 权限判断：
    # 1. 第一管理员：可修改所有留言
    # 2. 普通管理员：只能修改游客留言或自己的留言
    if not current_admin.is_super:
        if (message.author_type == "admin" and 
            message.author_id != current_admin.admin_id):
            raise HTTPException(
                status_code=403,
                detail="普通管理员仅可修改游客留言或自己的留言"
            )
    
    message.content = update_info.new_content
    db.commit()
    return {"message": "留言修改成功", "message_id": message.id}

@app.delete("/message/delete")
def delete_message(
    delete_info: MessageDelete,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin)
):
    """删除留言（权限控制）"""
    message = db.query(Message).filter(
        Message.id == delete_info.message_id,
        Message.is_deleted == False
    ).first()
    if not message:
        raise HTTPException(status_code=404, detail="留言不存在或已被删除")
    
    # 权限判断：
    # 1. 第一管理员：可删除所有留言
    # 2. 普通管理员：只能删除游客留言或自己的留言
    if not current_admin.is_super:
        if (message.author_type == "admin" and 
            message.author_id != current_admin.admin_id):
            raise HTTPException(
                status_code=403,
                detail="普通管理员仅可删除游客留言或自己的留言"
            )
    
    message.is_deleted = True
    db.commit()
    return {"message": "留言删除成功"}