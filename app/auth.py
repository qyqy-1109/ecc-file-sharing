"""
认证模块
=======
处理用户注册、登录、密码修改和 JWT 令牌管理。

安全机制：
  1. 密码使用 pbkdf2_sha256 哈希存储（不可逆）
  2. 登录成功后签发 JWT 令牌（HS256，24小时过期）
  3. get_current_user 依赖注入自动校验每个受保护请求的令牌
  4. 敏感操作（登录/注册/改密）受速率限制保护

密码学链路：
  注册时：用户生成 ECC 密钥对 → 公钥上传到服务器 → 私钥在浏览器端用密码加密后存 localStorage
  登录时：验证密码 → 签发 JWT → 浏览器端用密码解密私钥恢复会话
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from passlib.context import CryptContext
from app import models, schemas, database, config, utils, rate_limit

router = APIRouter(prefix="/auth", tags=["authentication"])

# ── 密码哈希上下文 ──
# pbkdf2_sha256：基于 PBKDF2 的 SHA-256 哈希，带自动加盐
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# ── OAuth2 令牌提取器 ──
# 自动从请求头 Authorization: Bearer <token> 中提取令牌
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def verify_password(plain_password, hashed_password):
    """验证明文密码与哈希值是否匹配"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    """将明文密码转为 pbkdf2_sha256 哈希值"""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: timedelta = None):
    """
    创建 JWT 访问令牌
    ================
    - data: 要编码到令牌中的数据（至少包含 sub=用户名）
    - expires_delta: 自定义过期时间，默认从配置读取（24小时）
    - 算法：HS256，密钥从 config.settings.SECRET_KEY 读取
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=config.settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, config.settings.SECRET_KEY, algorithm=config.settings.ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(database.get_db)):
    """
    从 JWT 令牌中提取当前用户（FastAPI 依赖注入）
    ============================================
    每个需要登录的接口通过 Depends(get_current_user) 调用此函数：
      1. 解码 JWT 令牌
      2. 提取用户名（sub 字段）
      3. 从数据库查询用户
      4. 返回 User ORM 对象（或抛出 401）

    使用统一的 credentials_exception 避免泄露具体失败原因
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, config.settings.SECRET_KEY, algorithms=[config.settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        raise credentials_exception
    return user


# ════════════════════════════════════════════════════════════
#  认证路由
# ════════════════════════════════════════════════════════════

@router.post("/register", response_model=schemas.UserOut)
def register(request: Request, user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    """
    用户注册
    =======
    流程：
      1. 速率限制检查（60秒最多5次注册）
      2. 密码长度校验（≥6位）
      3. 检查用户名是否已存在
      4. 哈希密码、编码公钥、写入数据库
      5. 返回用户信息

    前端配合：
      用户注册前已通过 WebCrypto API 生成 ECC P-384 密钥对
      公钥以 PEM 格式随注册请求上传
      私钥在浏览器端用密码加密后存入 localStorage
    """
    rate_limit.check_rate_limit(request, rate_limit.register_limiter, "register")
    if len(user.password) < 6:
        raise HTTPException(status_code=400, detail="密码长度不能少于6位")

    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    # 公钥以原始字节存入 LargeBinary 字段
    public_key_bytes = user.public_key.encode('utf-8')
    db_user = models.User(
        username=user.username,
        password_hash=hashed_password,
        public_key=public_key_bytes
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@router.post("/login", response_model=schemas.Token)
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    """
    用户登录
    =======
    流程：
      1. 速率限制检查（60秒最多10次登录）
      2. 验证用户名和密码
      3. 创建 JWT 令牌
      4. 记录登录日志（含 IP）
      5. 返回令牌

    使用 OAuth2PasswordRequestForm 以支持标准的 form-urlencoded 登录格式
    前端通过 URLSearchParams 发送请求
    """
    rate_limit.check_rate_limit(request, rate_limit.login_limiter, "login")
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    # 记录登录日志，安全处理 None 的 request.client
    utils.log_action(db, user.id, "login", target=f"ip:{request.client.host if request.client else 'unknown'}", request=request)
    db.commit()
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/change-password")
def change_password(
    pwd_data: schemas.ChangePasswordRequest,
    request: Request,
    db: Session = Depends(database.get_db),
    current_user=Depends(get_current_user)
):
    """
    修改密码
    =======
    流程：
      1. 速率限制检查
      2. 验证旧密码
      3. 校验新密码长度
      4. 更新密码哈希
      5. 记录日志

    前端配合：
      改密成功后会弹出提示要求重新登录
      因为旧密码加密的私钥需要用新密码重新加密
    """
    rate_limit.check_rate_limit(request, rate_limit.change_pwd_limiter, "change_password")
    if not verify_password(pwd_data.old_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Old password incorrect")
    if len(pwd_data.new_password) < 6:
        raise HTTPException(status_code=400, detail="New password too short")
    current_user.password_hash = get_password_hash(pwd_data.new_password)
    utils.log_action(db, current_user.id, "change_password", target=current_user.username, request=request)
    db.commit()
    return {"message": "Password changed successfully"}
