from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from passlib.context import CryptContext
from app import models, schemas, database, config, utils, rate_limit

router = APIRouter(prefix="/auth", tags=["authentication"])

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=config.settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, config.settings.SECRET_KEY, algorithm=config.settings.ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(database.get_db)):
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


@router.post("/register", response_model=schemas.UserOut)
def register(request: Request, user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    """用户注册（含密码长度校验）"""
    rate_limit.check_rate_limit(request, rate_limit.register_limiter, "register")
    if len(user.password) < 6:
        raise HTTPException(status_code=400, detail="密码长度不能少于6位")

    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
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
    rate_limit.check_rate_limit(request, rate_limit.login_limiter, "login")
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    utils.log_action(db, user.id, "login", target=f"ip:{request.client.host}", request=request)
    db.commit()
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/change-password")
def change_password(
    pwd_data: schemas.ChangePasswordRequest,
    request: Request,
    db: Session = Depends(database.get_db),
    current_user=Depends(get_current_user)
):
    rate_limit.check_rate_limit(request, rate_limit.change_pwd_limiter, "change_password")
    if not verify_password(pwd_data.old_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Old password incorrect")
    if len(pwd_data.new_password) < 6:
        raise HTTPException(status_code=400, detail="New password too short")
    current_user.password_hash = get_password_hash(pwd_data.new_password)
    utils.log_action(db, current_user.id, "change_password", target=current_user.username, request=request)
    db.commit()
    return {"message": "Password changed successfully"}