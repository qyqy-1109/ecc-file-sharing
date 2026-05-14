"""
Pydantic 数据校验模型
===================
定义所有 API 请求和响应的数据结构：

  请求模型（前端→后端）：
    - UserCreate       注册请求
    - ShareRequest     分享请求
    - BatchDeleteRequest  批量删除请求
    - ChangePasswordRequest 改密请求
    - RenameRequest    重命名请求

  响应模型（后端→前端）：
    - UserOut          用户信息
    - Token            JWT 令牌
    - FileUploadResponse  上传结果
    - FileInfo         文件列表项
    - PublicKeyResponse   公钥查询结果

Pydantic 自动完成：类型校验、JSON 序列化/反序列化、必填/可选检查
"""
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


# ── 认证相关模型 ──

class UserCreate(BaseModel):
    """注册请求"""
    username: str
    password: str
    public_key: str                          # ECC P-384 公钥 PEM 格式字符串


class UserLogin(BaseModel):
    """登录请求（已被 OAuth2PasswordRequestForm 替代，保留备用）"""
    username: str
    password: str


class UserOut(BaseModel):
    """用户公开信息响应"""
    id: int
    username: str
    created_at: datetime

    class Config:
        from_attributes = True               # 允许从 SQLAlchemy ORM 对象直接转换


class Token(BaseModel):
    """JWT 令牌响应"""
    access_token: str
    token_type: str


class PublicKeyResponse(BaseModel):
    """公钥查询响应"""
    username: str
    public_key: str


class ChangePasswordRequest(BaseModel):
    """修改密码请求"""
    old_password: str
    new_password: str


# ── 文件操作相关模型 ──

class FileUploadResponse(BaseModel):
    """上传成功响应"""
    file_id: int
    filename: str
    message: str


class FileInfo(BaseModel):
    """文件列表项"""
    id: int
    filename: str
    owner_id: int
    owner_username: Optional[str] = None
    created_at: datetime
    file_size: int = 0
    shared_with: Optional[list] = None       # 预留字段（前端暂未使用）


class ShareRequest(BaseModel):
    """分享请求"""
    target_username: str
    encrypted_aes_key: str                   # 用目标用户公钥重新加密后的 AES 密钥


class BatchDeleteRequest(BaseModel):
    """批量删除请求"""
    file_ids: List[int]


class RenameRequest(BaseModel):
    """重命名请求"""
    new_name: str
