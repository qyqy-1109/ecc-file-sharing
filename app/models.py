"""
ORM 数据模型
===========
定义四张核心表：

  users        — 用户表（用户名、密码哈希、ECC公钥）
  files        — 文件表（文件名、加密路径、大小、拥有者）
  file_keys    — 文件密钥表（每个用户对每个文件的加密AES密钥，支持多对多分享）
  logs         — 操作日志表（审计追踪）

表关系：
  User  1─N File      (owned_files，级联删除)
  User  1─N FileKey   (file_keys，级联删除)
  User  1─N Log       (logs，级联删除)
  File  1─N FileKey   (file_keys，级联删除)

安全设计要点：
  - 密码存哈希值（pbkdf2_sha256），永不存明文
  - ECC 公钥存原始字节（LargeBinary），前端 WebCrypto 生成
  - 加密后的 AES 密钥存 file_keys 表，实现一对多安全分享
"""
from sqlalchemy import Column, Integer, String, LargeBinary, ForeignKey, DateTime, Index, UniqueConstraint
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from .database import Base


class User(Base):
    """用户表"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)                  # pbkdf2_sha256 哈希值
    public_key = Column(LargeBinary, nullable=False)                # ECC P-384 公钥（PEM 格式字节）
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # 级联删除：删除用户时自动删除其拥有的文件、密钥记录和日志
    owned_files = relationship("File", back_populates="owner", cascade="all, delete-orphan")
    file_keys = relationship("FileKey", back_populates="user", cascade="all, delete-orphan")
    logs = relationship("Log", back_populates="user", cascade="all, delete-orphan")


class File(Base):
    """文件表"""
    __tablename__ = "files"
    __table_args__ = (
        Index("ix_files_owner_id", "owner_id"),                     # 按拥有者查询的索引
    )

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)                       # 原始文件名（明文）
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    encrypted_path = Column(String, nullable=False)                 # 磁盘上加密文件的路径
    file_size = Column(Integer, default=0)                          # 加密后文件大小（字节）
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    owner = relationship("User", back_populates="owned_files")
    file_keys = relationship("FileKey", back_populates="file", cascade="all, delete-orphan")


class FileKey(Base):
    """
    文件密钥表
    =========
    实现安全的一对多文件分享：
      - 上传者用自己公钥加密 AES 密钥后存入此表（user_id=上传者）
      - 分享时用目标用户公钥重新加密 AES 密钥并插入新行（user_id=目标用户）
      - 每个 (file_id, user_id) 组合唯一，避免重复分享
    """
    __tablename__ = "file_keys"
    __table_args__ = (
        Index("ix_file_keys_file_id", "file_id"),
        Index("ix_file_keys_user_id", "user_id"),
        UniqueConstraint("file_id", "user_id", name="uq_file_keys_file_user"),
    )

    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(Integer, ForeignKey("files.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    encrypted_key = Column(LargeBinary, nullable=False)             # ECIES 加密后的 AES 密钥

    file = relationship("File", back_populates="file_keys")
    user = relationship("User", back_populates="file_keys")


class Log(Base):
    """操作日志表（审计追踪）"""
    __tablename__ = "logs"
    __table_args__ = (
        Index("ix_logs_user_id", "user_id"),
    )

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    action = Column(String, nullable=False)                         # 操作类型：login/upload/download/share/delete 等
    target = Column(String, nullable=True)                          # 操作对象描述
    ip_address = Column(String, nullable=True)                      # 客户端 IP 地址
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="logs")
