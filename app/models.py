from sqlalchemy import Column, Integer, String, LargeBinary, ForeignKey, DateTime, Index
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from .database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    public_key = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    owned_files = relationship("File", back_populates="owner", cascade="all, delete-orphan")
    file_keys = relationship("FileKey", back_populates="user", cascade="all, delete-orphan")
    logs = relationship("Log", back_populates="user", cascade="all, delete-orphan")

class File(Base):
    __tablename__ = "files"
    __table_args__ = (
        Index("ix_files_owner_id", "owner_id"),
    )
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    encrypted_path = Column(String, nullable=False)
    file_size = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    owner = relationship("User", back_populates="owned_files")
    file_keys = relationship("FileKey", back_populates="file", cascade="all, delete-orphan")

class FileKey(Base):
    __tablename__ = "file_keys"
    __table_args__ = (
        Index("ix_file_keys_file_id", "file_id"),
        Index("ix_file_keys_user_id", "user_id"),
    )
    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(Integer, ForeignKey("files.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    encrypted_key = Column(LargeBinary, nullable=False)
    file = relationship("File", back_populates="file_keys")
    user = relationship("User", back_populates="file_keys")

class Log(Base):
    __tablename__ = "logs"
    __table_args__ = (
        Index("ix_logs_user_id", "user_id"),
    )
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    action = Column(String, nullable=False)
    target = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    user = relationship("User", back_populates="logs")