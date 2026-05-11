from pydantic import BaseModel
from typing import Optional,List
from datetime import datetime


class UserCreate(BaseModel):
    username: str
    password: str
    public_key: str


class UserLogin(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    created_at: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str


class FileUploadResponse(BaseModel):
    file_id: int
    filename: str
    message: str


class FileInfo(BaseModel):
    id: int
    filename: str
    owner_id: int
    owner_username: Optional[str] = None
    created_at: datetime
    file_size: int = 0
    shared_with: Optional[list] = None


class ShareRequest(BaseModel):
    target_username: str
    encrypted_aes_key: str


class PublicKeyResponse(BaseModel):
    username: str
    public_key: str

class BatchDeleteRequest(BaseModel):
    file_ids: List[int]


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


class RenameRequest(BaseModel):
    new_name: str