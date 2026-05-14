"""
用户模块
=======
提供用户相关的 API：
  - 查询他人公钥（用于分享时加密 AES 密钥）
  - 查看当前用户信息
  - 注销账户（删除所有数据）
"""
import os

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app import database, models, schemas, auth

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/{username}/public_key", response_model=schemas.PublicKeyResponse)
def get_public_key(username: str, db: Session = Depends(database.get_db),
                   current_user=Depends(auth.get_current_user)):
    """
    查询指定用户的 ECC 公钥
    ======================
    用途：分享文件时，前端需要获取目标用户的公钥来加密 AES 密钥

    安全性：
      - 需要登录才能查询（通过 get_current_user 验证）
      - 公钥本身是公开信息，不需要额外权限控制
    """
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"username": user.username, "public_key": user.public_key.decode('utf-8')}


@router.get("/me", response_model=schemas.UserOut)
def get_me(current_user=Depends(auth.get_current_user)):
    """
    获取当前登录用户信息
    ==================
    用途：前端验证 Token 是否有效、获取当前用户名
    """
    return current_user


@router.delete("/me")
def delete_account(db: Session = Depends(database.get_db),
                   current_user=Depends(auth.get_current_user)):
    """
    注销账户
    =======
    流程：
      1. 查询用户拥有的所有文件
      2. 暂存物理文件路径
      3. 级联删除用户及相关数据（文件、密钥、日志记录）
      4. 提交数据库事务
      5. 事务成功后删除所有物理文件

    级联删除范围（由 models.py 中的 cascade 定义）：
      - users 表中删除用户
      - files 表中删除用户拥有的所有文件记录
      - file_keys 表中删除用户的所有密钥记录
      - logs 表中删除用户的所有日志

    前端配合：
      注销前会要求用户输入私钥验证身份
    """
    user = db.query(models.User).get(current_user.id)

    # 先暂存所有文件路径，等 DB 事务成功后再删除物理文件
    owned_files = db.query(models.File).filter(models.File.owner_id == user.id).all()
    paths = [f.encrypted_path for f in owned_files]

    # 级联删除（数据库操作）
    db.delete(user)
    db.commit()

    # 事务成功，清理物理文件
    for path in paths:
        if os.path.exists(path):
            os.remove(path)
    return {"message": "Account and all associated data deleted successfully"}
