"""
工具函数模块
===========
提供跨模块使用的辅助功能，目前包含操作日志记录。

设计原则：
  - log_action 只做 db.add()，不负责 db.commit()
  - 统一由调用方在完成业务操作后一起提交，保证事务原子性
"""
from fastapi import Request
from sqlalchemy.orm import Session
from app import models


def log_action(db: Session, user_id: int, action: str, target: str = None, request: Request = None):
    """
    记录用户操作日志
    ===============
    参数：
      - db: 数据库会话
      - user_id: 操作用户 ID
      - action: 操作类型（login / upload / download / share / delete 等）
      - target: 操作对象描述（文件名、目标用户名等）
      - request: FastAPI Request 对象（用于提取客户端 IP）

    注意：
      此函数只调用 db.add()，不调用 db.commit()
      由调用方的路由函数在完成所有数据库操作后统一提交
      这样日志记录和业务操作要么一起成功，要么一起回滚
    """
    # 安全提取 IP：request.client 在某些代理配置下可能为 None
    ip = request.client.host if request and request.client else None
    db.add(models.Log(user_id=user_id, action=action, target=target, ip_address=ip))
