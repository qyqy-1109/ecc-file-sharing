from fastapi import Request
from sqlalchemy.orm import Session
from app import models


def log_action(db: Session, user_id: int, action: str, target: str = None, request: Request = None):
    ip = request.client.host if request and request.client else None
    db.add(models.Log(user_id=user_id, action=action, target=target, ip_address=ip))