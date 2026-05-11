import os

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app import database, models, schemas, auth

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/{username}/public_key", response_model=schemas.PublicKeyResponse)
def get_public_key(username: str, db: Session = Depends(database.get_db),
                   current_user=Depends(auth.get_current_user)):
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"username": user.username, "public_key": user.public_key.decode('utf-8')}


@router.get("/me", response_model=schemas.UserOut)
def get_me(current_user=Depends(auth.get_current_user)):
    return current_user


@router.delete("/me")
def delete_account(db: Session = Depends(database.get_db),
                   current_user=Depends(auth.get_current_user)):
    user = db.query(models.User).get(current_user.id)
    owned_files = db.query(models.File).filter(models.File.owner_id == user.id).all()
    for f in owned_files:
        if os.path.exists(f.encrypted_path):
            os.remove(f.encrypted_path)
    db.delete(user)
    db.commit()
    return {"message": "Account and all associated data deleted successfully"}