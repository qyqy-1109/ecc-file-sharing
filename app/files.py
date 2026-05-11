import os
import uuid
import base64
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Request
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.orm import Session
from typing import List
from app import database, models, schemas, auth, config, utils

router = APIRouter(prefix="/files", tags=["files"])
os.makedirs(config.settings.UPLOAD_DIR, exist_ok=True)

# 最大文件大小限制（50MB）
MAX_FILE_SIZE = 50 * 1024 * 1024


@router.post("/upload", response_model=schemas.FileUploadResponse)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    encrypted_key: str = Form(...),
    original_filename: str = Form(...),
    db: Session = Depends(database.get_db),
    current_user=Depends(auth.get_current_user)
):
    unique_id = str(uuid.uuid4())
    file_path = os.path.join(config.settings.UPLOAD_DIR, f"{unique_id}.enc")
    file_size = 0
    with open(file_path, "wb") as f:
        while chunk := await file.read(8192):
            f.write(chunk)
            file_size += len(chunk)
            # 边写边校验大小
            if file_size > MAX_FILE_SIZE:
                f.close()
                os.remove(file_path)
                raise HTTPException(
                    status_code=413,
                    detail=f"文件大小超过限制（最大 {MAX_FILE_SIZE // (1024 * 1024)}MB）"
                )

    db_file = models.File(
        filename=original_filename,
        owner_id=current_user.id,
        encrypted_path=file_path,
        file_size=file_size
    )
    db.add(db_file)
    db.flush()

    encrypted_key_bytes = encrypted_key.encode('utf-8')
    db_key = models.FileKey(
        file_id=db_file.id,
        user_id=current_user.id,
        encrypted_key=encrypted_key_bytes
    )
    db.add(db_key)
    utils.log_action(db, current_user.id, "upload", target=f"{original_filename} (id:{db_file.id})", request=request)
    db.commit()
    return {"file_id": db_file.id, "filename": original_filename, "message": "Upload successful"}


@router.get("/list", response_model=List[schemas.FileInfo])
def list_files(db: Session = Depends(database.get_db), current_user=Depends(auth.get_current_user)):
    owned = db.query(models.File).filter(models.File.owner_id == current_user.id).all()
    shared_keys = db.query(models.FileKey).filter(models.FileKey.user_id == current_user.id).all()
    shared_file_ids = [k.file_id for k in shared_keys]
    shared_files = db.query(models.File).filter(models.File.id.in_(shared_file_ids)).all() if shared_file_ids else []
    files_dict = {f.id: f for f in owned}
    for f in shared_files:
        files_dict[f.id] = f
    files = list(files_dict.values())
    owner_ids = {f.owner_id for f in files}
    owners = {u.id: u for u in db.query(models.User).filter(models.User.id.in_(owner_ids)).all()} if owner_ids else {}
    result = []
    for f in files:
        owner = owners.get(f.owner_id)
        result.append(schemas.FileInfo(
            id=f.id,
            filename=f.filename,
            owner_id=f.owner_id,
            owner_username=owner.username if owner else None,
            created_at=f.created_at,
            file_size=f.file_size,
            shared_with=None
        ))
    return result


@router.get("/{file_id}/download")
def download_file(
    request: Request,
    file_id: int,
    db: Session = Depends(database.get_db),
    current_user=Depends(auth.get_current_user)
):
    file = db.query(models.File).filter(models.File.id == file_id).first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    file_key = db.query(models.FileKey).filter(
        models.FileKey.file_id == file_id,
        models.FileKey.user_id == current_user.id
    ).first()
    if not file_key and file.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized")
    if not file_key:
        raise HTTPException(status_code=500, detail="No key found for this user")
    encrypted_key_b64 = base64.b64encode(file_key.encrypted_key).decode('ascii')

    utils.log_action(db, current_user.id, "download", target=f"{file.filename} (id:{file_id})", request=request)
    db.commit()

    def stream_content():
        with open(file.encrypted_path, "rb") as f:
            while chunk := f.read(65536):
                yield chunk

    return StreamingResponse(
        stream_content(),
        media_type="application/octet-stream",
        headers={
            "X-Filename": file.filename,
            "X-Encrypted-Key": encrypted_key_b64,
        },
    )

@router.get("/{file_id}/key")
def get_file_key(
    file_id: int,
    db: Session = Depends(database.get_db),
    current_user=Depends(auth.get_current_user)
):
    """
    获取文件的加密密钥（用于分享流程）
    只返回加密的 AES 密钥，不返回文件内容
    """
    file = db.query(models.File).filter(models.File.id == file_id).first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    file_key = db.query(models.FileKey).filter(
        models.FileKey.file_id == file_id,
        models.FileKey.user_id == current_user.id
    ).first()
    if not file_key:
        if file.owner_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not authorized")
        raise HTTPException(status_code=404, detail="No encryption key found for this user")
    return JSONResponse(content={
        "file_id": file_id,
        "encrypted_key": file_key.encrypted_key.decode('utf-8')
    })

@router.post("/{file_id}/share")
def share_file(
    request: Request,
    file_id: int,
    share_req: schemas.ShareRequest,
    db: Session = Depends(database.get_db),
    current_user=Depends(auth.get_current_user)
):
    file = db.query(models.File).filter(models.File.id == file_id, models.File.owner_id == current_user.id).first()
    if not file:
        raise HTTPException(status_code=403, detail="Only file owner can share")
    target_user = db.query(models.User).filter(models.User.username == share_req.target_username).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="Target user not found")
    existing = db.query(models.FileKey).filter(
        models.FileKey.file_id == file_id,
        models.FileKey.user_id == target_user.id
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="File already shared with this user")
    encrypted_key_bytes = share_req.encrypted_aes_key.encode('utf-8')
    new_key = models.FileKey(
        file_id=file_id,
        user_id=target_user.id,
        encrypted_key=encrypted_key_bytes
    )
    db.add(new_key)
    utils.log_action(db, current_user.id, "share", target=f"{file.filename} -> {target_user.username}", request=request)
    db.commit()
    return {"message": f"File shared with {share_req.target_username}"}


@router.delete("/{file_id}")
def delete_file(
    request: Request,
    file_id: int,
    db: Session = Depends(database.get_db),
    current_user=Depends(auth.get_current_user)
):
    file = db.query(models.File).filter(models.File.id == file_id).first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    if file.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only file owner can delete")
    if os.path.exists(file.encrypted_path):
        os.remove(file.encrypted_path)
    db.query(models.FileKey).filter(models.FileKey.file_id == file_id).delete()
    db.delete(file)
    utils.log_action(db, current_user.id, "delete", target=f"{file.filename} (id:{file_id})", request=request)
    db.commit()
    return {"message": "File deleted successfully"}


@router.put("/{file_id}/rename")
def rename_file(
    request: Request,
    file_id: int,
    data: schemas.RenameRequest,
    db: Session = Depends(database.get_db),
    current_user=Depends(auth.get_current_user)
):
    file = db.query(models.File).filter(models.File.id == file_id).first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    if file.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only file owner can rename")
    if not data.new_name or data.new_name.strip() == "":
        raise HTTPException(status_code=400, detail="New name cannot be empty")
    old_name = file.filename
    file.filename = data.new_name.strip()
    utils.log_action(db, current_user.id, "rename", target=f"{old_name} -> {data.new_name} (id:{file_id})", request=request)
    db.commit()
    return {"message": "File renamed successfully", "new_filename": file.filename}


@router.post("/batch-delete")
def batch_delete_files(
    request: Request,
    batch_req: schemas.BatchDeleteRequest,  # ← 改为接收 Pydantic 模型
    db: Session = Depends(database.get_db),
    current_user=Depends(auth.get_current_user)
):
    file_ids = batch_req.file_ids  # ← 从模型中取值
    files = db.query(models.File).filter(models.File.id.in_(file_ids), models.File.owner_id == current_user.id).all()
    if len(files) != len(file_ids):
        raise HTTPException(status_code=403, detail="Some files are not owned by you")
    deleted_names = []
    for file in files:
        if os.path.exists(file.encrypted_path):
            os.remove(file.encrypted_path)
        db.query(models.FileKey).filter(models.FileKey.file_id == file.id).delete()
        deleted_names.append(file.filename)
        db.delete(file)
    utils.log_action(db, current_user.id, "batch_delete", target=f"{len(files)} files: {', '.join(deleted_names)}", request=request)
    db.commit()
    return {"message": f"Deleted {len(files)} files"}