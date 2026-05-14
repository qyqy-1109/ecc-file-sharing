"""
文件管理模块
===========
处理文件的上传、下载、列表、分享、删除、重命名和批量操作。

端到端加密流程：
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  浏览器端    │     │   FastAPI   │     │   SQLite    │
│             │     │   服务器     │     │   数据库     │
├─────────────┤     ├─────────────┤     ├─────────────┤
│ 1. AES-GCM  │────→│ 接收密文    │────→│ files 表    │
│    加密文件  │     │ 存储到磁盘   │     │ (元数据)    │
│             │     │             │     │             │
│ 2. ECC 加密 │────→│ 接收加密后  │────→│ file_keys表 │
│    AES密钥   │     │ 的AES密钥   │     │ (密钥记录)  │
└─────────────┘     └─────────────┘     └─────────────┘

分享机制：
  - 每个用户对每个文件有独立的 FileKey 记录
  - 分享时用目标用户公钥重加密 AES 密钥，插入新 FileKey
  - 文件在磁盘上只有一份（加密态），不同用户用自己的私钥解密

安全要点：
  - 服务器永远不接触明文文件内容
  - 服务器永远不接触用户的 ECC 私钥
  - 服务器存的 AES 密钥是被 ECC 公钥加密过的，只有对应私钥持有者能解密
"""
import os
import uuid
import base64
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Request
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.orm import Session
import time
from typing import List
from urllib.parse import quote
from app import database, models, schemas, auth, config, utils

router = APIRouter(prefix="/files", tags=["files"])

# 确保上传目录存在
os.makedirs(config.settings.UPLOAD_DIR, exist_ok=True)

# 最大文件大小限制（50MB）
MAX_FILE_SIZE = 50 * 1024 * 1024


# ════════════════════════════════════════════════════════════
#  文件上传
# ════════════════════════════════════════════════════════════

@router.post("/upload", response_model=schemas.FileUploadResponse)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    encrypted_key: str = Form(...),
    original_filename: str = Form(...),
    db: Session = Depends(database.get_db),
    current_user=Depends(auth.get_current_user)
):
    """
    上传加密文件
    ===========
    前端发送的数据：
      - file: 已用 AES-256-GCM 加密的文件内容
      - encrypted_key: 已用当前用户 ECC 公钥加密的 AES 密钥
      - original_filename: 原始文件名（明文，仅用于显示）

    后端处理：
      1. 以 UUID 命名存储加密文件到磁盘（避免文件名冲突）
      2. 边写边校验大小（超过 50MB 立即终止并清理临时文件）
      3. 写入 files 表（文件元数据）
      4. 写入 file_keys 表（加密的 AES 密钥）
      5. 记录操作日志

    注意：服务器始终不接触明文文件，只存储加密后的数据
    """
    # 生成唯一文件名，防止同名冲突和路径遍历攻击
    unique_id = str(uuid.uuid4())
    file_path = os.path.join(config.settings.UPLOAD_DIR, f"{unique_id}.enc")
    file_size = 0

    # 边写边校验文件大小，避免超大文件撑爆磁盘
    with open(file_path, "wb") as f:
        while chunk := await file.read(8192):     # 每次读取 8KB，控制内存占用
            f.write(chunk)
            file_size += len(chunk)
            if file_size > MAX_FILE_SIZE:
                f.close()
                # Windows 下文件句柄可能未完全释放，加重试机制
                for _ in range(5):
                    try:
                        os.remove(file_path)
                        break
                    except PermissionError:
                        time.sleep(0.05)
                raise HTTPException(
                    status_code=413,
                    detail=f"文件大小超过限制（最大 {MAX_FILE_SIZE // (1024 * 1024)}MB）"
                )

    # 写入文件元数据（files 表）
    db_file = models.File(
        filename=original_filename,
        owner_id=current_user.id,
        encrypted_path=file_path,
        file_size=file_size
    )
    db.add(db_file)
    db.flush()  # 立即刷新以获取自增 ID

    # 写入密钥记录（file_keys 表）
    encrypted_key_bytes = encrypted_key.encode('utf-8')
    db_key = models.FileKey(
        file_id=db_file.id,
        user_id=current_user.id,
        encrypted_key=encrypted_key_bytes
    )
    db.add(db_key)

    # 记录操作日志并提交事务
    utils.log_action(db, current_user.id, "upload", target=f"{original_filename} (id:{db_file.id})", request=request)
    db.commit()
    return {"file_id": db_file.id, "filename": original_filename, "message": "Upload successful"}


# ════════════════════════════════════════════════════════════
#  文件列表
# ════════════════════════════════════════════════════════════

@router.get("/list", response_model=List[schemas.FileInfo])
def list_files(db: Session = Depends(database.get_db), current_user=Depends(auth.get_current_user)):
    """
    列出当前用户可访问的所有文件
    ============================
    包括两类文件：
      1. 自己上传的文件（owner_id = current_user.id）
      2. 其他用户分享给当前用户的文件（通过 file_keys 表关联）

    返回每个文件的详细信息和拥有者用户名
    """
    # 查询自己拥有的文件
    owned = db.query(models.File).filter(models.File.owner_id == current_user.id).all()
    # 查询被分享的文件（自己的 user_id 在 file_keys 中有记录）
    shared_keys = db.query(models.FileKey).filter(models.FileKey.user_id == current_user.id).all()
    shared_file_ids = [k.file_id for k in shared_keys]
    shared_files = db.query(models.File).filter(models.File.id.in_(shared_file_ids)).all() if shared_file_ids else []

    # 用字典去重（自己拥有的文件同时也可能有分享记录）
    files_dict = {f.id: f for f in owned}
    for f in shared_files:
        files_dict[f.id] = f
    files = list(files_dict.values())

    # 批量查询文件拥有者信息（避免 N+1 查询问题）
    owner_ids = {f.owner_id for f in files}
    owners = {u.id: u for u in db.query(models.User).filter(models.User.id.in_(owner_ids)).all()} if owner_ids else {}

    # 构建响应
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
            shared_with=None    # 预留字段
        ))
    return result


# ════════════════════════════════════════════════════════════
#  文件下载
# ════════════════════════════════════════════════════════════

@router.get("/{file_id}/download")
def download_file(
    request: Request,
    file_id: int,
    db: Session = Depends(database.get_db),
    current_user=Depends(auth.get_current_user)
):
    """
    下载加密文件
    ===========
    流程：
      1. 权限检查：必须是文件拥有者或被分享者
      2. 从 file_keys 表获取加密的 AES 密钥
      3. 通过自定义响应头传递加密密钥和文件名
      4. 以流式传输返回加密文件内容（避免大文件占满内存）

    返回头说明：
      - X-Filename: URL 编码后的原始文件名（前端解码后用于下载保存）
      - X-Encrypted-Key: Base64 编码的加密 AES 密钥（前端用私钥解密）

    使用 try/finally 而非 with 语句管理文件句柄
    （生成器中使用 with 可能在客户端断开时不执行 __exit__）
    """
    file = db.query(models.File).filter(models.File.id == file_id).first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")

    # 查找当前用户对该文件的密钥记录
    file_key = db.query(models.FileKey).filter(
        models.FileKey.file_id == file_id,
        models.FileKey.user_id == current_user.id
    ).first()

    # 权限校验：既非拥有者也未被分享 → 403
    if not file_key and file.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized")
    # 拥有者但没有密钥记录 → 数据异常，返回 500
    if not file_key:
        raise HTTPException(status_code=500, detail="No key found for this user")

    # Base64 编码加密密钥用于 HTTP 头传输
    encrypted_key_b64 = base64.b64encode(file_key.encrypted_key).decode('ascii')

    # 记录下载日志
    utils.log_action(db, current_user.id, "download", target=f"{file.filename} (id:{file_id})", request=request)
    db.commit()

    # 流式读取文件，16KB 分块输出，避免大文件占满内存
    def stream_content():
        f = open(file.encrypted_path, "rb")
        try:
            while chunk := f.read(65536):
                yield chunk
        finally:
            f.close()   # 保证文件句柄在客户端断开时也能被释放

    return StreamingResponse(
        stream_content(),
        media_type="application/octet-stream",
        headers={
            "X-Filename": quote(file.filename, safe=''),      # URL 编码避免非ASCII字符乱码
            "X-Encrypted-Key": encrypted_key_b64,
        },
    )


# ════════════════════════════════════════════════════════════
#  获取文件密钥（用于分享，不下载文件内容）
# ════════════════════════════════════════════════════════════

@router.get("/{file_id}/key")
def get_file_key(
    file_id: int,
    db: Session = Depends(database.get_db),
    current_user=Depends(auth.get_current_user)
):
    """
    获取文件的加密密钥（用于分享流程）
    ================================
    与 download 的区别：
      - download 返回加密文件体 + 加密密钥
      - key 只返回加密密钥，不返回文件内容

    用途：分享时，前端获取自己持有的加密 AES 密钥
          用自身私钥解密得到明文 AES 密钥
          再用目标用户的公钥重新加密
          最终通过 /share 接口写入目标用户的 FileKey 记录
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


# ════════════════════════════════════════════════════════════
#  文件分享
# ════════════════════════════════════════════════════════════

@router.post("/{file_id}/share")
def share_file(
    request: Request,
    file_id: int,
    share_req: schemas.ShareRequest,
    db: Session = Depends(database.get_db),
    current_user=Depends(auth.get_current_user)
):
    """
    分享文件给其他用户
    =================
    流程：
      1. 验证请求者是文件拥有者
      2. 查找目标用户是否存在
      3. 检查是否已分享给该用户（防止重复）
      4. 插入新的 FileKey 记录（用目标用户公钥加密的 AES 密钥）
      5. 记录操作日志

    安全性：
      - 只有文件拥有者可以分享
      - encrypted_aes_key 是用目标用户公钥加密的，只有目标用户能解密
      - 已分享过的用户不能重复分享
    """
    # 验证是文件拥有者
    file = db.query(models.File).filter(models.File.id == file_id, models.File.owner_id == current_user.id).first()
    if not file:
        raise HTTPException(status_code=403, detail="Only file owner can share")

    # 查找目标用户
    target_user = db.query(models.User).filter(models.User.username == share_req.target_username).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="Target user not found")

    # 防止重复分享
    existing = db.query(models.FileKey).filter(
        models.FileKey.file_id == file_id,
        models.FileKey.user_id == target_user.id
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="File already shared with this user")

    # 创建目标用户的密钥记录
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


# ════════════════════════════════════════════════════════════
#  文件删除
# ════════════════════════════════════════════════════════════

@router.delete("/{file_id}")
def delete_file(
    request: Request,
    file_id: int,
    db: Session = Depends(database.get_db),
    current_user=Depends(auth.get_current_user)
):
    """
    删除单个文件
    ===========
    流程：
      1. 验证是文件拥有者
      2. 暂存文件路径和名称
      3. 删除关联的 FileKey 记录和 File 记录
      4. 记录日志并提交数据库事务
      5. 事务提交成功后再从磁盘删除物理文件

    注意：先提交数据库再删文件
          避免「先删文件、DB提交失败回滚后数据库中残留幽灵记录」
    """
    file = db.query(models.File).filter(models.File.id == file_id).first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    if file.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only file owner can delete")

    # 先暂存路径，等 DB 事务成功后再删物理文件
    path = file.encrypted_path
    name = file.filename

    # 删除数据库记录（级联删除关联的 FileKey）
    db.query(models.FileKey).filter(models.FileKey.file_id == file_id).delete()
    db.delete(file)
    utils.log_action(db, current_user.id, "delete", target=f"{name} (id:{file_id})", request=request)
    db.commit()

    # DB 提交成功后才安全删除物理文件
    if os.path.exists(path):
        os.remove(path)
    return {"message": "File deleted successfully"}


# ════════════════════════════════════════════════════════════
#  文件重命名
# ════════════════════════════════════════════════════════════

@router.put("/{file_id}/rename")
def rename_file(
    request: Request,
    file_id: int,
    data: schemas.RenameRequest,
    db: Session = Depends(database.get_db),
    current_user=Depends(auth.get_current_user)
):
    """
    重命名文件
    =========
    只修改数据库中的显示名称，不影响磁盘上的加密文件
    """
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


# ════════════════════════════════════════════════════════════
#  批量删除
# ════════════════════════════════════════════════════════════

@router.post("/batch-delete")
def batch_delete_files(
    request: Request,
    batch_req: schemas.BatchDeleteRequest,
    db: Session = Depends(database.get_db),
    current_user=Depends(auth.get_current_user)
):
    """
    批量删除文件
    ===========
    流程：
      1. 用 set 去重（防止前端传重复 ID 导致数量不匹配误判）
      2. 查询并验证所有文件都属于当前用户
      3. 暂存所有文件路径
      4. 删除数据库记录并提交事务
      5. 事务成功后批量删除物理文件
    """
    # set 去重：防止前端传 [1,1,2] 导致 len 比较误判
    unique_file_ids = set(batch_req.file_ids)
    files = db.query(models.File).filter(
        models.File.id.in_(unique_file_ids),
        models.File.owner_id == current_user.id
    ).all()

    # 验证所有文件都属于当前用户
    if len(files) != len(unique_file_ids):
        raise HTTPException(status_code=403, detail="Some files are not owned by you")

    # 先暂存路径，等事务成功后再删文件
    paths = [f.encrypted_path for f in files]
    deleted_names = [f.filename for f in files]

    for file in files:
        db.query(models.FileKey).filter(models.FileKey.file_id == file.id).delete()
        db.delete(file)

    utils.log_action(db, current_user.id, "batch_delete",
                     target=f"{len(files)} files: {', '.join(deleted_names)}", request=request)
    db.commit()

    # 事务成功，安全删除所有物理文件
    for path in paths:
        if os.path.exists(path):
            os.remove(path)
    return {"message": f"Deleted {len(files)} files"}
