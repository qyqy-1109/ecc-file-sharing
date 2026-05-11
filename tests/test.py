"""
ECC 文件共享系统 — 单元测试
运行方式: pytest tests/test.py -v
"""

import os
import sys

# 将项目根目录加入 sys.path
_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _root not in sys.path:
    sys.path.insert(0, _root)

import tempfile
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# ── 测试环境配置（必须在导入 app 模块之前设置）──
os.environ["APP_BASE_DIR"] = tempfile.mkdtemp(prefix="ecc_test_")
os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only"

# 测试用 SQLite 内存数据库
TEST_DATABASE_URL = "sqlite:///./test.db"

# 现在导入项目模块
from app.database import Base, get_db
from app.main import app
from app import models, schemas
from app.rate_limit import login_limiter, register_limiter, change_pwd_limiter


# ── 测试数据库引擎 ──
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    """覆写依赖：使用测试数据库"""
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


# 应用覆写
app.dependency_overrides[get_db] = override_get_db


# ── Fixtures ──

@pytest.fixture(autouse=True)
def setup_db():
    """每个测试函数前重建表结构"""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(autouse=True)
def reset_rate_limiters():
    """每个测试函数后重置限流器状态"""
    yield
    login_limiter._store.clear()
    register_limiter._store.clear()
    change_pwd_limiter._store.clear()


@pytest.fixture
def client():
    """FastAPI 测试客户端"""
    return TestClient(app)


@pytest.fixture
def test_user_data():
    return {
        "username": "testuser",
        "password": "Test123!",
        "public_key": "ec-pub-key-12345",
    }


@pytest.fixture
def registered_user(client, test_user_data):
    """注册并返回用户数据的 fixture"""
    resp = client.post("/auth/register", json=test_user_data)
    assert resp.status_code == 200
    return resp.json()


@pytest.fixture
def token(client, test_user_data):
    """注册并登录，返回 JWT token"""
    client.post("/auth/register", json=test_user_data)
    resp = client.post("/auth/login", data={
        "username": test_user_data["username"],
        "password": test_user_data["password"],
    })
    assert resp.status_code == 200
    return resp.json()["access_token"]


@pytest.fixture
def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


# ══════════════════════════════════════════════
# 测试用例
# ══════════════════════════════════════════════

class TestAuth:
    """认证模块测试"""

    def test_register_success(self, client, test_user_data):
        resp = client.post("/auth/register", json=test_user_data)
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == test_user_data["username"]
        assert "id" in data
        assert "created_at" in data

    def test_register_duplicate(self, client, test_user_data):
        client.post("/auth/register", json=test_user_data)
        resp = client.post("/auth/register", json=test_user_data)
        assert resp.status_code == 400
        assert "already registered" in resp.json()["detail"]

    def test_register_short_password(self, client, test_user_data):
        data = {**test_user_data, "password": "12345"}
        resp = client.post("/auth/register", json=data)
        assert resp.status_code == 400
        assert "不能少于" in resp.json()["detail"]

    def test_login_success(self, client, test_user_data):
        client.post("/auth/register", json=test_user_data)
        resp = client.post("/auth/login", data={
            "username": test_user_data["username"],
            "password": test_user_data["password"],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_wrong_password(self, client, test_user_data):
        client.post("/auth/register", json=test_user_data)
        resp = client.post("/auth/login", data={
            "username": test_user_data["username"],
            "password": "WrongPass1!",
        })
        assert resp.status_code == 400
        assert "Incorrect" in resp.json()["detail"]

    def test_login_nonexistent_user(self, client):
        resp = client.post("/auth/login", data={
            "username": "nobody",
            "password": "SomePass1!",
        })
        assert resp.status_code == 400

    def test_change_password_success(self, client, token, auth_header):
        resp = client.post("/auth/change-password", json={
            "old_password": "Test123!",
            "new_password": "NewPass456!",
        }, headers=auth_header)
        assert resp.status_code == 200

        # 用新密码验证登录
        resp = client.post("/auth/login", data={
            "username": "testuser",
            "password": "NewPass456!",
        })
        assert resp.status_code == 200

    def test_change_password_wrong_old(self, client, token, auth_header):
        resp = client.post("/auth/change-password", json={
            "old_password": "WrongOld!",
            "new_password": "NewPass456!",
        }, headers=auth_header)
        assert resp.status_code == 400
        assert "incorrect" in resp.json()["detail"].lower()

    def test_access_without_token(self, client, auth_header):
        resp = client.get("/users/me")
        assert resp.status_code == 401

    def test_access_with_invalid_token(self, client):
        resp = client.get("/users/me", headers={"Authorization": "Bearer invalid-token"})
        assert resp.status_code == 401


class TestUsers:
    """用户模块测试"""

    def test_get_me(self, client, auth_header):
        resp = client.get("/users/me", headers=auth_header)
        assert resp.status_code == 200
        assert resp.json()["username"] == "testuser"

    def test_get_public_key(self, client, test_user_data, auth_header):
        resp = client.get(f"/users/{test_user_data['username']}/public_key", headers=auth_header)
        assert resp.status_code == 200
        data = resp.json()
        assert data["public_key"] == test_user_data["public_key"]

    def test_get_public_key_not_found(self, client, auth_header):
        resp = client.get("/users/nonexistent/public_key", headers=auth_header)
        assert resp.status_code == 404

    def test_delete_account(self, client, auth_header):
        resp = client.delete("/users/me", headers=auth_header)
        assert resp.status_code == 200

        # 确认用户已删除
        resp = client.post("/auth/login", data={
            "username": "testuser",
            "password": "Test123!",
        })
        assert resp.status_code == 400


@pytest.fixture
def sample_file():
    """创建一个测试用的小文件"""
    import io
    return io.BytesIO(b"Hello, ECC File Sharing! This is test content." * 100)


class TestFiles:
    """文件模块测试"""

    def test_upload_file(self, client, token, auth_header, sample_file):
        resp = client.post(
            "/files/upload",
            files={"file": ("test.txt", sample_file, "text/plain")},
            data={
                "encrypted_key": "aes-encrypted-key-123",
                "original_filename": "test.txt",
            },
            headers=auth_header,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["filename"] == "test.txt"
        assert "file_id" in data

    def test_list_files_empty(self, client, auth_header):
        resp = client.get("/files/list", headers=auth_header)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_files_after_upload(self, client, token, auth_header, sample_file):
        client.post(
            "/files/upload",
            files={"file": ("test.txt", sample_file, "text/plain")},
            data={
                "encrypted_key": "aes-encrypted-key-123",
                "original_filename": "test.txt",
            },
            headers=auth_header,
        )
        resp = client.get("/files/list", headers=auth_header)
        assert resp.status_code == 200
        files = resp.json()
        assert len(files) == 1
        assert files[0]["filename"] == "test.txt"

    def test_download_file(self, client, token, auth_header, sample_file):
        # 先上传
        upload_resp = client.post(
            "/files/upload",
            files={"file": ("test.txt", sample_file, "text/plain")},
            data={
                "encrypted_key": "aes-encrypted-key-123",
                "original_filename": "test.txt",
            },
            headers=auth_header,
        )
        file_id = upload_resp.json()["file_id"]

        # 下载
        resp = client.get(f"/files/{file_id}/download", headers=auth_header)
        assert resp.status_code == 200
        assert resp.headers.get("x-filename") == "test.txt"
        assert resp.headers.get("x-encrypted-key") is not None

    def test_download_nonexistent_file(self, client, auth_header):
        resp = client.get("/files/999/download", headers=auth_header)
        assert resp.status_code == 404

    def test_download_unauthorized(self, client, token, auth_header, test_user_data, sample_file):
        # 先上传
        upload_resp = client.post(
            "/files/upload",
            files={"file": ("test.txt", sample_file, "text/plain")},
            data={
                "encrypted_key": "aes-encrypted-key-123",
                "original_filename": "test.txt",
            },
            headers=auth_header,
        )
        file_id = upload_resp.json()["file_id"]

        # 用另一个用户下载（应被拒绝）
        client.post("/auth/register", json={
            "username": "otheruser",
            "password": "Other123!",
            "public_key": "other-pub-key",
        })
        other_token = client.post("/auth/login", data={
            "username": "otheruser",
            "password": "Other123!",
        }).json()["access_token"]

        resp = client.get(
            f"/files/{file_id}/download",
            headers={"Authorization": f"Bearer {other_token}"},
        )
        assert resp.status_code == 403

    def test_share_file(self, client, token, auth_header, test_user_data, sample_file):
        # 创建另一个用户
        client.post("/auth/register", json={
            "username": "sharetarget",
            "password": "Share123!",
            "public_key": "share-pub-key",
        })

        # 上传文件
        upload_resp = client.post(
            "/files/upload",
            files={"file": ("shared.txt", sample_file, "text/plain")},
            data={
                "encrypted_key": "aes-encrypted-key-123",
                "original_filename": "shared.txt",
            },
            headers=auth_header,
        )
        file_id = upload_resp.json()["file_id"]

        # 分享给另一个用户
        resp = client.post(
            f"/files/{file_id}/share",
            json={
                "target_username": "sharetarget",
                "encrypted_aes_key": "re-encrypted-key-for-sharetarget",
            },
            headers=auth_header,
        )
        assert resp.status_code == 200
        assert "shared with" in resp.json()["message"]

    def test_share_to_nonexistent_user(self, client, token, auth_header, sample_file):
        upload_resp = client.post(
            "/files/upload",
            files={"file": ("test.txt", sample_file, "text/plain")},
            data={
                "encrypted_key": "key",
                "original_filename": "test.txt",
            },
            headers=auth_header,
        )
        file_id = upload_resp.json()["file_id"]

        resp = client.post(
            f"/files/{file_id}/share",
            json={"target_username": "nobody", "encrypted_aes_key": "key"},
            headers=auth_header,
        )
        assert resp.status_code == 404

    def test_rename_file(self, client, token, auth_header, sample_file):
        upload_resp = client.post(
            "/files/upload",
            files={"file": ("oldname.txt", sample_file, "text/plain")},
            data={"encrypted_key": "key", "original_filename": "oldname.txt"},
            headers=auth_header,
        )
        file_id = upload_resp.json()["file_id"]

        resp = client.put(
            f"/files/{file_id}/rename",
            json={"new_name": "newname.txt"},
            headers=auth_header,
        )
        assert resp.status_code == 200
        assert resp.json()["new_filename"] == "newname.txt"

    def test_rename_empty_name(self, client, token, auth_header, sample_file):
        upload_resp = client.post(
            "/files/upload",
            files={"file": ("test.txt", sample_file, "text/plain")},
            data={"encrypted_key": "key", "original_filename": "test.txt"},
            headers=auth_header,
        )
        file_id = upload_resp.json()["file_id"]

        resp = client.put(
            f"/files/{file_id}/rename",
            json={"new_name": "  "},
            headers=auth_header,
        )
        assert resp.status_code == 400

    def test_batch_delete(self, client, token, auth_header, sample_file):
        # 上传两个文件
        ids = []
        for name in ["a.txt", "b.txt"]:
            resp = client.post(
                "/files/upload",
                files={"file": (name, sample_file, "text/plain")},
                data={"encrypted_key": "key", "original_filename": name},
                headers=auth_header,
            )
            ids.append(resp.json()["file_id"])

        # 批量删除
        resp = client.post(
            "/files/batch-delete",
            json={"file_ids": ids},
            headers=auth_header,
        )
        assert resp.status_code == 200

        # 确认列表为空
        resp = client.get("/files/list", headers=auth_header)
        assert resp.json() == []

    def test_delete_file(self, client, token, auth_header, sample_file):
        upload_resp = client.post(
            "/files/upload",
            files={"file": ("delete_me.txt", sample_file, "text/plain")},
            data={"encrypted_key": "key", "original_filename": "delete_me.txt"},
            headers=auth_header,
        )
        file_id = upload_resp.json()["file_id"]

        resp = client.delete(f"/files/{file_id}", headers=auth_header)
        assert resp.status_code == 200

        # 确认已删除
        resp = client.get(f"/files/{file_id}/download", headers=auth_header)
        assert resp.status_code == 404


class TestRateLimit:
    """速率限制测试"""

    def test_login_rate_limit(self, client, test_user_data):
        """连续错误登录超过限制应返回 429"""
        # 先注册
        client.post("/auth/register", json=test_user_data)

        for i in range(12):
            resp = client.post("/auth/login", data={
                "username": test_user_data["username"],
                "password": "WrongPass!",
            })
            if resp.status_code == 429:
                return  # 测试通过
        pytest.fail("未触发速率限制（应在大约第11次请求时返回 429）")


class TestFileKey:
    """文件密钥相关测试"""

    def test_get_file_key(self, client, token, auth_header, sample_file):
        upload_resp = client.post(
            "/files/upload",
            files={"file": ("secret.txt", sample_file, "text/plain")},
            data={"encrypted_key": "my-encrypted-aes-key", "original_filename": "secret.txt"},
            headers=auth_header,
        )
        file_id = upload_resp.json()["file_id"]

        resp = client.get(f"/files/{file_id}/key", headers=auth_header)
        assert resp.status_code == 200
        data = resp.json()
        assert data["encrypted_key"] == "my-encrypted-aes-key"

    def test_get_file_key_unauthorized(self, client, token, auth_header, sample_file):
        upload_resp = client.post(
            "/files/upload",
            files={"file": ("secret.txt", sample_file, "text/plain")},
            data={"encrypted_key": "key", "original_filename": "secret.txt"},
            headers=auth_header,
        )
        file_id = upload_resp.json()["file_id"]

        # 其他用户不应获取密钥
        client.post("/auth/register", json={
            "username": "other", "password": "Other123!", "public_key": "pk",
        })
        other_token = client.post("/auth/login", data={
            "username": "other", "password": "Other123!",
        }).json()["access_token"]

        resp = client.get(
            f"/files/{file_id}/key",
            headers={"Authorization": f"Bearer {other_token}"},
        )
        assert resp.status_code == 403
