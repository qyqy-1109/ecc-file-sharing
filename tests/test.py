"""
ECC 文件共享系统 — 单元测试
===========================
运行方式: pytest tests/test.py -v

测试覆盖范围：
  - TestAuth:     注册、登录、JWT 鉴权、改密
  - TestUsers:    用户信息查询、公钥查询、注销
  - TestFiles:    上传、下载、列表、分享、删除、重命名、批量删除
  - TestRateLimit: 速率限制触发
  - TestFileKey:  独立密钥接口（分享流程）

测试数据库：
  使用独立的 SQLite test.db 文件，每个测试函数前后自动重建表结构

运行前提：
  pip install pytest httpx
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
# 使用临时目录避免污染实际数据
os.environ["APP_BASE_DIR"] = tempfile.mkdtemp(prefix="ecc_test_")
os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only"

TEST_DATABASE_URL = "sqlite:///./test.db"

# 导入项目模块
from app.database import Base, get_db
from app.main import app
from app import models, schemas
from app.rate_limit import login_limiter, register_limiter, change_pwd_limiter


# ── 测试数据库引擎 ──
# 使用独立的 test.db，不影响开发/生产数据
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    """
    覆写 FastAPI 的 get_db 依赖
    ============================
    将所有数据库操作重定向到测试数据库
    通过 app.dependency_overrides 注入
    """
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


# 注入测试数据库依赖
app.dependency_overrides[get_db] = override_get_db


# ════════════════════════════════════════════════════════════
#  Fixtures（测试夹具）
# ════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def setup_db():
    """
    每个测试函数自动执行：
      - 测试前：创建所有表
      - 测试后：删除所有表（保证测试隔离）
    """
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(autouse=True)
def reset_rate_limiters():
    """
    每个测试函数自动执行：
      - 测试后：清空所有限流器状态（避免测试间干扰）
    """
    yield
    login_limiter._store.clear()
    register_limiter._store.clear()
    change_pwd_limiter._store.clear()


@pytest.fixture
def client():
    """返回 FastAPI TestClient，用于模拟 HTTP 请求"""
    return TestClient(app)


@pytest.fixture
def test_user_data():
    """标准测试用户数据"""
    return {
        "username": "testuser",
        "password": "Test123!",
        "public_key": "ec-pub-key-12345",
    }


@pytest.fixture
def registered_user(client, test_user_data):
    """注册一个测试用户，返回用户信息"""
    resp = client.post("/auth/register", json=test_user_data)
    assert resp.status_code == 200
    return resp.json()


@pytest.fixture
def token(client, test_user_data):
    """
    注册并登录，返回 JWT 令牌
    依赖 registered_user 的执行结果
    """
    client.post("/auth/register", json=test_user_data)
    resp = client.post("/auth/login", data={
        "username": test_user_data["username"],
        "password": test_user_data["password"],
    })
    assert resp.status_code == 200
    return resp.json()["access_token"]


@pytest.fixture
def auth_header(token):
    """返回带 Bearer 令牌的 Authorization 头"""
    return {"Authorization": f"Bearer {token}"}


# ════════════════════════════════════════════════════════════
#  测试用例
# ════════════════════════════════════════════════════════════

class TestAuth:
    """
    认证模块测试
    ===========
    覆盖注册、登录、改密、令牌验证的正常和异常路径
    """

    def test_register_success(self, client, test_user_data):
        """正常注册应返回 200 和用户信息"""
        resp = client.post("/auth/register", json=test_user_data)
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == test_user_data["username"]
        assert "id" in data
        assert "created_at" in data

    def test_register_duplicate(self, client, test_user_data):
        """重复注册同一用户名应返回 400"""
        client.post("/auth/register", json=test_user_data)
        resp = client.post("/auth/register", json=test_user_data)
        assert resp.status_code == 400
        assert "already registered" in resp.json()["detail"]

    def test_register_short_password(self, client, test_user_data):
        """密码少于6位应返回 400"""
        data = {**test_user_data, "password": "12345"}
        resp = client.post("/auth/register", json=data)
        assert resp.status_code == 400
        assert "不能少于" in resp.json()["detail"]

    def test_login_success(self, client, test_user_data):
        """正常登录应返回 JWT 令牌"""
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
        """错误密码应返回 400"""
        client.post("/auth/register", json=test_user_data)
        resp = client.post("/auth/login", data={
            "username": test_user_data["username"],
            "password": "WrongPass1!",
        })
        assert resp.status_code == 400
        assert "Incorrect" in resp.json()["detail"]

    def test_login_nonexistent_user(self, client):
        """不存在的用户应返回 400"""
        resp = client.post("/auth/login", data={
            "username": "nobody",
            "password": "SomePass1!",
        })
        assert resp.status_code == 400

    def test_change_password_success(self, client, token, auth_header):
        """正常改密后应能用新密码登录"""
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
        """旧密码错误应返回 400"""
        resp = client.post("/auth/change-password", json={
            "old_password": "WrongOld!",
            "new_password": "NewPass456!",
        }, headers=auth_header)
        assert resp.status_code == 400
        assert "incorrect" in resp.json()["detail"].lower()

    def test_access_without_token(self, client, auth_header):
        """无令牌访问受保护接口应返回 401"""
        resp = client.get("/users/me")
        assert resp.status_code == 401

    def test_access_with_invalid_token(self, client):
        """无效令牌应返回 401"""
        resp = client.get("/users/me", headers={"Authorization": "Bearer invalid-token"})
        assert resp.status_code == 401


class TestUsers:
    """用户模块测试"""

    def test_get_me(self, client, auth_header):
        """获取当前用户信息"""
        resp = client.get("/users/me", headers=auth_header)
        assert resp.status_code == 200
        assert resp.json()["username"] == "testuser"

    def test_get_public_key(self, client, test_user_data, auth_header):
        """查询用户公钥"""
        resp = client.get(f"/users/{test_user_data['username']}/public_key", headers=auth_header)
        assert resp.status_code == 200
        data = resp.json()
        assert data["public_key"] == test_user_data["public_key"]

    def test_get_public_key_not_found(self, client, auth_header):
        """查询不存在的用户应返回 404"""
        resp = client.get("/users/nonexistent/public_key", headers=auth_header)
        assert resp.status_code == 404

    def test_delete_account(self, client, auth_header):
        """注销账户后应无法登录"""
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
    """创建测试用的内存文件（BytesIO 模拟真实上传）"""
    import io
    return io.BytesIO(b"Hello, ECC File Sharing! This is test content." * 100)


class TestFiles:
    """文件模块测试"""

    def test_upload_file(self, client, token, auth_header, sample_file):
        """正常上传应返回文件 ID 和文件名"""
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
        """新用户文件列表应为空"""
        resp = client.get("/files/list", headers=auth_header)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_files_after_upload(self, client, token, auth_header, sample_file):
        """上传后文件列表应有 1 个文件"""
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
        """下载文件应返回文件内容和加密密钥头"""
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

        # 下载验证
        resp = client.get(f"/files/{file_id}/download", headers=auth_header)
        assert resp.status_code == 200
        assert resp.headers.get("x-filename") is not None
        assert resp.headers.get("x-encrypted-key") is not None

    def test_download_nonexistent_file(self, client, auth_header):
        """下载不存在的文件应返回 404"""
        resp = client.get("/files/999/download", headers=auth_header)
        assert resp.status_code == 404

    def test_download_unauthorized(self, client, token, auth_header, test_user_data, sample_file):
        """未授权用户下载他人文件应返回 403"""
        # 上传文件
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

        # 用另一个用户尝试下载
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
        """分享文件给其他用户应成功"""
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

        # 分享
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
        """分享给不存在用户应返回 404"""
        upload_resp = client.post(
            "/files/upload",
            files={"file": ("test.txt", sample_file, "text/plain")},
            data={"encrypted_key": "key", "original_filename": "test.txt"},
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
        """重命名文件应成功"""
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
        """空白文件名应返回 400"""
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
        """批量删除应删除所有指定文件"""
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
        """删除单个文件后下载应返回 404"""
        upload_resp = client.post(
            "/files/upload",
            files={"file": ("delete_me.txt", sample_file, "text/plain")},
            data={"encrypted_key": "key", "original_filename": "delete_me.txt"},
            headers=auth_header,
        )
        file_id = upload_resp.json()["file_id"]

        resp = client.delete(f"/files/{file_id}", headers=auth_header)
        assert resp.status_code == 200

        # 确认文件已删除
        resp = client.get(f"/files/{file_id}/download", headers=auth_header)
        assert resp.status_code == 404


class TestRateLimit:
    """速率限制测试"""

    def test_login_rate_limit(self, client, test_user_data):
        """
        连续错误登录超过限制应返回 429
        ==============================
        注意：登录限流器设为 60秒内10次
        因此第11次请求应触发限流
        """
        client.post("/auth/register", json=test_user_data)

        for i in range(12):
            resp = client.post("/auth/login", data={
                "username": test_user_data["username"],
                "password": "WrongPass!",
            })
            if resp.status_code == 429:
                return  # 测试通过：限流正常触发
        pytest.fail("未触发速率限制（应在大约第11次请求时返回 429）")


class TestFileKey:
    """文件密钥相关测试（用于分享流程）"""

    def test_get_file_key(self, client, token, auth_header, sample_file):
        """获取自己文件的密钥应成功"""
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
        """未授权用户获取密钥应返回 403"""
        upload_resp = client.post(
            "/files/upload",
            files={"file": ("secret.txt", sample_file, "text/plain")},
            data={"encrypted_key": "key", "original_filename": "secret.txt"},
            headers=auth_header,
        )
        file_id = upload_resp.json()["file_id"]

        # 另一个用户不应获取密钥
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
