# ECC 认证文件共享系统

基于椭圆曲线密码学（ECC）的端到端加密文件共享系统。采用 **FastAPI** 构建后端服务，**原生 Web Crypto API** 实现浏览器端加密，**零知识安全模型**确保服务器无法查看用户文件内容。

---

## 技术架构

```
┌─────────────────────────────────────────────────────────────┐
│                        浏览器（前端）                         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Web Crypto API (ECC P-384)              │   │
│  │  密钥对生成 → ECDH密钥协商 → AES-256-GCM加密/解密    │   │
│  └──────────────────────────────────────────────────────┘   │
│                          ↕ HTTPS                            │
├─────────────────────────────────────────────────────────────┤
│                      FastAPI 后端服务                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐  │
│  │  认证模块 │  │  文件模块 │  │  用户模块 │  │  速率限制   │  │
│  │ JWT签发   │  │ 上传/下载 │  │ 公钥查询  │  │ 滑动窗口   │  │
│  │ 密码哈希  │  │ 分享/删除 │  │ 账户管理  │  │ 防暴力破解 │  │
│  └──────────┘  └──────────┘  └──────────┘  └────────────┘  │
│                          ↕ ORM                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │         SQLite (WAL模式) + SQLAlchemy                 │   │
│  │   User | File | FileKey | Log                        │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### 安全模型（零知识架构）

| 阶段 | 操作位置 | 服务器可见数据 |
|------|----------|---------------|
| 密钥生成 | 浏览器 (Web Crypto API) | 仅公钥 |
| 文件加密 | 浏览器 (AES-256-GCM) | 密文 |
| 密钥封装 | 浏览器 (ECIES + HKDF) | 加密后的密钥 |
| 文件解密 | 浏览器 (AES-256-GCM) | 密文 |
| 用户认证 | 后端 (bcrypt + JWT) | 密码哈希 |

---

## 技术栈

| 层级 | 技术 | 用途 |
|------|------|------|
| 后端框架 | FastAPI (Python 3.9+) | RESTful API |
| 数据库 | SQLite + SQLAlchemy 2.0 | 持久化存储 |
| 密码学（后端） | python-jose, passlib (PBKDF2) | JWT 认证, 密码哈希 |
| 密码学（前端） | Web Crypto API (P-384) | ECC 密钥对, AES 加解密 |
| 前端 | 原生 HTML/CSS/JavaScript | 单页应用 (SPA) |

---

## 项目结构

```
ecc-file-sharing/
├── main.py              # FastAPI 应用入口，路由注册
├── config.py            # 配置（密钥、数据库路径等）
├── database.py          # SQLAlchemy 引擎与会话管理
├── models.py            # ORM 模型（User / File / FileKey / Log）
├── schemas.py           # Pydantic 请求/响应模型
├── auth.py              # 注册 / 登录 / JWT / 修改密码
├── users.py             # 用户公钥查询 / 账户管理
├── files.py             # 文件上传 / 下载 / 分享 / 删除 / 重命名
├── rate_limit.py        # 滑动窗口速率限制
├── utils.py             # 审计日志工具
├── run.py               # 统一启动入口（支持开发与打包模式）
├── test.py              # 单元测试（pytest, 29 项）
├── requirements.txt     # Python 依赖
├── .env                 # 环境变量（SECRET_KEY）
├── .env.example         # 环境变量示例
├── static/
│   └── index.html       # 前端单页应用（~1200 行）
└── uploads/             # 加密文件存储目录（运行时创建）
```

---

## API 接口

### 认证 (`/auth`)

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/auth/register` | 用户注册 |
| POST | `/auth/login` | 用户登录（返回 JWT） |
| POST | `/auth/change-password` | 修改密码 |

### 用户 (`/users`)

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/users/me` | 获取当前用户信息 |
| GET | `/users/{username}/public_key` | 获取用户公钥 |
| DELETE | `/users/me` | 删除账户 |

### 文件 (`/files`)

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/files/upload` | 上传加密文件 |
| GET | `/files/list` | 列出文件列表 |
| GET | `/files/{id}/download` | 下载文件（含加密密钥） |
| GET | `/files/{id}/key` | 获取文件加密密钥 |
| POST | `/files/{id}/share` | 分享文件给其他用户 |
| DELETE | `/files/{id}` | 删除文件 |
| PUT | `/files/{id}/rename` | 重命名文件 |
| POST | `/files/batch-delete` | 批量删除文件 |

### API 文档

启动服务后访问：

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

---

## 快速开始

### 环境要求

- Python 3.9+
- pip

### 安装与运行

```bash
# 1. 克隆项目
git clone <repo-url>
cd ecc-file-sharing

# 2. 创建虚拟环境（推荐）
python -m venv venv
venv\Scripts\activate     # Windows
source venv/bin/activate  # Linux/Mac

# 3. 安装依赖
pip install -r requirements.txt

# 4. 配置密钥
# 生成密钥: python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(32))"
# 写入 .env 文件:
echo SECRET_KEY=your-generated-key-here > .env

# 5. 启动服务
python run.py
# 或: uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

启动后访问 **http://localhost:8000**

### 打包为可执行文件

```bash
pip install pyinstaller
python -m PyInstaller --onedir --name FileShareApp --add-data "static;app/static" --add-data "__init__.py;app" --hidden-import app.main --hidden-import app.auth --hidden-import app.files --hidden-import app.users --hidden-import app.database --hidden-import app.config --hidden-import app.models --hidden-import app.schemas --hidden-import app.rate_limit --hidden-import app.utils --hidden-import uvicorn.logging --hidden-import uvicorn.loops.auto --hidden-import uvicorn.protocols.http.auto --hidden-import passlib.handlers.pbkdf2 --hidden-import passlib.handlers.bcrypt run.py
```

生成的可执行文件位于 `dist/FileShareApp/`，双击 `FileShareApp.exe` 即可运行。

---

## 测试

```bash
# 安装测试依赖
pip install pytest httpx

# 运行全部测试
pytest test.py -v

# 运行指定测试类
pytest test.py::TestAuth -v
pytest test.py::TestFiles -v
```

测试覆盖：认证、用户管理、文件上传/下载/分享/删除/重命名/批量删除、速率限制、权限控制。

---

## 核心加密流程

```
文件所有者：
  1. 生成 ECC P-384 密钥对（浏览器）
  2. 生成 AES-256 随机密钥
  3. 用 AES-GCM 加密文件
  4. 用接收者公钥通过 ECDH + HKDF 派生共享密钥
  5. 用共享密钥加密 AES 密钥（ECIES）
  6. 上传密文 + 加密后的 AES 密钥

文件接收者：
  1. 下载密文 + 加密后的 AES 密钥
  2. 用私钥通过 ECDH + HKDF 派生出共享密钥
  3. 解密获得 AES 密钥
  4. 用 AES-GCM 解密密文
```

---

## 毕业设计说明

本项目适用于 **Web 开发与网络安全交叉方向** 的本科毕业设计，技术亮点：

- 混合加密架构：ECC + AES 结合，兼顾安全性与性能
- 零知识安全模型：服务器零信任，无法获取用户私钥和文件明文
- 前向安全性：每次加密使用临时 ECC 密钥对
- 完整的全栈开发：后端 API + 前端 SPA + 数据库设计
- 工程化实践：pytest 单元测试、PyInstaller 打包、审计日志、速率限制
