"""
FastAPI 应用主模块
================
负责：
  1. 创建 FastAPI 应用实例
  2. 配置 CORS（跨域资源共享）中间件
  3. 挂载静态文件目录（前端 HTML/CSS/JS）
  4. 注册各功能模块的路由
  5. 配置日志系统
  6. 启动时校验配置并初始化数据库表

启动顺序：
  config.validate() → Base.metadata.create_all() → 注册路由 → 挂载静态文件 → 启动 uvicorn
"""
import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from app import auth, users, files, database, config

# ── 日志配置 ──
# 统一格式：时间 + 级别 + 模块名 + 消息
logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s")
logger = logging.getLogger(__name__)

# ── 启动时校验和初始化 ──
# 1. 校验配置（SECRET_KEY 是否设置、ALGORITHM 是否合法）
config.settings.validate()
# 2. 根据 ORM 模型自动创建数据库表（已存在的表不会重复创建）
database.Base.metadata.create_all(bind=database.engine)

# ── 创建 FastAPI 应用 ──
app = FastAPI(title="ECC File Sharing System", version="1.0")

# ── CORS 中间件 ──
# 允许前端页面（同源或指定源）跨域访问 API
# 生产环境中应把 allow_origins 限制为具体域名
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:8000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── 挂载静态文件 ──
# 将 app/static/ 目录映射到 /static 路径
# 前端 index.html 通过 /static/index.html 访问
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# ── 注册路由模块 ──
# 各模块通过 APIRouter 定义路由，在此统一注册
app.include_router(auth.router)     # /auth/register  /auth/login  /auth/change-password
app.include_router(users.router)    # /users/me  /users/{username}/public_key
app.include_router(files.router)    # /files/upload  /files/list  /files/{id}/download 等

# ── 根路径重定向到前端页面 ──
@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")
