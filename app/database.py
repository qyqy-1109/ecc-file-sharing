"""
数据库模块
=========
- 使用 SQLAlchemy 2.0 风格的 ORM
- SQLite 数据库（单文件，零配置，适合轻量级部署）
- 启用 WAL 模式提升并发读写性能
- 通过 FastAPI 依赖注入管理数据库会话生命周期

架构说明：
  engine（全局唯一）→ SessionLocal（会话工厂）→ get_db()（每个请求一个会话）
"""
from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from app.config import settings

# ── 创建数据库引擎 ──
# SQLite 需要 check_same_thread=False 才能在 FastAPI 多线程环境下工作
engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
)


# ── SQLite 连接事件：自动设置 WAL 模式和同步级别 ──
# WAL (Write-Ahead Logging) 允许读写并发，比默认的 DELETE 模式性能更好
# synchronous=NORMAL 在保证安全的前提下减少 fsync 次数
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()


# ── 会话工厂 ──
# autocommit=False：所有写操作需要显式 commit()
# autoflush=False：避免自动 flush 导致意外查询
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """所有 ORM 模型的基类"""
    pass


def get_db():
    """
    FastAPI 依赖注入：为每个请求创建独立的数据库会话
    ===============================================
    使用 yield 模式：
      - 进入路由时创建会话（yield db）
      - 退出路由时自动关闭会话（finally: db.close()）
    无论请求成功还是异常，finally 块都会执行，确保连接不泄漏
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
