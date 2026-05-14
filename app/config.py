"""
应用配置模块
===========
负责：
  1. 确定数据目录 base_dir（由 run.py 通过环境变量 APP_BASE_DIR 指定）
  2. 加载 .env 文件中的环境变量
  3. 集中管理所有配置项（密钥、算法、Token过期时间、数据库URL、上传目录）
  4. 启动时校验关键配置是否缺失或非法

配置优先级：环境变量 > .env 文件 > 代码默认值
"""
import os
import logging
from dotenv import load_dotenv

# ── 确定数据目录 ──
# PyInstaller 打包后 run.py 设置 APP_BASE_DIR 指向 exe 所在目录
# 开发模式下 APP_BASE_DIR 为项目根目录
_base_dir = os.environ.get("APP_BASE_DIR")
if not _base_dir:
    _base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── 加载 .env 文件 ──
# 优先从数据目录加载，找不到则回退到当前工作目录
_env_path = os.path.join(_base_dir, ".env")
if os.path.exists(_env_path):
    load_dotenv(_env_path)
else:
    load_dotenv()

logger = logging.getLogger(__name__)


class Settings:
    """
    应用配置单例
    ============
    所有配置通过 os.getenv() 读取，支持 .env 文件或系统环境变量覆盖
    """

    BASE_DIR = _base_dir

    # JWT 签名密钥（必须由用户通过 .env 文件设置）
    SECRET_KEY: str = os.getenv("SECRET_KEY", "")
    # JWT 签名算法（HS256 / HS384 / HS512）
    ALGORITHM: str = "HS256"
    # Token 过期时间（分钟），默认 24 小时
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24
    # SQLite 数据库文件路径
    DATABASE_URL: str = f"sqlite:///{os.path.join(BASE_DIR, 'file_sharing.db')}"
    # 加密文件存储目录
    UPLOAD_DIR: str = os.path.join(BASE_DIR, "uploads")

    def validate(self):
        """
        启动时校验关键配置
        ================
        - SECRET_KEY 不能为空（否则 JWT 不安全）
        - ALGORITHM 必须在 HS256/HS384/HS512 范围内
        """
        if not self.SECRET_KEY:
            raise ValueError(
                "SECRET_KEY 未设置！请在 .env 文件中设置 SECRET_KEY，例如：\n"
                "  SECRET_KEY=your-secure-random-string-here\n"
                "  可运行 python -c \"import secrets; print(secrets.token_urlsafe(32))\" 生成一个"
            )
        if self.ALGORITHM not in ("HS256", "HS384", "HS512"):
            raise ValueError(f"ALGORITHM 设置为 {self.ALGORITHM}，请使用 HS256/HS384/HS512")
        logger.info("配置检查通过")
        return True


# 模块级单例，全局共享
settings = Settings()
