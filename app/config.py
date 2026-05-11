import os
import logging
from dotenv import load_dotenv

# 优先使用环境变量 APP_BASE_DIR（由 run.py 设置，用于 PyInstaller 打包环境）
_base_dir = os.environ.get("APP_BASE_DIR")
if not _base_dir:
    _base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 从数据目录加载 .env 文件
_env_path = os.path.join(_base_dir, ".env")
if os.path.exists(_env_path):
    load_dotenv(_env_path)
else:
    load_dotenv()

logger = logging.getLogger(__name__)


class Settings:
    BASE_DIR = _base_dir

    SECRET_KEY: str = os.getenv("SECRET_KEY", "")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24
    DATABASE_URL: str = f"sqlite:///{os.path.join(BASE_DIR, 'file_sharing.db')}"
    UPLOAD_DIR: str = os.path.join(BASE_DIR, "uploads")

    def validate(self):
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


settings = Settings()
