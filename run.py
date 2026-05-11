"""
ECC File Sharing App - 启动入口
支持开发模式 (python run.py) 与 PyInstaller 打包模式 (双击 exe)
"""

import os
import sys
import webbrowser
import threading


# ── 1. 确定数据目录（数据库、上传文件、.env 所在位置）──
if getattr(sys, "frozen", False):
    # PyInstaller 打包模式：数据目录 = exe 所在目录
    DATA_DIR = os.path.dirname(sys.executable)
else:
    # 开发模式：将项目根目录加入 sys.path
    _root_dir = os.path.dirname(os.path.abspath(__file__))
    if _root_dir not in sys.path:
        sys.path.insert(0, _root_dir)
    DATA_DIR = _root_dir

# ── 2. 通过环境变量通知 config.py ──
os.environ["APP_BASE_DIR"] = DATA_DIR

# ── 3. 导入应用模块 ──
from app.main import app
import uvicorn


# ── 4. 自动打开浏览器 ──
def _open_browser():
    import time
    time.sleep(1.5)
    url = "http://localhost:8000"
    print(f"正在打开浏览器: {url}")
    webbrowser.open(url)


# ── 5. 启动服务器 ──
if __name__ == "__main__":
    print("=" * 50)
    print("  ECC 文件共享系统")
    print("=" * 50)
    print(f"数据目录: {DATA_DIR}")
    print(f"访问地址: http://localhost:8000")
    print(f"按 Ctrl+C 停止服务器")
    print("=" * 50)

    threading.Thread(target=_open_browser, daemon=True).start()
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
