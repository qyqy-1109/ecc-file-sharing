"""
ECC 文件共享系统 — 启动入口
=======================
支持两种运行模式：
  1. 开发模式：python run.py（源代码直接运行）
  2. 打包模式：PyInstaller 打包后双击 exe 运行

启动流程：
  确定数据目录 → 设置环境变量 → 导入 FastAPI 应用 → 自动打开浏览器 → 启动 uvicorn 服务器
"""
import os
import sys
import webbrowser
import threading


# ── 1. 确定数据目录（数据库、上传文件、.env 所在位置）──
# PyInstaller 打包后 sys.frozen 为 True，此时数据目录为 exe 所在目录
# 开发模式下数据目录就是项目根目录
if getattr(sys, "frozen", False):
    DATA_DIR = os.path.dirname(sys.executable)
else:
    _root_dir = os.path.dirname(os.path.abspath(__file__))
    if _root_dir not in sys.path:
        sys.path.insert(0, _root_dir)
    DATA_DIR = _root_dir

# ── 2. 通过环境变量通知 config.py 数据目录位置 ──
# config.py 在模块加载时读取此变量来确定 .env / 数据库 / 上传目录的路径
os.environ["APP_BASE_DIR"] = DATA_DIR

# ── 3. 导入应用模块（config.py 此时读取 APP_BASE_DIR）──
from app.main import app
import uvicorn


# ── 4. 自动打开浏览器 ──
# 延迟 1.5 秒确保服务器先启动完毕
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

    # 浏览器启动放在独立线程中，不阻塞服务器启动
    threading.Thread(target=_open_browser, daemon=True).start()
    # 绑定 127.0.0.1 仅本地访问，避免局域网暴露
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
