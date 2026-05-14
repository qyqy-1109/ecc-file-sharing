"""
速率限制模块
===========
基于内存的滑动窗口算法，防止暴力破解和滥用：

应用场景：
  - 登录接口：    60秒内最多 10 次（防密码爆破）
  - 注册接口：    60秒内最多  5 次（防批量注册）
  - 改密接口：    60秒内最多  5 次（防恶意改密）

实现方案选择：
  - 使用内存字典存储（不依赖 Redis）
  - 适合单进程部署场景
  - 多进程部署需替换为 Redis 方案

清理策略：
  - 每次查询时清理当前 key 的过期记录
  - 每 500 次查询触发一次全局清理（移除所有过期 key）
"""
import time
from collections import defaultdict
from fastapi import Request, HTTPException


class RateLimiter:
    """
    滑动窗口速率限制器
    =================
    算法：滑动窗口（而非固定窗口），更平滑
      - 记录每次请求的时间戳
      - 判断时清理窗口外的旧记录
      - 窗口内的记录数超过上限则拒绝

    内存模型：
      _store = {
          "192.168.1.1:login":    [1700000000.1, 1700000001.2, ...],
          "192.168.1.1:register": [1700000000.5, ...],
      }
    """

    def __init__(self, max_requests: int = 5, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # defaultdict 确保首次访问 key 时自动初始化为空列表
        self._store: dict[str, list[float]] = defaultdict(list)
        self._probe_count = 0    # 调用计数，用于触发全局清理

    def _clean_old(self, key: str, now: float) -> None:
        """
        清理单个 key 的过期时间戳
        ========================
        只移除窗口外的记录，保留窗口内的
        如果清理后列表为空，删除整个 key（节省内存）
        """
        cutoff = now - self.window_seconds
        self._store[key] = [t for t in self._store[key] if t > cutoff]
        if not self._store[key]:
            del self._store[key]

    def _cleanup_stale(self, now: float) -> None:
        """
        全局清理：遍历所有 key，移除过期的
        ====================================
        每 500 次调用触发一次，摊销成本
        防止不再访问的 IP 残留空条目导致内存泄漏
        """
        cutoff = now - self.window_seconds
        stale = []
        for key, timestamps in self._store.items():
            if not any(t > cutoff for t in timestamps):
                stale.append(key)
        for key in stale:
            del self._store[key]

    def is_allowed(self, key: str) -> bool:
        """
        检查请求是否允许
        ================
        返回 True 表示允许，False 表示被限流

        步骤：
          1. 清理当前 key 的过期时间戳
          2. 每 500 次触发一次全局过期清理
          3. 判断窗口内请求数是否超限
          4. 未超限则记录本次时间戳
        """
        now = time.time()
        self._clean_old(key, now)

        # 每 500 次 is_allowed 调用触发一次全局清理
        self._probe_count += 1
        if self._probe_count % 500 == 0:
            self._cleanup_stale(now)

        if len(self._store[key]) >= self.max_requests:
            return False
        self._store[key].append(now)
        return True


# ── 预设限流器实例 ──
# 可根据实际需求调整 max_requests 和 window_seconds

login_limiter = RateLimiter(max_requests=10, window_seconds=60)
"""登录限流器：60秒内最多10次尝试，防止暴力破解"""

register_limiter = RateLimiter(max_requests=5, window_seconds=60)
"""注册限流器：60秒内最多5次注册，防止批量注册垃圾账号"""

change_pwd_limiter = RateLimiter(max_requests=5, window_seconds=60)
"""改密限流器：60秒内最多5次改密，防止恶意修改密码"""


def check_rate_limit(request: Request, limiter: RateLimiter, action: str) -> None:
    """
    检查速率限制
    ============
    被限流时抛出 HTTP 429 (Too Many Requests)

    参数：
      - request: FastAPI Request 对象（提取客户端 IP）
      - limiter: 对应操作的限流器实例
      - action: 操作名称（用于区分不同接口的限流计数）
    """
    # 安全获取客户端 IP
    client_ip = request.client.host if request.client else "unknown"
    # 组合 key：按 IP + 操作类型分别计数
    key = f"{client_ip}:{action}"
    if not limiter.is_allowed(key):
        raise HTTPException(
            status_code=429,
            detail=f"操作过于频繁，请等待 {limiter.window_seconds} 秒后再试",
        )
