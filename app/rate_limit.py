"""基于内存的滑动窗口速率限制器"""

import time
from collections import defaultdict
from fastapi import Request, HTTPException


class RateLimiter:
    """
    滑动窗口速率限制：
    - max_requests: 时间窗口内允许的最大请求数
    - window_seconds: 时间窗口（秒）
    """

    def __init__(self, max_requests: int = 5, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._store: dict[str, list[float]] = defaultdict(list)

    def _clean_old(self, key: str, now: float) -> None:
        cutoff = now - self.window_seconds
        self._store[key] = [t for t in self._store[key] if t > cutoff]
        if not self._store[key]:
            del self._store[key]

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        self._clean_old(key, now)
        if len(self._store[key]) >= self.max_requests:
            return False
        self._store[key].append(now)
        return True


# 不同端点的限流器实例
login_limiter = RateLimiter(max_requests=10, window_seconds=60)       # 60秒最多10次登录
register_limiter = RateLimiter(max_requests=5, window_seconds=60)     # 60秒最多5次注册
change_pwd_limiter = RateLimiter(max_requests=5, window_seconds=60)   # 60秒最多5次改密


def check_rate_limit(request: Request, limiter: RateLimiter, action: str) -> None:
    """检查速率限制，超限时抛出 HTTPException"""
    client_ip = request.client.host if request.client else "unknown"
    key = f"{client_ip}:{action}"
    if not limiter.is_allowed(key):
        raise HTTPException(
            status_code=429,
            detail=f"操作过于频繁，请等待 {limiter.window_seconds} 秒后再试",
        )
