# app/rate_limiter.py
from __future__ import annotations
from collections import defaultdict, deque
from typing import Deque, Dict, Tuple
import time

# simple limiter for requests (anti-bruteforce)
class RateLimiter:
    def __init__(self) -> None:
        self._buckets: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)
        self._lock_until: Dict[str, float] = {}

    # current time
    @staticmethod
    def _now() -> float:
        return time.time()

    # pair kind+key
    @staticmethod
    def _pair(kind: str, key: str) -> Tuple[str, str]:
        return kind, key  # style: no redundant parentheses

    # check if allowed or too many tries
    def allow(self, kind: str, key: str, limit: int, window_s: int):
        now = self._now()
        locked_until = self._lock_until.get(key)
        if locked_until and locked_until > now:
            return False, int(locked_until - now)

        nk = self._pair(kind, key)
        q = self._buckets[nk]
        cutoff = now - window_s
        while q and q[0] < cutoff:
            q.popleft()

        if len(q) < limit:
            q.append(now)
            return True, 0

        retry_after = int(q[0] - cutoff) + 1
        return False, max(retry_after, 1)

    # manually lock user/ip
    def lock(self, key: str, seconds: int) -> None:
        self._lock_until[key] = self._now() + max(0, int(seconds))

    # clear rate limit for key
    def clear(self, kind: str, key: str) -> None:
        self._buckets.pop(self._pair(kind, key), None)

rate_limiter = RateLimiter()

# helper: get client IP
def _client_ip_from_environ(remote_addr: str | None, xff: str | None) -> str:
    if xff:
        return xff.split(",")[0].strip()
    return (remote_addr or "unknown").strip()

# key for login attempts
def rate_key_login(request, email: str) -> str:
    ip = _client_ip_from_environ(
        getattr(request, "remote_addr", None),
        request.headers.get("X-Forwarded-For") if hasattr(request, "headers") else None,
    )
    return f"login:{ip}:{(email or '').lower()}"

# key for 2FA token attempts
def rate_key_token(user_id: int | str) -> str:
    return f"token:{user_id}"
