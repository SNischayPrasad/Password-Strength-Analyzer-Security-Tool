"""
Minimal in-memory rate limiter (sliding window, per client IP).

Rate limiting stops a single client from hammering the API. In production you
would use a shared store (e.g. Redis) or a gateway/WAF feature, because an
in-memory limiter only protects a single process.
"""

import threading
import time
from collections import defaultdict, deque
from functools import wraps

from flask import current_app, jsonify, request


class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds)."""
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window_seconds:
                hits.popleft()
            if len(hits) >= self.max_requests:
                retry_after = int(self.window_seconds - (now - hits[0])) + 1
                return False, retry_after
            hits.append(now)
            return True, 0


def rate_limited(limiter_name: str):
    """Decorator: apply the named limiter (stored in app.extensions) to a route."""

    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if current_app.config.get("RATE_LIMIT_ENABLED", True):
                limiter: RateLimiter = current_app.extensions["rate_limiters"][limiter_name]
                allowed, retry_after = limiter.check(request.remote_addr or "unknown")
                if not allowed:
                    response = jsonify(error="Too many requests. Please slow down and try again.")
                    response.status_code = 429
                    response.headers["Retry-After"] = str(retry_after)
                    return response
            return view(*args, **kwargs)

        return wrapper

    return decorator
