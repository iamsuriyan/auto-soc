"""
src/api/rest/middleware/rate_limiter.py
========================================
Redis-Backed Atomic Sliding-Window Rate Limiter.
Prevents API abuse, runaway webhook loops, and DoS attacks by tracking request
timestamps in a Redis Sorted Set with atomic Lua / Pipeline executions.
"""

import time
from typing import Optional
from fastapi import HTTPException, Request, status
import redis.asyncio as aioredis
import structlog

from src.config import settings

logger = structlog.get_logger(__name__)


class SlidingWindowRateLimiter:
    """
    Atomic Sliding-Window Rate Limiter using Redis Sorted Sets.
    
    Why Atomic Sliding-Window?
    - Fixed-window counters suffer from the "double-rate burst" at window boundaries.
    - Token buckets require complex lock synchronisation across distributed nodes.
    - Redis Sorted Sets track exact millisecond timestamps and execute pruning,
      counting, and insertion atomically inside a single pipeline or transaction.
    """

    def __init__(
        self,
        requests_per_window: int = 60,
        window_seconds: int = 60,
        redis_client: Optional[aioredis.Redis] = None
    ):
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self.redis = redis_client
        # In-memory fallback if Redis is unavailable
        self._local_history = {}

    async def get_redis(self) -> Optional[aioredis.Redis]:
        """Lazy-initializes async Redis connection if not provided."""
        if self.redis is None:
            try:
                self.redis = aioredis.from_url(
                    settings.redis_url,
                    decode_responses=True,
                    socket_connect_timeout=0.5
                )
                await self.redis.ping()
            except Exception as e:
                logger.warning("redis_rate_limiter_connection_failed_fallback_local", error=str(e))
                self.redis = None
        return self.redis

    async def is_rate_limited(self, identifier: str) -> bool:
        """
        Executes an atomic sliding-window check for the given client identifier (e.g. IP or User ID).
        Returns True if the client has exceeded their quota.
        """
        now = time.time()
        window_start = now - self.window_seconds
        key = f"rate_limit:{identifier}"

        redis_conn = await self.get_redis()

        if redis_conn:
            try:
                # Redis Atomic Pipeline: all 4 operations execute as one atomic batch
                async with redis_conn.pipeline(transaction=True) as pipe:
                    # 1. Remove all timestamps older than the sliding window boundary
                    pipe.zremrangebyscore(key, 0, window_start)
                    # 2. Count requests currently inside the active window
                    pipe.zcard(key)
                    # 3. Add current timestamp to the sorted set
                    pipe.zadd(key, {f"{now}": now})
                    # 4. Set TTL so idle keys automatically expire
                    pipe.expire(key, self.window_seconds + 5)
                    
                    results = await pipe.execute()

                current_count = results[1]

                if current_count >= self.requests_per_window:
                    logger.warning(
                        "rate_limit_exceeded",
                        identifier=identifier,
                        count=current_count,
                        limit=self.requests_per_window
                    )
                    return True
                return False

            except Exception as e:
                logger.error("redis_rate_limit_check_error_using_fallback", error=str(e))

        # Local in-memory sliding window fallback (for testing / offline Redis)
        timestamps = self._local_history.get(identifier, [])
        # Prune older than window_start
        timestamps = [ts for ts in timestamps if ts > window_start]
        if len(timestamps) >= self.requests_per_window:
            self._local_history[identifier] = timestamps
            return True

        timestamps.append(now)
        self._local_history[identifier] = timestamps
        return False


# Global default rate limiter instance (60 requests per 60 seconds per IP)
default_rate_limiter = SlidingWindowRateLimiter(requests_per_window=60, window_seconds=60)


async def rate_limit_dependency(request: Request):
    """
    FastAPI route dependency to enforce sliding-window rate limits.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    
    if await default_rate_limiter.is_rate_limited(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please wait before retrying.",
            headers={"Retry-After": str(default_rate_limiter.window_seconds)}
        )
