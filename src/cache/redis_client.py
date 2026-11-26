"""
src/cache/redis_client.py
=========================
Asynchronous Redis Connection Manager with connection pooling.
Serves as the shared backbone for:
  1. Semantic Vector Caching
  2. Redlock Distributed Locking
  3. Sliding-Window Rate Limiting
  4. LangGraph State Checkpointing
"""

from typing import Optional
import redis.asyncio as aioredis
import structlog

from src.config import settings

logger = structlog.get_logger(__name__)


class RedisClientManager:
    """
    Manages an asynchronous Redis connection pool.
    """

    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url or settings.redis_url
        self._pool: Optional[aioredis.ConnectionPool] = None
        self._client: Optional[aioredis.Redis] = None

    async def get_client(self) -> aioredis.Redis:
        """
        Returns a connected async Redis client backed by a shared ConnectionPool.
        """
        if self._client is None:
            self._pool = aioredis.ConnectionPool.from_url(
                self.redis_url,
                decode_responses=True,
                max_connections=50,
                socket_connect_timeout=2.0,
            )
            self._client = aioredis.Redis(connection_pool=self._pool)
            logger.info("redis_pool_initialized", url=self.redis_url.split("@")[-1])

        return self._client

    async def ping(self) -> bool:
        """Healthcheck: verifies Redis connectivity."""
        client = await self.get_client()
        return bool(await client.ping())

    async def close(self) -> None:
        """Gracefully closes the client and underlying connection pool."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        if self._pool is not None:
            await self._pool.disconnect()
            self._pool = None
        logger.info("redis_pool_closed")


# Module-level singleton
redis_manager = RedisClientManager()
