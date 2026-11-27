"""
src/cache/distributed_lock.py
=============================
Redlock-style Distributed Mutual Exclusion Lock backed by Redis.
Prevents multiple concurrent LangGraph agent workers from issuing conflicting
remediation commands against the same target asset (e.g., host IP or user account).

Key Guarantees:
  1. Atomic acquisition via `SET key token NX PX ttl_ms`
  2. Ownership protection: Only the lock holder with matching UUID token can release it
     (enforced via atomic Lua script)
  3. Deadlock prevention: Automatic TTL lease expiration if a worker crashes
"""

import asyncio
from contextlib import asynccontextmanager
import random
from typing import AsyncIterator, Optional
import uuid
import redis.asyncio as aioredis

from src.logger import get_logger
from src.cache.redis_client import RedisClientManager, redis_manager

logger = get_logger(__name__)

# Atomic Lua script: delete lock ONLY IF the stored token matches our owner token
UNLOCK_LUA_SCRIPT = """
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
else
    return 0
end
"""


class LockAcquisitionError(Exception):
    """Raised when a distributed lock cannot be acquired within the timeout."""


class DistributedLock:
    """
    Represents a single acquired distributed lock instance on a resource.
    """

    def __init__(
        self,
        redis: aioredis.Redis,
        resource_name: str,
        ttl_ms: int = 30_000,
    ):
        self.redis = redis
        self.key = f"lock:{resource_name}"
        self.ttl_ms = ttl_ms
        self.token = str(uuid.uuid4())
        self._acquired = False

    async def acquire(
        self,
        timeout_seconds: float = 5.0,
        retry_delay_ms: int = 50,
    ) -> bool:
        """
        Attempts to acquire the lock with jittered retries until timeout_seconds elapses.
        """
        deadline = asyncio.get_running_loop().time() + timeout_seconds

        while True:
            # Atomic SET if Not eXists (NX) with millisecond expiration (PX)
            acquired = await self.redis.set(
                self.key,
                self.token,
                nx=True,
                px=self.ttl_ms,
            )
            if acquired:
                self._acquired = True
                logger.info("distributed_lock_acquired", key=self.key, ttl_ms=self.ttl_ms)
                return True

            if asyncio.get_running_loop().time() >= deadline:
                logger.warning("distributed_lock_timeout", key=self.key, timeout=timeout_seconds)
                return False

            # Jittered sleep prevents thundering-herd contention across workers
            jitter = random.uniform(0.5, 1.5)
            await asyncio.sleep((retry_delay_ms / 1000.0) * jitter)

    async def release(self) -> bool:
        """
        Atomically releases the lock ONLY if this instance still owns the token.
        """
        if not self._acquired:
            return False

        deleted = await self.redis.eval(UNLOCK_LUA_SCRIPT, 1, self.key, self.token)
        self._acquired = False

        if deleted:
            logger.info("distributed_lock_released", key=self.key)
            return True

        logger.warning("distributed_lock_release_skipped_expired_or_stolen", key=self.key)
        return False


class DistributedLockManager:
    """
    High-level factory and async context manager for acquiring Redlocks.
    Usage:
        async with lock_manager.lock("host:10.0.0.50"):
            await execute_firewall_block("10.0.0.50")
    """

    def __init__(self, manager: Optional[RedisClientManager] = None):
        self.manager = manager or redis_manager

    @asynccontextmanager
    async def lock(
        self,
        resource_name: str,
        ttl_ms: int = 30_000,
        timeout_seconds: float = 5.0,
    ) -> AsyncIterator[DistributedLock]:
        client = await self.manager.get_client()
        dlock = DistributedLock(redis=client, resource_name=resource_name, ttl_ms=ttl_ms)

        acquired = await dlock.acquire(timeout_seconds=timeout_seconds)
        if not acquired:
            raise LockAcquisitionError(
                f"Failed to acquire lock for '{resource_name}' within {timeout_seconds}s"
            )

        try:
            yield dlock
        finally:
            await dlock.release()


# Module-level singleton
lock_manager = DistributedLockManager()
