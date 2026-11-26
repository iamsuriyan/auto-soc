"""
tests/integration/test_redis_services.py
=========================================
Integration tests for Phase 3.2 Redis High-Performance Services:
  1. Async Redis client connectivity & ping.
  2. Semantic Cache HIT when incoming alert is >= 0.94 similar.
  3. Semantic Cache MISS when incoming alert is a different attack vector.
  4. Redlock Distributed Lock mutual exclusion, timeout contention, and release.
  5. Ownership safety: Worker B cannot unlock Worker A's lock.
"""

import asyncio
import pytest

from src.cache.distributed_lock import (
    DistributedLock,
    DistributedLockManager,
    LockAcquisitionError,
)
from src.cache.redis_client import RedisClientManager
from src.cache.semantic_cache import SemanticCache


@pytest.fixture
async def redis_mgr():
    mgr = RedisClientManager()
    assert await mgr.ping() is True
    yield mgr
    await mgr.close()


@pytest.mark.asyncio
async def test_semantic_cache_hit_and_miss(redis_mgr: RedisClientManager):
    """
    Verifies:
      - Storing an SSH brute force alert analysis
      - Similar alert ('admin' instead of 'root') achieves >= 0.94 similarity -> CACHE HIT
      - Unrelated SQL Injection alert -> CACHE MISS
    """
    cache = SemanticCache(similarity_threshold=0.94, manager=redis_mgr)
    await cache.clear()

    original_alert = (
        "SSH_BRUTE_FORCE: Failed password for invalid user root "
        "from 192.168.1.50 port 44210 ssh2 on host prod-gateway-01"
    )
    verified_analysis = {
        "triage_verdict": "CRITICAL",
        "mitre_tactic": "TA0006: Credential Access (T1110 Brute Force)",
        "remediation": "Block source IP 192.168.1.50 via iptables",
    }

    await cache.set(original_alert, verified_analysis)

    # 1. Semantically equivalent alert (different username & port, same attack pattern)
    similar_alert = (
        "SSH_BRUTE_FORCE: Failed password for invalid user admin "
        "from 192.168.1.50 port 44212 ssh2 on host prod-gateway-01"
    )
    hit = await cache.get(similar_alert)
    assert hit is not None, "Expected semantic cache HIT for nearly identical SSH brute force"
    cached_result, score = hit
    assert score >= 0.94
    assert cached_result["triage_verdict"] == "CRITICAL"

    # 2. Completely different attack type -> must MISS
    unrelated_alert = (
        "SQL_INJECTION: GET /api/v1/users?id=1' OR '1'='1' UNION SELECT password FROM admin_users"
    )
    miss = await cache.get(unrelated_alert)
    assert miss is None, "Expected semantic cache MISS for unrelated SQL injection alert"

    await cache.clear()


@pytest.mark.asyncio
async def test_distributed_lock_mutual_exclusion(redis_mgr: RedisClientManager):
    """
    Verifies that two concurrent workers cannot hold the same asset lock simultaneously.
    """
    lock_mgr = DistributedLockManager(manager=redis_mgr)
    resource = "asset:10.0.0.50"

    # Worker 1 acquires the lock
    async with lock_mgr.lock(resource, ttl_ms=5000, timeout_seconds=1.0):
        # While Worker 1 holds the lock, Worker 2 tries to acquire with short timeout -> must fail
        with pytest.raises(LockAcquisitionError):
            async with lock_mgr.lock(resource, ttl_ms=5000, timeout_seconds=0.3):
                pass

    # After Worker 1 exits context manager, lock is released -> Worker 2 succeeds immediately!
    async with lock_mgr.lock(resource, ttl_ms=5000, timeout_seconds=1.0) as worker2_lock:
        assert worker2_lock._acquired is True


@pytest.mark.asyncio
async def test_distributed_lock_ownership_safety(redis_mgr: RedisClientManager):
    """
    Verifies Worker B cannot delete Worker A's active lock (token mismatch protection).
    """
    client = await redis_mgr.get_client()
    resource = "asset:10.0.0.99"

    worker_a_lock = DistributedLock(client, resource, ttl_ms=5000)
    worker_b_lock = DistributedLock(client, resource, ttl_ms=5000)

    assert await worker_a_lock.acquire(timeout_seconds=1.0) is True

    # Simulate Worker B somehow trying to release without owning it
    worker_b_lock._acquired = True  # pretend B thinks it owns it
    released_by_b = await worker_b_lock.release()
    assert released_by_b is False, "Worker B must NOT be able to release Worker A's lock!"

    # Worker A can cleanly release its own lock
    released_by_a = await worker_a_lock.release()
    assert released_by_a is True
