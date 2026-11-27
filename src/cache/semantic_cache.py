"""
src/cache/semantic_cache.py
===========================
Redis-Backed Semantic Vector Cache.
Computes dense vector embeddings for incoming alert signatures and searches
for semantically equivalent past analyses using Cosine Similarity.

If Cosine Similarity >= settings.semantic_cache_similarity_threshold (0.94),
the verified triage/remediation analysis is returned in < 5ms, bypassing
expensive LLM and RAG calls.
"""

from datetime import datetime, timezone
import hashlib
import json
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
import uuid
import numpy as np

from src.logger import get_logger
from src.cache.redis_client import RedisClientManager, redis_manager
from src.config import settings

logger = get_logger(__name__)

CACHE_KEY_PREFIX = "semcache:entry:"
CACHE_INDEX_KEY = "semcache:index"


def default_local_embedder(text: str, dim: int = 384) -> List[float]:
    """
    Lightweight, deterministic L2-normalized feature-hashing embedder
    combining word tokens and character trigrams.
    Allows sub-millisecond offline semantic similarity without external API keys.
    Can be swapped for OpenAI / FastEmbed BGE embeddings in production.
    """
    vec = np.zeros(dim, dtype=np.float32)
    normalized = text.lower().strip()
    # Normalize standalone ephemeral numbers (e.g. ports, PIDs) while preserving IP addresses
    normalized = re.sub(r"(?<![.\d])\b\d+\b(?![.\d])", "<num>", normalized)
    words = re.findall(r"[a-z0-9_.:/<>-]+", normalized)

    # Combine word tokens with dense character trigrams for robust sub-word similarity
    features: List[Tuple[str, float]] = [(f"w:{w}", 1.0) for w in words]
    for i in range(max(0, len(normalized) - 2)):
        trigram = normalized[i : i + 3]
        features.append((f"c:{trigram}", 2.0))

    for feat, weight in features:
        digest = hashlib.blake2b(feat.encode("utf-8"), digest_size=8).digest()
        idx = int.from_bytes(digest[:4], "little") % dim
        sign = 1.0 if (digest[4] & 1) == 0 else -1.0
        vec[idx] += sign * weight

    norm = float(np.linalg.norm(vec))
    if norm > 0:
        vec = vec / norm

    return vec.tolist()


def cosine_similarity(vec_a: List[float], vec_b: List[float]) -> float:
    """Computes cosine similarity between two dense vectors."""
    a = np.asarray(vec_a, dtype=np.float32)
    b = np.asarray(vec_b, dtype=np.float32)
    denom = float(np.linalg.norm(a) * np.linalg.norm(b))
    if denom == 0.0:
        return 0.0
    return float(np.dot(a, b) / denom)


class SemanticCache:
    """
    Semantic Vector Cache stored in Redis.
    """

    def __init__(
        self,
        similarity_threshold: Optional[float] = None,
        ttl_seconds: int = 3600,
        embed_fn: Optional[Callable[[str], List[float]]] = None,
        manager: Optional[RedisClientManager] = None,
    ):
        self.similarity_threshold = (
            similarity_threshold
            if similarity_threshold is not None
            else settings.semantic_cache_similarity_threshold
        )
        self.ttl_seconds = ttl_seconds
        self.embed_fn = embed_fn or default_local_embedder
        self.manager = manager or redis_manager

    async def set(
        self,
        alert_signature: str,
        analysis_result: Dict[str, Any],
        ttl_seconds: Optional[int] = None,
    ) -> str:
        """
        Embeds an alert signature and stores its verified analysis in Redis.
        """
        client = await self.manager.get_client()
        entry_id = uuid.uuid4().hex[:12]
        key = f"{CACHE_KEY_PREFIX}{entry_id}"
        ttl = ttl_seconds if ttl_seconds is not None else self.ttl_seconds

        embedding = self.embed_fn(alert_signature)
        record = {
            "id": entry_id,
            "signature": alert_signature,
            "embedding": embedding,
            "analysis": analysis_result,
            "cached_at": datetime.now(timezone.utc).isoformat(),
        }

        async with client.pipeline(transaction=True) as pipe:
            pipe.set(key, json.dumps(record), ex=ttl)
            pipe.sadd(CACHE_INDEX_KEY, key)
            await pipe.execute()

        logger.info("semantic_cache_stored", entry_id=entry_id, ttl=ttl)
        return entry_id

    async def get(self, alert_signature: str) -> Optional[Tuple[Dict[str, Any], float]]:
        """
        Searches Redis for a semantically similar cached alert.
        Returns `(analysis_result, similarity_score)` if similarity >= threshold, else None.
        """
        start_ns = time.perf_counter_ns()
        client = await self.manager.get_client()

        keys = await client.smembers(CACHE_INDEX_KEY)
        if not keys:
            return None

        query_vec = self.embed_fn(alert_signature)
        raw_records = await client.mget(list(keys))

        best_score = -1.0
        best_analysis: Optional[Dict[str, Any]] = None
        expired_keys: List[str] = []

        for key, raw in zip(keys, raw_records):
            if raw is None:
                expired_keys.append(key)
                continue

            record = json.loads(raw)
            score = cosine_similarity(query_vec, record["embedding"])
            if score > best_score:
                best_score = score
                best_analysis = record["analysis"]

        # Prune expired keys from index lazily
        if expired_keys:
            await client.srem(CACHE_INDEX_KEY, *expired_keys)

        latency_ms = round((time.perf_counter_ns() - start_ns) / 1_000_000, 3)

        if best_analysis is not None and best_score >= self.similarity_threshold:
            logger.info(
                "semantic_cache_hit",
                similarity=round(best_score, 4),
                threshold=self.similarity_threshold,
                latency_ms=latency_ms,
            )
            return best_analysis, best_score

        logger.info(
            "semantic_cache_miss",
            best_similarity=round(best_score, 4) if best_score >= 0 else 0.0,
            threshold=self.similarity_threshold,
            latency_ms=latency_ms,
        )
        return None

    async def clear(self) -> None:
        """Clears all semantic cache entries from Redis."""
        client = await self.manager.get_client()
        keys = await client.smembers(CACHE_INDEX_KEY)
        if keys:
            await client.delete(*keys)
        await client.delete(CACHE_INDEX_KEY)


# Module-level singleton
semantic_cache = SemanticCache()
