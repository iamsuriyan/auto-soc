"""
src/rag/qdrant_client.py
========================
Asynchronous Qdrant Vector Database Client.
Manages connection, collection initialization, and dual-vector indexing:
  - 'dense': Cosine distance semantic vector (384-dim)
  - 'sparse': Sparse BM25 keyword index for exact match on CVEs/hashes
"""

from typing import Any, Dict, List, Optional
from qdrant_client import AsyncQdrantClient
from qdrant_client.http import models as qmodels

from src.logger import get_logger
from src.config import settings

logger = get_logger(__name__)

COLLECTION_NAME = settings.qdrant_collection_name
DENSE_VECTOR_SIZE = 384


class QdrantManager:
    """
    Manages the async Qdrant client and dual-vector collection lifecycle.
    """

    def __init__(self, host: Optional[str] = None, port: Optional[int] = None):
        self.host = host or settings.qdrant_host
        self.port = port or settings.qdrant_port
        self.url = f"http://{self.host}:{self.port}"
        self._client: Optional[AsyncQdrantClient] = None

    async def get_client(self) -> AsyncQdrantClient:
        """Returns initialized AsyncQdrantClient."""
        if self._client is None:
            self._client = AsyncQdrantClient(url=self.url, timeout=10.0, check_compatibility=False)
            logger.info("qdrant_client_initialized", url=self.url)
        return self._client

    async def ensure_collection(self, collection_name: Optional[str] = None) -> bool:
        """
        Idempotently creates the hybrid collection with named 'dense' and 'sparse' vectors.
        """
        client = await self.get_client()
        col_name = collection_name or COLLECTION_NAME

        existing = await client.get_collections()
        existing_names = [col.name for col in existing.collections]

        if col_name in existing_names:
            logger.info("qdrant_collection_already_exists", collection=col_name)
            return True

        # Configure Dual-Vector Spaces: Dense + Sparse BM25
        await client.create_collection(
            collection_name=col_name,
            vectors_config={
                "dense": qmodels.VectorParams(
                    size=DENSE_VECTOR_SIZE,
                    distance=qmodels.Distance.COSINE
                )
            },
            sparse_vectors_config={
                "sparse": qmodels.SparseVectorParams(
                    index=qmodels.SparseIndexParams(on_disk=False)
                )
            }
        )

        logger.info(
            "qdrant_hybrid_collection_created",
            collection=col_name,
            dense_dim=DENSE_VECTOR_SIZE
        )
        return True

    async def upsert_points(
        self,
        points: List[qmodels.PointStruct],
        collection_name: Optional[str] = None
    ) -> qmodels.UpdateResult:
        """Upserts a batch of hybrid points with payloads into Qdrant."""
        client = await self.get_client()
        col_name = collection_name or COLLECTION_NAME
        result = await client.upsert(collection_name=col_name, points=points)
        logger.info("qdrant_points_upserted", collection=col_name, count=len(points))
        return result

    async def count_points(self, collection_name: Optional[str] = None) -> int:
        """Returns total point count in collection."""
        client = await self.get_client()
        col_name = collection_name or COLLECTION_NAME
        count_res = await client.count(collection_name=col_name)
        return count_res.count

    async def close(self) -> None:
        """Closes async client connections."""
        if self._client is not None:
            await self._client.close()
            self._client = None
            logger.info("qdrant_client_closed")


# Module-level singleton
qdrant_manager = QdrantManager()
