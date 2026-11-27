"""
src/rag/hybrid_search.py
========================
Hybrid Search Engine combining Dense Vector Search and Sparse BM25 Keyword Search
using Reciprocal Rank Fusion (RRF).

RRF Formula:
    RRF_Score(d) = sum_{m in {dense, sparse}} ( 1.0 / (k + rank_m(d)) )
    Default k = 60 (standard Cormack et al. constant)
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from qdrant_client.http import models as qmodels

from src.logger import get_logger
from src.config import settings
from src.rag.ingestion import compute_dense_embedding, compute_sparse_bm25_vector
from src.rag.qdrant_client import QdrantManager, qdrant_manager

logger = get_logger(__name__)


@dataclass
class SearchResult:
    """A retrieved knowledge chunk with fused ranking metadata."""
    chunk_id: str
    doc_id: str
    title: str
    header_path: str
    text: str
    score: float                        # Final fused RRF score
    dense_rank: Optional[int] = None
    sparse_rank: Optional[int] = None
    metadata: Dict[str, Any] = None


class HybridSearcher:
    """
    Executes parallel Dense and Sparse searches in Qdrant and merges them with RRF.
    """

    def __init__(
        self,
        manager: Optional[QdrantManager] = None,
        rrf_k: int = 60,
        top_k: int = 15
    ):
        self.manager = manager or qdrant_manager
        self.rrf_k = rrf_k
        self.top_k = top_k

    async def search(
        self,
        query: str,
        limit: Optional[int] = None,
        collection_name: Optional[str] = None
    ) -> List[SearchResult]:
        """
        Executes hybrid search across dense and sparse vectors and applies RRF.
        """
        client = await self.manager.get_client()
        col = collection_name or settings.qdrant_collection_name
        final_limit = limit or self.top_k

        # 1. Compute query embeddings
        dense_query = compute_dense_embedding(query)
        sparse_query = compute_sparse_bm25_vector(query)

        # 2. Parallel search: Top-25 Dense + Top-25 Sparse
        dense_res = await client.query_points(
            collection_name=col,
            query=dense_query,
            using="dense",
            limit=25,
            with_payload=True
        )
        dense_results = dense_res.points

        sparse_res = await client.query_points(
            collection_name=col,
            query=sparse_query,
            using="sparse",
            limit=25,
            with_payload=True
        )
        sparse_results = sparse_res.points

        # 3. Apply Reciprocal Rank Fusion (RRF)
        # Maps chunk_id -> {score, dense_rank, sparse_rank, point}
        fused_candidates: Dict[str, Dict[str, Any]] = {}

        # Process Dense Ranks (1-indexed)
        for rank, hit in enumerate(dense_results, start=1):
            chunk_id = hit.payload.get("chunk_id", str(hit.id))
            rrf_contrib = 1.0 / (self.rrf_k + rank)
            if chunk_id not in fused_candidates:
                fused_candidates[chunk_id] = {
                    "score": rrf_contrib,
                    "dense_rank": rank,
                    "sparse_rank": None,
                    "hit": hit
                }
            else:
                fused_candidates[chunk_id]["score"] += rrf_contrib
                fused_candidates[chunk_id]["dense_rank"] = rank

        # Process Sparse Ranks (1-indexed)
        for rank, hit in enumerate(sparse_results, start=1):
            chunk_id = hit.payload.get("chunk_id", str(hit.id))
            rrf_contrib = 1.0 / (self.rrf_k + rank)
            if chunk_id not in fused_candidates:
                fused_candidates[chunk_id] = {
                    "score": rrf_contrib,
                    "dense_rank": None,
                    "sparse_rank": rank,
                    "hit": hit
                }
            else:
                fused_candidates[chunk_id]["score"] += rrf_contrib
                fused_candidates[chunk_id]["sparse_rank"] = rank

        # 4. Sort by fused RRF score descending
        sorted_candidates = sorted(
            fused_candidates.values(),
            key=lambda item: item["score"],
            reverse=True
        )

        # 5. Build structured SearchResult objects
        results: List[SearchResult] = []
        for item in sorted_candidates[:final_limit]:
            hit = item["hit"]
            p = hit.payload or {}
            results.append(SearchResult(
                chunk_id=p.get("chunk_id", str(hit.id)),
                doc_id=p.get("doc_id", "unknown"),
                title=p.get("title", ""),
                header_path=p.get("header_path", ""),
                text=p.get("text", ""),
                score=round(item["score"], 5),
                dense_rank=item["dense_rank"],
                sparse_rank=item["sparse_rank"],
                metadata=p
            ))

        logger.info(
            "hybrid_search_completed",
            query=query[:60],
            dense_hits=len(dense_results),
            sparse_hits=len(sparse_results),
            fused_results=len(results),
            top_score=results[0].score if results else 0.0
        )

        return results


# Module-level singleton
hybrid_searcher = HybridSearcher()
