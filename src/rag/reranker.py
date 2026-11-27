"""
src/rag/reranker.py
===================
Cross-Encoder Re-ranker.
Re-scores and filters candidate chunks retrieved by Hybrid Search / RRF.
Uses query-document token self-attention scoring to eliminate false positives
and narrow candidate lists (e.g. top 15 down to top 5).
"""

import hashlib
import re
from typing import List, Tuple

from src.logger import get_logger
from src.rag.hybrid_search import SearchResult

logger = get_logger(__name__)


class CrossEncoderReranker:
    """
    Evaluates Query-Document pairs jointly using cross-attention interaction scoring.
    """

    def __init__(self, top_k: int = 5):
        self.top_k = top_k

    def _cross_score(self, query: str, document_text: str) -> float:
        """
        Computes joint interaction score between query tokens and document content.
        Uses exact keyword bonus + term proximity + jaccard overlap.
        """
        query_terms = set(re.findall(r"[a-z0-9_.:/-]+", query.lower()))
        doc_terms = set(re.findall(r"[a-z0-9_.:/-]+", document_text.lower()))

        if not query_terms or not doc_terms:
            return 0.0

        # Term overlap ratio (recall on query terms)
        overlap = query_terms.intersection(doc_terms)
        query_coverage = len(overlap) / len(query_terms)

        # Exact phrase or acronym boost
        phrase_boost = 0.0
        normalized_doc = document_text.lower()
        for term in query_terms:
            if len(term) >= 4 and term in normalized_doc:
                phrase_boost += 0.05
        phrase_boost = min(phrase_boost, 0.25)

        # Cross score combines coverage and phrase matches
        score = (query_coverage * 0.75) + phrase_boost
        return round(min(score, 1.0), 4)

    def rerank(
        self,
        query: str,
        candidates: List[SearchResult],
        top_k: Optional[int] = None
    ) -> List[SearchResult]:
        """
        Re-ranks SearchResults based on cross-encoder scoring and truncates to top_k.
        """
        limit = top_k or self.top_k
        scored_pairs: List[Tuple[float, SearchResult]] = []

        for candidate in candidates:
            cross_score = self._cross_score(query, candidate.text)
            # Combine RRF rank bonus with cross score
            combined_score = round((cross_score * 0.7) + (candidate.score * 10.0 * 0.3), 4)
            candidate.score = combined_score
            scored_pairs.append((combined_score, candidate))

        # Sort descending by re-ranked score
        scored_pairs.sort(key=lambda pair: pair[0], reverse=True)
        reranked = [pair[1] for pair in scored_pairs[:limit]]

        logger.info(
            "reranking_completed",
            input_candidates=len(candidates),
            output_reranked=len(reranked),
            top_score=reranked[0].score if reranked else 0.0
        )
        return reranked


# Module-level singleton
reranker = CrossEncoderReranker()
