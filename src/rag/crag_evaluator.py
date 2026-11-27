"""
src/rag/crag_evaluator.py
=========================
Corrective RAG (CRAG) Evaluator.
Evaluates the relevance confidence of retrieved threat intelligence.
If top confidence is below threshold (< 0.80), triggers automated query
reformulation (expanding cybersecurity acronyms, stripping noise, expanding aliases)
and executes a corrective secondary search.
"""

from dataclasses import dataclass
import re
from typing import List, Optional, Tuple
from src.logger import get_logger
from src.config import settings
from src.rag.hybrid_search import HybridSearcher, SearchResult, hybrid_searcher
from src.rag.reranker import CrossEncoderReranker, reranker

logger = get_logger(__name__)

# Common Cybersecurity Acronym & Alias Map for CRAG reformulation
CYBER_ACRONYM_MAP = {
    "rce": "Remote Code Execution",
    "dos": "Denial of Service",
    "c2": "Command and Control",
    "mitm": "Man in the Middle",
    "privesc": "Privilege Escalation",
    "powershell": "powershell.exe -ExecutionPolicy Bypass script",
    "ssh": "OpenSSH sshd port 22",
    "log4j": "CVE-2021-44228 Log4Shell JNDI LDAP",
    "xz": "CVE-2024-3094 liblzma backdoor sshd",
    "bruteforce": "T1110 Password Guessing Credential Access",
    "persistence": "T1547.001 Registry Run Keys autostart",
    "registry": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
}


@dataclass
class CRAGResult:
    """Outcome of Corrective RAG evaluation."""
    accepted: bool                      # True if confidence >= threshold
    confidence_score: float
    reformulated_query: Optional[str]
    context_chunks: List[SearchResult]


class CRAGEvaluator:
    """
    Evaluates retrieved context and executes self-correction loops when needed.
    """

    def __init__(
        self,
        confidence_threshold: Optional[float] = None,
        searcher: Optional[HybridSearcher] = None,
        ranker: Optional[CrossEncoderReranker] = None,
    ):
        self.threshold = (
            confidence_threshold
            if confidence_threshold is not None
            else settings.crag_relevance_threshold
        )
        self.searcher = searcher or hybrid_searcher
        self.reranker = ranker or reranker

    def reformulate_query(self, query: str) -> str:
        """
        Rewrites the query: expands acronyms, strips punctuation, and enriches context.
        """
        tokens = re.findall(r"[a-z0-9_.:/-]+", query.lower())
        expanded_terms: List[str] = []

        for token in tokens:
            expanded_terms.append(token)
            if token in CYBER_ACRONYM_MAP:
                expanded_terms.append(CYBER_ACRONYM_MAP[token])

        reformulated = " ".join(expanded_terms).strip()
        logger.info("crag_query_reformulated", original=query, reformulated=reformulated)
        return reformulated

    async def evaluate_and_retrieve(
        self,
        query: str,
        top_k: int = 5
    ) -> CRAGResult:
        """
        Full CRAG Loop:
        1. Hybrid Search + Re-rank with initial query.
        2. Evaluate top confidence score.
        3. If score >= threshold -> ACCEPT immediately.
        4. If score < threshold -> REFORMULATE query, re-search, and re-evaluate.
        """
        # Step 1: Initial Retrieval + Re-ranking
        initial_candidates = await self.searcher.search(query, limit=15)
        reranked = self.reranker.rerank(query, initial_candidates, top_k=top_k)

        top_score = reranked[0].score if reranked else 0.0

        # Step 2: Quality Gate
        if top_score >= self.threshold:
            logger.info("crag_evaluation_accepted", query=query, score=top_score)
            return CRAGResult(
                accepted=True,
                confidence_score=top_score,
                reformulated_query=None,
                context_chunks=reranked
            )

        # Step 3: Corrective Loop Triggered
        logger.warning(
            "crag_confidence_below_threshold_triggering_correction",
            query=query,
            score=top_score,
            threshold=self.threshold
        )

        reformulated = self.reformulate_query(query)
        corrective_candidates = await self.searcher.search(reformulated, limit=15)
        corrective_reranked = self.reranker.rerank(reformulated, corrective_candidates, top_k=top_k)

        new_score = corrective_reranked[0].score if corrective_reranked else 0.0

        logger.info("crag_corrective_search_completed", new_score=new_score)

        return CRAGResult(
            accepted=new_score >= self.threshold,
            confidence_score=new_score,
            reformulated_query=reformulated,
            context_chunks=corrective_reranked
        )


# Module-level singleton
crag_evaluator = CRAGEvaluator()
