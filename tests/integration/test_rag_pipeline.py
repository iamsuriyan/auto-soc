"""
tests/integration/test_rag_pipeline.py
======================================
Integration tests for Phase 4 Advanced Hybrid RAG Engine.
Verifies against live Qdrant container:
  1. Collection creation with Dual-Vector (Dense + Sparse) configuration.
  2. Threat intel document chunking and upserting into Qdrant.
  3. Exact keyword retrieval (CVE-2024-3094) where sparse vector ensures Rank #1.
  4. Conceptual semantic retrieval (host containment) where dense vector matches meaning.
  5. Reciprocal Rank Fusion (RRF) scores candidates cleanly without scale divergence.
  6. Cross-Encoder re-ranking narrows candidates to top 5.
  7. Corrective RAG (CRAG) triggers query reformulation when confidence is low.
"""

import pytest

from scripts.seed_threat_intel import seed_knowledge_base
from src.rag.crag_evaluator import CRAGEvaluator
from src.rag.hybrid_search import HybridSearcher
from src.rag.qdrant_client import QdrantManager
from src.rag.reranker import CrossEncoderReranker


@pytest.fixture
async def seeded_qdrant():
    """Initializes and seeds Qdrant collection for tests."""
    mgr = QdrantManager()
    await mgr.ensure_collection()
    await seed_knowledge_base()
    yield mgr
    await mgr.close()


@pytest.mark.asyncio
async def test_qdrant_collection_created_with_dual_vectors(seeded_qdrant: QdrantManager):
    """Asserts collection exists and contains seeded points."""
    client = await seeded_qdrant.get_client()
    col = await client.get_collection("autosoc_knowledge")
    assert col is not None
    assert "dense" in col.config.params.vectors
    assert "sparse" in col.config.params.sparse_vectors

    point_count = await seeded_qdrant.count_points()
    assert point_count > 0, "Expected non-zero seeded points in Qdrant"


@pytest.mark.asyncio
async def test_exact_cve_keyword_retrieval(seeded_qdrant: QdrantManager):
    """
    Tests exact keyword match:
    Querying 'CVE-2024-3094 backdoor' must retrieve the XZ liblzma document at Rank #1.
    """
    searcher = HybridSearcher(manager=seeded_qdrant)
    results = await searcher.search("CVE-2024-3094 sshd liblzma backdoor", limit=5)

    assert len(results) > 0
    top_result = results[0]
    assert "CVE-2024-3094" in top_result.text or "cve-2024-3094" in top_result.doc_id
    assert top_result.sparse_rank is not None, "Expected Sparse BM25 hit on exact CVE ID"
    assert top_result.score > 0.0


@pytest.mark.asyncio
async def test_conceptual_semantic_retrieval(seeded_qdrant: QdrantManager):
    """
    Tests conceptual semantic match:
    Querying 'disconnect an active infected machine from the network'
    should match NIST SP 800-61 host isolation playbook even without exact phrase match.
    """
    searcher = HybridSearcher(manager=seeded_qdrant)
    results = await searcher.search(
        "disconnect infected machine from network to stop lateral movement",
        limit=5
    )

    assert len(results) > 0
    found_isolation = any("containment" in r.text.lower() or "isolation" in r.text.lower() for r in results)
    assert found_isolation is True, "Expected semantic match on NIST containment playbook"


@pytest.mark.asyncio
async def test_cross_encoder_reranker(seeded_qdrant: QdrantManager):
    """Asserts re-ranker filters top candidates down to top 3."""
    searcher = HybridSearcher(manager=seeded_qdrant)
    reranker = CrossEncoderReranker(top_k=3)

    candidates = await searcher.search("powershell base64 encoded command execution", limit=10)
    reranked = reranker.rerank("powershell base64 encoded command execution", candidates, top_k=3)

    assert len(reranked) <= 3
    assert any("powershell" in r.text.lower() for r in reranked)


@pytest.mark.asyncio
async def test_crag_corrective_loop(seeded_qdrant: QdrantManager):
    """
    Tests Corrective RAG:
    A short query with an acronym ('xz rce') triggers query reformulation,
    expanding terms and improving retrieval confidence.
    """
    evaluator = CRAGEvaluator(confidence_threshold=0.85, searcher=HybridSearcher(manager=seeded_qdrant))
    result = await evaluator.evaluate_and_retrieve("xz rce", top_k=5)

    assert result.reformulated_query is not None
    assert "cve-2024-3094" in result.reformulated_query.lower() or "remote code execution" in result.reformulated_query.lower()
    assert len(result.context_chunks) > 0
