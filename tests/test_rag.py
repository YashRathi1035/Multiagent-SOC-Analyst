"""Unit and integration tests for the Cybersecurity Knowledge and RAG subsystem."""

from pathlib import Path
import pytest
from rag.embeddings import EmbeddingManager
from rag.ingest import (
    chunk_cybersecurity_knowledge,
    build_vector_store,
    load_knowledge_documents,
    save_vector_store,
    load_vector_store,
)
from rag.retrieve import RAGRetriever, RetrievedChunk


def test_load_knowledge_documents():
    mitre_data, playbook_data = load_knowledge_documents()
    assert len(mitre_data) >= 5
    assert len(playbook_data) >= 3

    # Check key MITRE techniques exist
    tids = {item["technique_id"] for item in mitre_data}
    assert "T1110" in tids
    assert "T1110.001" in tids
    assert "T1078" in tids


def test_chunking_preserves_metadata():
    mitre_data, playbook_data = load_knowledge_documents()
    chunks = chunk_cybersecurity_knowledge(mitre_data, playbook_data)

    assert len(chunks) > len(mitre_data)  # Multi-chunk per technique

    # Verify metadata on sample chunk
    t1110_chunks = [c for c in chunks if c.technique_id == "T1110.001"]
    assert len(t1110_chunks) >= 2
    sample = t1110_chunks[0]
    assert sample.url is not None
    assert "Credential Access" in sample.tactics
    assert "T1110.001" in sample.text


def test_embedding_manager():
    # Test deterministic mock embedding
    mock_mgr = EmbeddingManager(force_mock=True)
    assert mock_mgr.dimension == 384
    q_vec = mock_mgr.embed_query("test query")
    assert q_vec.shape == (1, 384)

    # Test real embedding manager with cached model
    real_mgr = EmbeddingManager(force_mock=False)
    assert real_mgr.dimension == 384
    docs_emb = real_mgr.embed_documents(["SSH password guessing", "Valid accounts"])
    assert docs_emb.shape == (2, 384)


def test_vector_store_persistence(tmp_path: Path):
    emb_mgr = EmbeddingManager(force_mock=True)
    mitre_data, playbook_data = load_knowledge_documents()
    chunks = chunk_cybersecurity_knowledge(mitre_data, playbook_data)

    index, indexed_chunks = build_vector_store(chunks, emb_mgr)
    assert index.ntotal == len(chunks)

    save_vector_store(index, indexed_chunks, cache_dir=tmp_path)
    loaded = load_vector_store(cache_dir=tmp_path)
    assert loaded is not None
    loaded_idx, loaded_chunks = loaded
    assert loaded_idx.ntotal == len(chunks)
    assert len(loaded_chunks) == len(chunks)


def test_rag_retrieval_relevance_brute_force():
    # Use real embedding manager for semantic test
    retriever = RAGRetriever(embedding_manager=EmbeddingManager(force_mock=False))
    query = "Repeated failed SSH password attempts from external IP guessing root password"
    results = retriever.retrieve(query, top_k=3)

    assert len(results) > 0
    top_result = results[0]
    assert isinstance(top_result, RetrievedChunk)
    # The top result should be Brute Force (T1110 or T1110.001) or the Brute-Force Playbook
    matched_ids = [r.technique_id or r.chunk_id for r in results]
    assert any("T1110" in mid or "IR-PLAYBOOK-001" in mid for mid in matched_ids)
    assert top_result.similarity_score > 0.40
    assert "https://" in top_result.citation


def test_rag_retrieval_relevance_compromise():
    retriever = RAGRetriever(embedding_manager=EmbeddingManager(force_mock=False))
    query = "Multiple authentication failures followed by accepted login session potential valid account abuse"
    results = retriever.retrieve(query, top_k=3)

    assert len(results) > 0
    matched_ids = [r.technique_id or r.chunk_id for r in results]
    # Should match T1078 (Valid Accounts) or IR-PLAYBOOK-002
    assert any("T1078" in mid or "IR-PLAYBOOK-002" in mid or "T1110" in mid for mid in matched_ids)


def test_format_context_for_prompt():
    retriever = RAGRetriever(embedding_manager=EmbeddingManager(force_mock=False))
    results = retriever.retrieve("User enumeration reconnaissance", top_k=2)
    prompt_context = retriever.format_context_for_prompt(results)

    assert "### Knowledge Excerpt" in prompt_context
    assert "Citation:" in prompt_context
