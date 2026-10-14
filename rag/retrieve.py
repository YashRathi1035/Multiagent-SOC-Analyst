"""Semantic retrieval engine over FAISS cybersecurity knowledge vector store.

Performs similarity search, metadata filtering, score thresholding,
and generates grounded citations for LLM prompt context construction.
"""

import logging
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from rag.embeddings import EmbeddingManager
from rag.ingest import KnowledgeChunk, get_or_create_vector_store

logger = logging.getLogger(__name__)


class RetrievedChunk(BaseModel):
    """A search result retrieved from the cybersecurity knowledge store."""
    chunk_id: str
    title: str
    source_type: str
    technique_id: Optional[str] = None
    tactics: List[str] = Field(default_factory=list)
    text: str
    url: Optional[str] = None
    similarity_score: float
    citation: str


class RAGRetriever:
    """Retrieval service over FAISS-indexed MITRE ATT&CK and IR guidance."""

    def __init__(
        self,
        embedding_manager: Optional[EmbeddingManager] = None,
        force_rebuild: bool = False,
    ):
        self.embedding_manager = embedding_manager or EmbeddingManager()
        self.index, self.chunks = get_or_create_vector_store(
            embedding_manager=self.embedding_manager, force_rebuild=force_rebuild
        )
        logger.info(
            "RAGRetriever initialized with %d indexed chunks (FAISS total: %d)",
            len(self.chunks),
            self.index.ntotal,
        )

    def retrieve(
        self,
        query: str,
        top_k: int = 4,
        score_threshold: float = 0.20,
        source_filter: Optional[str] = None,
    ) -> List[RetrievedChunk]:
        """Search knowledge base for chunks semantically similar to the query.

        Args:
            query: Cybersecurity context, alert description, or search string
            top_k: Maximum number of chunks to return
            score_threshold: Minimum cosine similarity score (0.0 to 1.0)
            source_filter: Optional filter ('mitre_attack' or 'incident_playbook')

        Returns:
            Ranked list of RetrievedChunk instances
        """
        if not query.strip() or self.index.ntotal == 0:
            return []

        # Generate query vector
        q_vec = self.embedding_manager.embed_query(query)

        # Search FAISS index
        search_k = min(top_k * 3, self.index.ntotal)
        scores, indices = self.index.search(q_vec, search_k)

        results: List[RetrievedChunk] = []

        for score, idx in zip(scores[0], indices[0]):
            if idx < 0 or idx >= len(self.chunks):
                continue

            sim_score = float(score)
            if sim_score < score_threshold:
                continue

            chunk = self.chunks[idx]

            # Apply metadata source filter if specified
            if source_filter and chunk.source_type != source_filter:
                continue

            # Build grounded citation
            if chunk.source_type == "mitre_attack":
                tech_tag = f"MITRE ATT&CK {chunk.technique_id} - " if chunk.technique_id else ""
                tactics_tag = f" | Tactics: {', '.join(chunk.tactics)}" if chunk.tactics else ""
                citation = f"[{tech_tag}{chunk.title}{tactics_tag} | Source: {chunk.url or 'MITRE ATT&CK'}]"
            else:
                citation = f"[Playbook: {chunk.title} | Source: {chunk.url or 'NIST SP 800-61'}]"

            results.append(
                RetrievedChunk(
                    chunk_id=chunk.chunk_id,
                    title=chunk.title,
                    source_type=chunk.source_type,
                    technique_id=chunk.technique_id,
                    tactics=chunk.tactics,
                    text=chunk.text,
                    url=chunk.url,
                    similarity_score=round(sim_score, 4),
                    citation=citation,
                )
            )

            if len(results) >= top_k:
                break

        return results

    def format_context_for_prompt(self, chunks: List[RetrievedChunk]) -> str:
        """Format retrieved chunks into structured context for LLM prompt injection."""
        if not chunks:
            return "No relevant cybersecurity knowledge or MITRE ATT&CK documents retrieved."

        formatted_lines = []
        for i, c in enumerate(chunks, start=1):
            formatted_lines.append(
                f"### Knowledge Excerpt {i} (Relevance Score: {c.similarity_score:.2f})\n"
                f"Citation: {c.citation}\n"
                f"{c.text}\n"
            )

        return "\n".join(formatted_lines)
