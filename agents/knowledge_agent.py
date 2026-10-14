"""Knowledge Agent (Agent 2) — LangGraph node.

Responsibilities:
- Receive alert description, rule name, and MITRE candidates from state.
- Build a targeted semantic query combining all available context signals.
- Retrieve top-k relevant MITRE ATT&CK and IR playbook chunks via FAISS.
- Format the retrieved context for LLM prompt injection.
- Propagate knowledge_context and retrieved_knowledge to state.
"""

import logging
from typing import Any, Dict, List, Optional

from models.schemas import DetectionAlert
from rag.embeddings import EmbeddingManager
from rag.retrieve import RAGRetriever
from graph.state import SOCState

logger = logging.getLogger(__name__)

NODE_NAME = "knowledge_agent"


class KnowledgeAgent:
    """Specialist agent wrapping the RAG retriever for cybersecurity knowledge lookup."""

    def __init__(self, retriever: Optional[RAGRetriever] = None):
        self.retriever = retriever

    def _get_retriever(self) -> RAGRetriever:
        """Lazy-initialize retriever to avoid slow startup in tests."""
        if self.retriever is None:
            self.retriever = RAGRetriever()
        return self.retriever

    def retrieve_for_alert(
        self,
        alert: DetectionAlert,
        extra_context: Optional[str] = None,
        top_k: int = 4,
        score_threshold: float = 0.20,
    ) -> Dict[str, Any]:
        """Build a context-rich semantic query and retrieve relevant knowledge.

        Args:
            alert: The detection alert driving the investigation.
            extra_context: Additional behavioral context from the log agent.
            top_k: Max chunks to retrieve.
            score_threshold: Minimum cosine similarity.

        Returns:
            Dict with 'retrieved_knowledge' (list of dicts) and 'knowledge_context' (str).
        """
        retriever = self._get_retriever()

        # Compose rich semantic query from all available signals
        query_parts = [
            alert.rule_name,
            alert.description,
            " ".join(alert.mitre_candidates),
        ]
        if alert.affected_user and alert.affected_user not in ("multiple_users", "multiple_accounts"):
            query_parts.append(f"account targeting {alert.affected_user}")
        if extra_context:
            query_parts.append(extra_context[:300])

        query = " ".join(filter(None, query_parts))
        logger.info("[%s] RAG query: %s", NODE_NAME, query[:120])

        # Retrieve relevant chunks
        chunks = retriever.retrieve(query, top_k=top_k, score_threshold=score_threshold)
        context_str = retriever.format_context_for_prompt(chunks)

        retrieved_dicts = [c.model_dump() for c in chunks]

        logger.info(
            "[%s] Retrieved %d knowledge chunks (top score: %.3f)",
            NODE_NAME,
            len(chunks),
            chunks[0].similarity_score if chunks else 0.0,
        )
        return {
            "retrieved_knowledge": retrieved_dicts,
            "knowledge_context": context_str,
        }


def knowledge_agent_node(state: SOCState) -> SOCState:
    """LangGraph node: Knowledge / RAG Agent.

    Reads: selected_alert, log_analysis_findings
    Writes: retrieved_knowledge, knowledge_context, agent_trace
    """
    trace = list(state.get("agent_trace", []))
    errors = list(state.get("errors", []))
    trace.append(f"[{NODE_NAME}] started")

    selected_alert: Optional[DetectionAlert] = state.get("selected_alert")
    findings: Dict[str, Any] = state.get("log_analysis_findings", {})
    extra_ctx = findings.get("narrative", "")

    if not selected_alert:
        msg = f"[{NODE_NAME}] No selected_alert — skipping RAG retrieval."
        logger.warning(msg)
        errors.append(msg)
        trace.append(f"[{NODE_NAME}] skipped (no alert)")
        return {
            **state,
            "retrieved_knowledge": [],
            "knowledge_context": "No alert selected; RAG retrieval skipped.",
            "agent_trace": trace,
            "errors": errors,
            "current_node": NODE_NAME,
        }

    try:
        agent = KnowledgeAgent()
        result = agent.retrieve_for_alert(selected_alert, extra_context=extra_ctx)
        chunk_count = len(result["retrieved_knowledge"])
        trace.append(f"[{NODE_NAME}] completed — {chunk_count} knowledge chunks retrieved")
        return {
            **state,
            "retrieved_knowledge": result["retrieved_knowledge"],
            "knowledge_context": result["knowledge_context"],
            "agent_trace": trace,
            "errors": errors,
            "current_node": NODE_NAME,
        }
    except Exception as exc:
        msg = f"[{NODE_NAME}] RAG retrieval failed: {exc}"
        logger.exception(msg)
        errors.append(msg)
        trace.append(f"[{NODE_NAME}] FAILED — using empty knowledge context")
        return {
            **state,
            "retrieved_knowledge": [],
            "knowledge_context": "RAG retrieval failed; no external cybersecurity guidance available.",
            "agent_trace": trace,
            "errors": errors,
            "current_node": NODE_NAME,
        }
