"""Knowledge ingestion, semantic chunking, and FAISS vector index builder.

Loads MITRE ATT&CK techniques and incident response playbooks, chunks them
contextually to preserve source metadata, and indexes them into FAISS.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import faiss
import numpy as np
from pydantic import BaseModel, Field

from config.settings import settings
from rag.embeddings import EmbeddingManager

logger = logging.getLogger(__name__)


class KnowledgeChunk(BaseModel):
    """A granular, context-preserved chunk of cybersecurity knowledge."""
    chunk_id: str = Field(..., description="Unique chunk ID (e.g. CHK-T1110.001-DESC)")
    doc_id: str = Field(..., description="Source document or technique identifier")
    title: str = Field(..., description="Human-readable title or technique name")
    source_type: str = Field(..., description="'mitre_attack' or 'incident_playbook'")
    technique_id: Optional[str] = Field(None, description="MITRE ATT&CK technique ID if applicable")
    tactics: List[str] = Field(default_factory=list, description="Associated MITRE tactics or categories")
    text: str = Field(..., description="Chunk content for embedding and retrieval")
    url: Optional[str] = Field(None, description="Stable reference URL")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional context")


def load_knowledge_documents(knowledge_dir: Path = settings.KNOWLEDGE_DIR) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Load raw JSON files from knowledge directory."""
    mitre_file = knowledge_dir / "mitre_attack_subset.json"
    playbook_file = knowledge_dir / "incident_response_playbooks.json"

    mitre_data: List[Dict[str, Any]] = []
    playbook_data: List[Dict[str, Any]] = []

    if mitre_file.exists():
        try:
            with open(mitre_file, "r", encoding="utf-8") as f:
                mitre_data = json.load(f)
        except Exception as e:
            logger.error("Failed to load MITRE ATT&CK knowledge file: %s", e)

    if playbook_file.exists():
        try:
            with open(playbook_file, "r", encoding="utf-8") as f:
                playbook_data = json.load(f)
        except Exception as e:
            logger.error("Failed to load Incident Response playbook file: %s", e)

    return mitre_data, playbook_data


def chunk_cybersecurity_knowledge(
    mitre_data: List[Dict[str, Any]], playbook_data: List[Dict[str, Any]]
) -> List[KnowledgeChunk]:
    """Contextually chunk MITRE techniques and IR playbooks.

    Chunks by logical domain section (Description, Detection Guidance, Mitigation, Response Steps)
    so each chunk contains complete actionable guidance with embedded technique headers.
    """
    chunks: List[KnowledgeChunk] = []

    # Process MITRE ATT&CK entries
    for entry in mitre_data:
        tid = entry.get("technique_id", "T-UNKNOWN")
        name = entry.get("name", "Unknown Technique")
        tactics = entry.get("tactics", [])
        url = entry.get("url")

        # Chunk 1: Description & Overview
        desc = entry.get("description", "")
        if desc:
            chunks.append(
                KnowledgeChunk(
                    chunk_id=f"CHK-{tid}-DESC",
                    doc_id=tid,
                    title=f"{tid}: {name} - Description",
                    source_type="mitre_attack",
                    technique_id=tid,
                    tactics=tactics,
                    text=(
                        f"MITRE ATT&CK Technique {tid} ({name})\n"
                        f"Tactics: {', '.join(tactics)}\n"
                        f"Description: {desc}"
                    ),
                    url=url,
                    metadata={"section": "description"},
                )
            )

        # Chunk 2: Detection Guidance
        det = entry.get("detection_guidance", "")
        if det:
            chunks.append(
                KnowledgeChunk(
                    chunk_id=f"CHK-{tid}-DET",
                    doc_id=tid,
                    title=f"{tid}: {name} - Detection Guidance",
                    source_type="mitre_attack",
                    technique_id=tid,
                    tactics=tactics,
                    text=(
                        f"MITRE ATT&CK Technique {tid} ({name}) Detection Guidance\n"
                        f"Tactics: {', '.join(tactics)}\n"
                        f"Detection Strategy: {det}"
                    ),
                    url=url,
                    metadata={"section": "detection"},
                )
            )

        # Chunk 3: Mitigation Strategy
        mit = entry.get("mitigation", "")
        if mit:
            chunks.append(
                KnowledgeChunk(
                    chunk_id=f"CHK-{tid}-MIT",
                    doc_id=tid,
                    title=f"{tid}: {name} - Mitigation Controls",
                    source_type="mitre_attack",
                    technique_id=tid,
                    tactics=tactics,
                    text=(
                        f"MITRE ATT&CK Technique {tid} ({name}) Mitigation Controls\n"
                        f"Tactics: {', '.join(tactics)}\n"
                        f"Mitigation & Defenses: {mit}"
                    ),
                    url=url,
                    metadata={"section": "mitigation"},
                )
            )

    # Process Incident Response Playbooks
    for pb in playbook_data:
        pbid = pb.get("playbook_id", "IR-UNKNOWN")
        title = pb.get("title", "Unknown Playbook")
        cat = pb.get("category", "General")
        phase = pb.get("nist_phase", "Incident Handling")
        summary = pb.get("summary", "")
        ref = pb.get("references", "")

        inv_steps = "\n".join(pb.get("investigation_steps", []))
        containment = "\n".join(pb.get("containment_actions", []))
        remediation = "\n".join(pb.get("remediation_actions", []))

        # Chunk 1: Playbook Overview & Investigation Steps
        chunks.append(
            KnowledgeChunk(
                chunk_id=f"CHK-{pbid}-TRIAGE",
                doc_id=pbid,
                title=f"{pbid}: {title} - Investigation Steps",
                source_type="incident_playbook",
                technique_id=None,
                tactics=[cat],
                text=(
                    f"Incident Response Playbook: {title} ({pbid})\n"
                    f"NIST Phase: {phase} | Category: {cat}\n"
                    f"Summary: {summary}\n"
                    f"Investigation Steps:\n{inv_steps}\n"
                    f"Reference: {ref}"
                ),
                url="https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final",
                metadata={"section": "investigation", "nist_phase": phase},
            )
        )

        # Chunk 2: Containment & Remediation Actions
        chunks.append(
            KnowledgeChunk(
                chunk_id=f"CHK-{pbid}-REMED",
                doc_id=pbid,
                title=f"{pbid}: {title} - Containment & Remediation",
                source_type="incident_playbook",
                technique_id=None,
                tactics=[cat],
                text=(
                    f"Incident Response Playbook: {title} ({pbid}) - Remediation Controls\n"
                    f"Containment Actions:\n{containment}\n\n"
                    f"Remediation Actions:\n{remediation}\n"
                    f"Reference: {ref}"
                ),
                url="https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final",
                metadata={"section": "containment_remediation"},
            )
        )

    return chunks


def build_vector_store(
    chunks: List[KnowledgeChunk], embedding_manager: EmbeddingManager
) -> Tuple[faiss.IndexFlatIP, List[KnowledgeChunk]]:
    """Embed chunks and index them into an exact inner-product (cosine) FAISS index."""
    if not chunks:
        raise ValueError("Cannot build index from empty chunks list.")

    texts = [c.text for c in chunks]
    embeddings = embedding_manager.embed_documents(texts)

    # L2-normalized vectors with IndexFlatIP computes exact Cosine Similarity
    dim = embeddings.shape[1]
    index = faiss.IndexFlatIP(dim)
    index.add(embeddings)

    return index, chunks


def save_vector_store(
    index: faiss.IndexFlatIP,
    chunks: List[KnowledgeChunk],
    cache_dir: Path = settings.VECTOR_CACHE_DIR,
) -> None:
    """Save FAISS index binary and chunks metadata JSON to disk."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    index_file = cache_dir / "faiss_index.bin"
    chunks_file = cache_dir / "chunks.json"

    faiss.write_index(index, str(index_file))
    chunks_dicts = [c.model_dump() for c in chunks]
    with open(chunks_file, "w", encoding="utf-8") as f:
        json.dump(chunks_dicts, f, indent=2)

    logger.info("Saved FAISS vector store with %d chunks to %s", len(chunks), cache_dir)


def load_vector_store(
    cache_dir: Path = settings.VECTOR_CACHE_DIR,
) -> Optional[Tuple[faiss.IndexFlatIP, List[KnowledgeChunk]]]:
    """Load FAISS index and chunk metadata from disk if available."""
    index_file = cache_dir / "faiss_index.bin"
    chunks_file = cache_dir / "chunks.json"

    if not index_file.exists() or not chunks_file.exists():
        return None

    try:
        index = faiss.read_index(str(index_file))
        with open(chunks_file, "r", encoding="utf-8") as f:
            raw_chunks = json.load(f)
        chunks = [KnowledgeChunk.model_validate(c) for c in raw_chunks]
        logger.info("Loaded cached FAISS vector store with %d chunks", len(chunks))
        return index, chunks
    except Exception as e:
        logger.warning("Failed to load cached vector store: %s", e)
        return None


def get_or_create_vector_store(
    embedding_manager: Optional[EmbeddingManager] = None, force_rebuild: bool = False
) -> Tuple[faiss.IndexFlatIP, List[KnowledgeChunk]]:
    """Retrieve existing cached FAISS store or build from source knowledge documents."""
    cache_dir = settings.VECTOR_CACHE_DIR

    if not force_rebuild:
        cached = load_vector_store(cache_dir)
        if cached is not None:
            return cached

    logger.info("Building new FAISS vector store from source knowledge...")
    emb_mgr = embedding_manager or EmbeddingManager()
    mitre_data, playbook_data = load_knowledge_documents()
    chunks = chunk_cybersecurity_knowledge(mitre_data, playbook_data)
    index, indexed_chunks = build_vector_store(chunks, emb_mgr)
    save_vector_store(index, indexed_chunks, cache_dir)
    return index, indexed_chunks
