"""Local embedding generator using sentence-transformers and offline deterministic fallback.

Produces L2-normalized dense vector representations for FAISS cosine similarity search.
"""

import hashlib
import logging
from typing import List, Union
import numpy as np
from config.settings import settings

logger = logging.getLogger(__name__)


class EmbeddingManager:
    """Manages document and query embeddings with local sentence-transformers."""

    def __init__(
        self,
        model_name: str = settings.EMBEDDING_MODEL_NAME,
        force_mock: bool = False,
    ):
        self.model_name = model_name
        self.force_mock = force_mock
        self.dimension = 384
        self._model = None

        if not self.force_mock:
            try:
                from sentence_transformers import SentenceTransformer

                logger.info("Loading local embedding model: %s", self.model_name)
                self._model = SentenceTransformer(self.model_name)
                if hasattr(self._model, "get_embedding_dimension"):
                    self.dimension = self._model.get_embedding_dimension()
                elif hasattr(self._model, "get_sentence_embedding_dimension"):
                    self.dimension = self._model.get_sentence_embedding_dimension()
                else:
                    self.dimension = 384
                logger.info("Embedding model loaded successfully (dimension: %d)", self.dimension)
            except Exception as e:
                logger.warning(
                    "Failed to initialize SentenceTransformer (%s). Using deterministic mock fallback.",
                    e,
                )
                self._model = None

    def _mock_embed(self, text: str) -> np.ndarray:
        """Deterministic 384-dimensional vector from SHA-256 digest for offline testing."""
        vec = np.zeros(self.dimension, dtype=np.float32)
        words = text.lower().split()
        if not words:
            words = ["empty"]
        for idx, word in enumerate(words):
            h = int(hashlib.sha256(word.encode("utf-8")).hexdigest(), 16)
            pos = h % self.dimension
            vec[pos] += 1.0 / (idx + 1)

        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        return vec

    def embed_documents(self, texts: List[str]) -> np.ndarray:
        """Generate normalized float32 embeddings for a list of document strings."""
        if not texts:
            return np.empty((0, self.dimension), dtype=np.float32)

        if self._model is not None and not self.force_mock:
            embeddings = self._model.encode(
                texts,
                batch_size=32,
                show_progress_bar=False,
                normalize_embeddings=True,
            )
            return np.array(embeddings, dtype=np.float32)

        # Fallback deterministic embeddings
        mock_vecs = [self._mock_embed(t) for t in texts]
        return np.vstack(mock_vecs).astype(np.float32)

    def embed_query(self, query: str) -> np.ndarray:
        """Generate normalized float32 embedding for a single search query."""
        if self._model is not None and not self.force_mock:
            emb = self._model.encode([query], normalize_embeddings=True)
            return np.array(emb, dtype=np.float32)

        mock_vec = self._mock_embed(query).reshape(1, -1)
        return mock_vec.astype(np.float32)
