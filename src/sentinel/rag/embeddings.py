from __future__ import annotations

import re
from functools import lru_cache
from typing import Protocol

from sentinel.schemas.rag import EmbeddingModelInfo


KNOWN_DIMS = {
    "sentence-transformers/all-MiniLM-L6-v2": 384,
}


class EmbeddingClient(Protocol):
    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        ...

    def embed_query(self, text: str) -> list[float]:
        ...

    def get_model_info(self) -> EmbeddingModelInfo:
        ...


class SentenceTransformerEmbeddingClient:
    def __init__(self, model_name: str, *, local_files_only: bool = False, normalize_embeddings: bool = True) -> None:
        self.model_name = model_name
        self.local_files_only = local_files_only
        self.normalize_embeddings = normalize_embeddings
        self._model = None

    def _load(self):
        if self._model is None:
            self._model = _load_sentence_transformer(self.model_name, self.local_files_only)
        return self._model

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        model = self._load()
        vectors = model.encode(texts, normalize_embeddings=self.normalize_embeddings)
        return [vector.tolist() for vector in vectors]

    def embed_query(self, text: str) -> list[float]:
        return self.embed_documents([text])[0]

    def get_model_info(self) -> EmbeddingModelInfo:
        model = self._load()
        if hasattr(model, "get_embedding_dimension"):
            dimension = int(model.get_embedding_dimension())
        else:
            dimension = int(model.get_sentence_embedding_dimension())
        max_seq_length = getattr(model, "max_seq_length", None)
        return EmbeddingModelInfo(
            model_name=self.model_name,
            dimension=dimension,
            provider="sentence_transformers",
            max_seq_length=max_seq_length,
            normalize_embeddings=self.normalize_embeddings,
        )


class LangChainEmbeddingAdapter:
    def __init__(self, client: EmbeddingClient) -> None:
        self.client = client

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return self.client.embed_documents(texts)

    def embed_query(self, text: str) -> list[float]:
        return self.client.embed_query(text)


@lru_cache(maxsize=4)
def _load_sentence_transformer(model_name: str, local_files_only: bool):
    from sentence_transformers import SentenceTransformer

    return SentenceTransformer(model_name, local_files_only=local_files_only)


def safe_collection_name(prefix: str, model_name: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", model_name.lower()).strip("_")
    return f"{prefix}_{slug}"[:63]


def get_embedding_model_info(model_name: str, *, local_files_only: bool = False) -> EmbeddingModelInfo:
    try:
        return SentenceTransformerEmbeddingClient(model_name, local_files_only=local_files_only).get_model_info()
    except Exception:
        if model_name in KNOWN_DIMS:
            return EmbeddingModelInfo(
                model_name=model_name,
                dimension=KNOWN_DIMS[model_name],
                provider="sentence_transformers",
                normalize_embeddings=True,
            )
        raise
