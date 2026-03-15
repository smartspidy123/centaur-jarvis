"""
Text Embedder for RAG - converts security knowledge to vectors
Uses sentence-transformers for local embedding (no API costs)
"""
from typing import List, Union

from sentence_transformers import SentenceTransformer
import numpy as np

from shared.logger import get_logger

logger = get_logger("rag.embedder")

class LocalEmbedder:
    """Local embedding generator using sentence-transformers"""
    
    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2"):
        logger.info(f"Loading embedding model: {model_name}")
        self.model = SentenceTransformer(model_name)
        self.dimension = self.model.get_sentence_embedding_dimension()
        logger.info(f"✅ Model loaded. Dimension: {self.dimension}")
    
    def encode(self, texts: Union[str, List[str]]) -> List[List[float]]:
        """Convert text(s) to embeddings"""
        if isinstance(texts, str):
            texts = [texts]
        
        embeddings = self.model.encode(texts, normalize_embeddings=True)
        return embeddings.tolist()
    
    def encode_batch(self, texts: List[str], batch_size: int = 32) -> List[List[float]]:
        """Batch encode for efficiency"""
        embeddings = self.model.encode(texts, batch_size=batch_size, normalize_embeddings=True)
        return embeddings.tolist()
