"""
Text embedding service for semantic fingerprinting.

Uses sentence-transformers to generate compact embeddings for text analysis.
"""

import hashlib
from typing import Optional, Tuple
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Try to import sentence-transformers
try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False
    logger.warning("sentence-transformers not available. Text embedding disabled.")

# Global model instance (loaded lazily)
_model = None
MODEL_NAME = "all-MiniLM-L6-v2"  # Lightweight, fast model


def get_embedding_model() -> Optional[SentenceTransformer]:
    """
    Get or load the sentence transformer model.
    
    Returns:
        SentenceTransformer model or None if unavailable
    """
    global _model
    
    if not SENTENCE_TRANSFORMERS_AVAILABLE:
        return None
    
    if _model is None:
        try:
            logger.info(f"Loading sentence transformer model: {MODEL_NAME}")
            _model = SentenceTransformer(MODEL_NAME)
            logger.info(f"Model loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load sentence transformer model: {e}")
            return None
    
    return _model


def generate_text_embedding(text: str) -> Optional[str]:
    """
    Generate a compact embedding fingerprint for text.
    
    Args:
        text: Text to embed
    
    Returns:
        Hash of embedding vector, or None if failed
    """
    if not text or not text.strip():
        return None
    
    model = get_embedding_model()
    if model is None:
        logger.warning("Sentence transformer model not available")
        return None
    
    try:
        # Generate embedding
        embedding = model.encode(text, convert_to_numpy=True)
        
        # Create hash of embedding vector for compact fingerprint
        embedding_bytes = embedding.tobytes()
        embedding_hash = hashlib.sha256(embedding_bytes).hexdigest()[:32]
        
        logger.debug(f"Generated embedding hash: {embedding_hash} (shape: {embedding.shape})")
        
        return embedding_hash
    
    except Exception as e:
        logger.error(f"Failed to generate text embedding: {e}")
        return None


def generate_text_embedding_with_vector(text: str) -> Optional[Tuple[str, list]]:
    """
    Generate embedding fingerprint and return full vector.
    
    Args:
        text: Text to embed
    
    Returns:
        Tuple of (hash, vector_list) or None if failed
    """
    if not text or not text.strip():
        return None
    
    model = get_embedding_model()
    if model is None:
        return None
    
    try:
        # Generate embedding
        embedding = model.encode(text, convert_to_numpy=True)
        
        # Create hash
        embedding_bytes = embedding.tobytes()
        embedding_hash = hashlib.sha256(embedding_bytes).hexdigest()[:32]
        
        # Convert to list for JSON serialization
        embedding_list = embedding.tolist()
        
        logger.debug(f"Generated embedding: hash={embedding_hash}, dim={len(embedding_list)}")
        
        return embedding_hash, embedding_list
    
    except Exception as e:
        logger.error(f"Failed to generate text embedding with vector: {e}")
        return None


def calculate_embedding_similarity(text1: str, text2: str) -> Optional[float]:
    """
    Calculate cosine similarity between two text embeddings.
    
    Args:
        text1: First text
        text2: Second text
    
    Returns:
        Similarity score (0-1), or None if failed
    """
    model = get_embedding_model()
    if model is None:
        return None
    
    try:
        # Generate embeddings
        embeddings = model.encode([text1, text2], convert_to_numpy=True)
        
        # Calculate cosine similarity
        from numpy import dot
        from numpy.linalg import norm
        
        similarity = dot(embeddings[0], embeddings[1]) / (norm(embeddings[0]) * norm(embeddings[1]))
        
        logger.debug(f"Embedding similarity: {similarity:.4f}")
        
        return float(similarity)
    
    except Exception as e:
        logger.error(f"Failed to calculate embedding similarity: {e}")
        return None


def check_embedding_available() -> bool:
    """
    Check if text embedding is available.
    
    Returns:
        True if available, False otherwise
    """
    return SENTENCE_TRANSFORMERS_AVAILABLE and get_embedding_model() is not None
