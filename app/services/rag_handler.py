"""
RAG (Retrieval-Augmented Generation) data handler.

Processes external data from direct sources or vector databases,
applies delimiters, and generates HMAC signatures for integrity verification.
"""

from typing import List, Optional, Tuple
from app.models.schemas import FileChunk
from app.utils.hmac_utils import generate_hmac
from app.utils.logger import get_logger

logger = get_logger(__name__)

# External data delimiters
EXTERNAL_START = "[EXTERNAL]"
EXTERNAL_END = "[/EXTERNAL]"


def apply_delimiter(text: str) -> str:
    """
    Apply external data delimiter tags to text.
    
    Args:
        text: Text content to wrap with delimiters
    
    Returns:
        Text wrapped with [EXTERNAL] tags
    
    Example:
        >>> apply_delimiter("RAG data")
        '[EXTERNAL]RAG data[/EXTERNAL]'
    """
    return f"{EXTERNAL_START}{text}{EXTERNAL_END}"


def remove_delimiter(text: str) -> str:
    """
    Remove external data delimiter tags from text.
    
    Args:
        text: Text with delimiters
    
    Returns:
        Text without delimiter tags
    
    Example:
        >>> remove_delimiter('[EXTERNAL]RAG data[/EXTERNAL]')
        'RAG data'
    """
    text = text.strip()
    if text.startswith(EXTERNAL_START):
        text = text[len(EXTERNAL_START):]
    if text.endswith(EXTERNAL_END):
        text = text[:-len(EXTERNAL_END)]
    return text


def sign_external_chunk(chunk: str) -> Tuple[str, str]:
    """
    Apply delimiter and generate HMAC for an external data chunk.
    
    Args:
        chunk: External data chunk
    
    Returns:
        Tuple of (delimited_chunk, hmac_signature)
    
    Example:
        >>> delimited, sig = sign_external_chunk("RAG data")
        >>> delimited.startswith('[EXTERNAL]')
        True
        >>> len(sig) == 64  # SHA256 hex digest length
        True
    """
    delimited = apply_delimiter(chunk)
    signature = generate_hmac(chunk)  # Sign the original content, not the delimited version
    return delimited, signature


def process_file_chunks(file_chunks: List[FileChunk]) -> Tuple[List[str], List[str]]:
    """
    Process file chunks into delimited external data with HMAC signatures.
    
    Args:
        file_chunks: List of FileChunk objects from file extraction
    
    Returns:
        Tuple of (list of delimited chunks, list of HMAC signatures)
    
    Example:
        >>> from app.models.schemas import FileChunk
        >>> chunks = [FileChunk(content="text", source="file.txt", hash="abc", chunk_id=0)]
        >>> delimited, sigs = process_file_chunks(chunks)
        >>> len(delimited) == len(sigs)
        True
    """
    delimited_chunks = []
    signatures = []
    
    for chunk in file_chunks:
        # Add source metadata to chunk content
        chunk_with_source = f"{chunk.content} [Source: {chunk.source}, Chunk: {chunk.chunk_id}]"
        delimited, signature = sign_external_chunk(chunk_with_source)
        delimited_chunks.append(delimited)
        signatures.append(signature)
    
    logger.debug(f"Processed {len(file_chunks)} file chunks with HMAC signatures")
    return delimited_chunks, signatures


def process_external_data(external_data: List[str]) -> Tuple[List[str], List[str]]:
    """
    Process external data strings with delimiters and HMAC signatures.
    
    Args:
        external_data: List of external data strings
    
    Returns:
        Tuple of (list of delimited chunks, list of HMAC signatures)
    
    Example:
        >>> delimited, sigs = process_external_data(["chunk1", "chunk2"])
        >>> len(delimited) == 2
        True
        >>> all(d.startswith('[EXTERNAL]') for d in delimited)
        True
    """
    delimited_chunks = []
    signatures = []
    
    for i, data in enumerate(external_data):
        if not data or not data.strip():
            continue
        
        delimited, signature = sign_external_chunk(data)
        delimited_chunks.append(delimited)
        signatures.append(signature)
    
    logger.debug(f"Processed {len(delimited_chunks)} external data chunks with HMAC signatures")
    return delimited_chunks, signatures


def retrieve_from_vector_db(query: str, top_k: int = 5) -> List[str]:
    """
    Retrieve relevant chunks from vector database.
    
    This is a placeholder for future implementation with ChromaDB/FAISS.
    
    Args:
        query: Query text to search for
        top_k: Number of top results to retrieve
    
    Returns:
        List of retrieved text chunks
    
    Note:
        This is currently a stub. Implement with your vector DB of choice:
        - ChromaDB: Persistent vector database
        - FAISS: Facebook's similarity search library
        - Pinecone: Cloud-based vector database
    
    Example:
        >>> results = retrieve_from_vector_db("weather information", top_k=3)
        >>> isinstance(results, list)
        True
    """
    logger.warning("Vector DB retrieval not yet implemented. Returning empty list.")
    # TODO: Implement vector DB integration
    # Example implementation:
    # 
    # from chromadb import Client
    # client = Client()
    # collection = client.get_collection("documents")
    # results = collection.query(query_texts=[query], n_results=top_k)
    # return results['documents'][0]
    
    return []


def process_rag_data(
    user_prompt: str,
    external_data: Optional[List[str]] = None,
    file_chunks: Optional[List[FileChunk]] = None,
    retrieve_from_db: bool = False,
    top_k: int = 5
) -> Tuple[List[str], List[str], bool]:
    """
    Process all RAG data sources and combine them.
    
    Handles:
    - Direct external data provided in request
    - File chunks from uploaded documents
    - Vector DB retrieval (if enabled)
    
    Args:
        user_prompt: The user's input (used for vector DB queries)
        external_data: Optional list of external data strings
        file_chunks: Optional list of FileChunk objects
        retrieve_from_db: Whether to retrieve from vector database
        top_k: Number of results to retrieve from vector DB
    
    Returns:
        Tuple of (all_delimited_chunks, all_signatures, rag_enabled)
    
    Example:
        >>> chunks, sigs, enabled = process_rag_data(
        ...     "What's the weather?",
        ...     external_data=["Weather data"],
        ...     file_chunks=None,
        ...     retrieve_from_db=False
        ... )
        >>> enabled
        True
    """
    all_delimited_chunks = []
    all_signatures = []
    
    # Process file chunks
    if file_chunks:
        file_delimited, file_sigs = process_file_chunks(file_chunks)
        all_delimited_chunks.extend(file_delimited)
        all_signatures.extend(file_sigs)
        logger.info(f"Added {len(file_chunks)} file chunks to RAG data")
    
    # Process direct external data
    if external_data:
        ext_delimited, ext_sigs = process_external_data(external_data)
        all_delimited_chunks.extend(ext_delimited)
        all_signatures.extend(ext_sigs)
        logger.info(f"Added {len(ext_delimited)} external data chunks to RAG data")
    
    # Retrieve from vector DB if enabled
    if retrieve_from_db:
        db_results = retrieve_from_vector_db(user_prompt, top_k=top_k)
        if db_results:
            db_delimited, db_sigs = process_external_data(db_results)
            all_delimited_chunks.extend(db_delimited)
            all_signatures.extend(db_sigs)
            logger.info(f"Added {len(db_results)} vector DB results to RAG data")
    
    # Determine if RAG is enabled
    rag_enabled = len(all_delimited_chunks) > 0
    
    logger.info(
        f"RAG processing complete: {len(all_delimited_chunks)} total chunks, "
        f"RAG enabled: {rag_enabled}"
    )
    
    return all_delimited_chunks, all_signatures, rag_enabled


def verify_external_chunk(delimited_chunk: str, signature: str) -> bool:
    """
    Verify the HMAC signature of a delimited external chunk.
    
    Args:
        delimited_chunk: Chunk with [EXTERNAL] delimiters
        signature: HMAC signature to verify
    
    Returns:
        True if signature is valid, False otherwise
    
    Example:
        >>> delimited, sig = sign_external_chunk("test data")
        >>> verify_external_chunk(delimited, sig)
        True
    """
    from app.utils.hmac_utils import verify_hmac
    
    # Extract original content
    original = remove_delimiter(delimited_chunk)
    
    # Verify signature against original content
    return verify_hmac(original, signature)

