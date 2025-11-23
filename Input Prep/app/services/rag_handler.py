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

# Data source delimiters (per INNOVATION 4: Structured Query Separation)
EXTERNAL_START = "[EXTERNAL]"
EXTERNAL_END = "[/EXTERNAL]"
CONVERSATION_START = "[CONVERSATION]"
CONVERSATION_END = "[/CONVERSATION]"


def apply_delimiter(text: str, delimiter_type: str = "external") -> str:
    """
    Apply delimiter tags to text based on source type.
    
    Args:
        text: Text content to wrap with delimiters
        delimiter_type: Type of delimiter ('external' for RAG data, 'conversation' for chat history)
    
    Returns:
        Text wrapped with appropriate tags
    
    Example:
        >>> apply_delimiter("RAG data", "external")
        '[EXTERNAL]RAG data[/EXTERNAL]'
        >>> apply_delimiter("Previous chat", "conversation")
        '[CONVERSATION]Previous chat[/CONVERSATION]'
    """
    if delimiter_type == "conversation":
        return f"{CONVERSATION_START}{text}{CONVERSATION_END}"
    else:
        return f"{EXTERNAL_START}{text}{EXTERNAL_END}"


def remove_delimiter(text: str) -> str:
    """
    Remove delimiter tags from text (works for both external and conversation).
    
    Args:
        text: Text with delimiters
    
    Returns:
        Text without delimiter tags
    
    Example:
        >>> remove_delimiter('[EXTERNAL]RAG data[/EXTERNAL]')
        'RAG data'
        >>> remove_delimiter('[CONVERSATION]Chat history[/CONVERSATION]')
        'Chat history'
    """
    text = text.strip()
    # Remove EXTERNAL delimiters
    if text.startswith(EXTERNAL_START):
        text = text[len(EXTERNAL_START):]
    if text.endswith(EXTERNAL_END):
        text = text[:-len(EXTERNAL_END)]
    # Remove CONVERSATION delimiters
    if text.startswith(CONVERSATION_START):
        text = text[len(CONVERSATION_START):]
    if text.endswith(CONVERSATION_END):
        text = text[:-len(CONVERSATION_END)]
    return text


def sign_external_chunk(chunk: str, delimiter_type: str = "external") -> Tuple[str, str]:
    """
    Apply delimiter and generate HMAC for a data chunk.
    
    Args:
        chunk: Data chunk (external RAG data or conversation history)
        delimiter_type: Type of delimiter ('external' for RAG, 'conversation' for chat history)
    
    Returns:
        Tuple of (delimited_chunk, hmac_signature)
    
    Example:
        >>> delimited, sig = sign_external_chunk("RAG data", "external")
        >>> delimited.startswith('[EXTERNAL]')
        True
        >>> delimited, sig = sign_external_chunk("Chat history", "conversation")
        >>> delimited.startswith('[CONVERSATION]')
        True
        >>> len(sig) == 64  # SHA256 hex digest length
        True
    """
    delimited = apply_delimiter(chunk, delimiter_type=delimiter_type)
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
        
        delimited, signature = sign_external_chunk(data, delimiter_type="external")
        delimited_chunks.append(delimited)
        signatures.append(signature)
    
    logger.debug(f"Processed {len(delimited_chunks)} external data chunks with HMAC signatures")
    return delimited_chunks, signatures


def process_conversation_context(conversation_text: str) -> Tuple[str, str]:
    """
    Process conversation history with [CONVERSATION] delimiters and HMAC signature.
    
    This separates conversation context from external RAG data per INNOVATION 4 
    (Structured Query Separation) to prevent confusion and enable proper context tracking.
    
    Args:
        conversation_text: Formatted conversation history text
    
    Returns:
        Tuple of (delimited_text, hmac_signature)
    
    Example:
        >>> text = "Previous: User asked about weather\\nBot replied..."
        >>> delimited, sig = process_conversation_context(text)
        >>> delimited.startswith('[CONVERSATION]')
        True
    """
    if not conversation_text or not conversation_text.strip():
        return "", ""
    
    delimited, signature = sign_external_chunk(conversation_text, delimiter_type="conversation")
    logger.debug(f"Processed conversation context ({len(conversation_text)} chars) with HMAC signature")
    return delimited, signature


def retrieve_from_vector_db(query: str, top_k: int = 5) -> List[str]:
    """
    Retrieve relevant chunks from vector database using ChromaDB.
    
    Args:
        query: Query text to search for
        top_k: Number of top results to retrieve
    
    Returns:
        List of retrieved text chunks
    
    Example:
        >>> results = retrieve_from_vector_db("weather information", top_k=3)
        >>> isinstance(results, list)
        True
    """
    try:
        import chromadb
        
        # Initialize ChromaDB client (persistent storage in ./chroma_db/)
        client = chromadb.PersistentClient(path="./chroma_db")
        
        # Get or create collection
        try:
            collection = client.get_collection(name="knowledge_base")
        except Exception:
            logger.warning("Knowledge base collection not found. Create it with populate_vector_db.py")
            return []
        
        # Query the collection
        results = collection.query(
            query_texts=[query],
            n_results=top_k
        )
        
        # Extract documents
        if results and 'documents' in results and len(results['documents']) > 0:
            documents = results['documents'][0]  # First query results
            logger.info(f"Retrieved {len(documents)} documents from vector DB for query: {query[:50]}...")
            return documents
        else:
            logger.info(f"No results found in vector DB for query: {query[:50]}...")
            return []
            
    except ImportError:
        logger.warning("ChromaDB not installed. Install with: pip install chromadb")
        return []
    except Exception as e:
        logger.error(f"Error retrieving from vector DB: {e}")
        return []


def process_rag_data(
    user_prompt: str,
    external_data: Optional[List[str]] = None,
    file_chunks: Optional[List[FileChunk]] = None,
    retrieve_from_db: bool = False,
    conversation_text: Optional[str] = None,
    top_k: int = 5
) -> Tuple[List[str], List[str], bool]:
    """
    Process all RAG data sources and conversation context separately.
    
    Per INNOVATION 4 (Structured Query Separation), keeps conversation history
    separate from RAG data using different delimiters to prevent confusion.
    
    Handles:
    - Conversation history (with [CONVERSATION] tags) - SEPARATE from RAG
    - Direct external data provided in request (with [EXTERNAL] tags)
    - File chunks from uploaded documents (with [EXTERNAL] tags)
    - Vector DB retrieval (with [EXTERNAL] tags, only if enabled)
    
    Args:
        user_prompt: The user's input (used for vector DB queries)
        external_data: Optional list of external data strings
        file_chunks: Optional list of FileChunk objects
        retrieve_from_db: Whether to retrieve from vector database
        conversation_text: Optional conversation history (kept separate from RAG)
        top_k: Number of results to retrieve from vector DB
    
    Returns:
        Tuple of (all_delimited_chunks, all_signatures, rag_enabled)
        NOTE: Conversation context is placed FIRST, followed by RAG data
    
    Example:
        >>> chunks, sigs, enabled = process_rag_data(
        ...     "What's the weather?",
        ...     external_data=["Weather data"],
        ...     conversation_text="Previous: User asked about time",
        ...     retrieve_from_db=False
        ... )
        >>> chunks[0].startswith('[CONVERSATION]')  # Conversation comes first
        True
        >>> chunks[1].startswith('[EXTERNAL]')  # RAG data follows
        True
    """
    all_delimited_chunks = []
    all_signatures = []
    
    # Process conversation history FIRST (separate from RAG data)
    if conversation_text and conversation_text.strip():
        conv_delimited, conv_sig = process_conversation_context(conversation_text)
        if conv_delimited:
            all_delimited_chunks.append(conv_delimited)
            all_signatures.append(conv_sig)
            logger.info(f"Added conversation context (tagged as [CONVERSATION], separate from RAG)")
    
    # Process file chunks (RAG data)
    if file_chunks:
        file_delimited, file_sigs = process_file_chunks(file_chunks)
        all_delimited_chunks.extend(file_delimited)
        all_signatures.extend(file_sigs)
        logger.info(f"Added {len(file_chunks)} file chunks to RAG data")
    
    # Process direct external data (RAG data)
    if external_data:
        ext_delimited, ext_sigs = process_external_data(external_data)
        all_delimited_chunks.extend(ext_delimited)
        all_signatures.extend(ext_sigs)
        logger.info(f"Added {len(ext_delimited)} external data chunks to RAG data")
    
    # Retrieve from vector DB if enabled (RAG data)
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
        f"Context processing complete: {len(all_delimited_chunks)} total chunks, "
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

