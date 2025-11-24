"""
Payload packaging service.

Combines all processed data into the final PreparedInput format
with complete metadata and timing information.
"""

import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any
from app.models.schemas import (
    PreparedInput,
    TextEmbedStub,
    ImageEmojiStub,
    MetadataInfo,
    StatsInfo,
    FileInfo,
    EmojiSummary,
    Layer0Output,
    ImageProcessingOutput
)
from app.utils.logger import get_logger

logger = get_logger(__name__)


def package_payload(
    # Text data
    original_user_prompt: str,
    normalized_user: str,
    normalized_external: List[str],
    emoji_descriptions: List[str],
    hmacs: List[str],
    stats: StatsInfo,
    
    # Media data
    image_dict: Dict[str, Any],
    emoji_summary: EmojiSummary,
    
    # Metadata
    request_id: Optional[str] = None,
    session_id: Optional[str] = None,
    rag_enabled: bool = False,
    has_media: bool = False,
    has_file: bool = False,
    file_info: Optional[FileInfo] = None,
    prep_time_ms: float = 0.0,
    step_times: Optional[Dict[str, float]] = None,
    
    # Advanced analysis
    layer0_output: Optional[Layer0Output] = None,
    image_processing_output: Optional[ImageProcessingOutput] = None
) -> PreparedInput:
    """
    Package all processed data into final PreparedInput format.
    
    This is the main output format of the input preparation module.
    
    Args:
        original_user_prompt: Original user input text (for LLM)
        normalized_user: Normalized user input text (for security analysis)
        normalized_external: List of normalized external chunks with delimiters
        emoji_descriptions: Text descriptions of emojis
        hmacs: HMAC signatures for external chunks
        stats: Statistics about the input
        image_dict: Image metadata dictionary
        emoji_summary: Summary of emojis
        request_id: Optional custom request ID (generates UUID if not provided)
        rag_enabled: Whether RAG/external data was used
        has_media: Whether media (images) were included
        has_file: Whether files were uploaded
        file_info: Information about uploaded file
        prep_time_ms: Total preparation time in milliseconds
        step_times: Breakdown of time per processing step
    
    Returns:
        PreparedInput object ready for downstream processing
    
    Example:
        >>> from app.models.schemas import StatsInfo, EmojiSummary
        >>> stats = StatsInfo(
        ...     char_total=100, token_estimate=25,
        ...     user_external_ratio=0.7, file_chunks_count=0,
        ...     extracted_total_chars=0
        ... )
        >>> emoji_sum = EmojiSummary(count=0, types=[], descriptions=[])
        >>> prepared = package_payload(
        ...     original_user_prompt="Hello",
        ...     normalized_user="Hello",
        ...     normalized_external=[],
        ...     emoji_descriptions=[],
        ...     hmacs=[],
        ...     stats=stats,
        ...     image_dict={},
        ...     emoji_summary=emoji_sum
        ... )
        >>> prepared.metadata.rag_enabled
        False
    """
    # Generate request ID if not provided
    if request_id is None:
        request_id = str(uuid.uuid4())
    
    # Create timestamp
    timestamp = datetime.utcnow().isoformat() + 'Z'
    
    # Create TextEmbedStub
    text_embed_stub = TextEmbedStub(
        original_user_prompt=original_user_prompt,
        normalized_user=normalized_user,
        normalized_external=normalized_external,
        emoji_descriptions=emoji_descriptions,
        hmacs=hmacs,
        stats=stats
    )
    
    # Create ImageEmojiStub
    image_emoji_stub = ImageEmojiStub(
        image=image_dict,
        emoji_summary=emoji_summary
    )
    
    # Create MetadataInfo
    metadata = MetadataInfo(
        request_id=request_id,
        timestamp=timestamp,
        session_id=session_id,
        rag_enabled=rag_enabled,
        has_media=has_media,
        has_file=has_file,
        file_info=file_info,
        prep_time_ms=prep_time_ms,
        step_times=step_times
    )
    
    # Create final PreparedInput
    prepared_input = PreparedInput(
        text_embed_stub=text_embed_stub,
        image_emoji_stub=image_emoji_stub,
        metadata=metadata,
        layer0=layer0_output,
        image_processing=image_processing_output
    )
    
    logger.info(
        f"Payload packaged: request_id={request_id}, "
        f"tokens={stats.token_estimate}, prep_time={prep_time_ms:.2f}ms"
    )
    
    return prepared_input


def create_error_response(
    error_message: str,
    request_id: Optional[str] = None,
    prep_time_ms: float = 0.0
) -> PreparedInput:
    """
    Create an error response in PreparedInput format.
    
    Useful for handling processing failures gracefully.
    
    Args:
        error_message: Description of the error
        request_id: Optional request ID
        prep_time_ms: Time elapsed before error
    
    Returns:
        PreparedInput object with error information
    
    Example:
        >>> error_response = create_error_response("File not found")
        >>> error_response.metadata.request_id
        '...'
    """
    from app.models.schemas import StatsInfo, EmojiSummary
    
    if request_id is None:
        request_id = str(uuid.uuid4())
    
    # Create minimal stats
    stats = StatsInfo(
        char_total=0,
        token_estimate=0,
        user_external_ratio=0.0,
        file_chunks_count=0,
        extracted_total_chars=0
    )
    
    # Create empty emoji summary
    emoji_summary = EmojiSummary(
        count=0,
        types=[],
        descriptions=[]
    )
    
    # Create text stub with error
    text_embed_stub = TextEmbedStub(
        original_user_prompt=f"ERROR: {error_message}",
        normalized_user=f"ERROR: {error_message}",
        normalized_external=[],
        emoji_descriptions=[],
        hmacs=[],
        stats=stats
    )
    
    # Create empty image stub
    image_emoji_stub = ImageEmojiStub(
        image={"error": error_message},
        emoji_summary=emoji_summary
    )
    
    # Create metadata
    metadata = MetadataInfo(
        request_id=request_id,
        timestamp=datetime.utcnow().isoformat() + 'Z',
        rag_enabled=False,
        has_media=False,
        has_file=False,
        file_info=None,
        prep_time_ms=prep_time_ms
    )
    
    logger.error(f"Error response created: {error_message}")
    
    return PreparedInput(
        text_embed_stub=text_embed_stub,
        image_emoji_stub=image_emoji_stub,
        metadata=metadata
    )


def validate_payload(prepared_input: PreparedInput) -> tuple[bool, Optional[str]]:
    """
    Validate a prepared payload before sending downstream.
    
    Checks for:
    - Valid request ID
    - Non-empty user input
    - Matching HMAC count with external chunks
    - Reasonable token estimates
    
    Args:
        prepared_input: PreparedInput object to validate
    
    Returns:
        Tuple of (is_valid, error_message)
    
    Example:
        >>> from app.models.schemas import PreparedInput, TextEmbedStub, ImageEmojiStub, MetadataInfo, StatsInfo, EmojiSummary
        >>> stats = StatsInfo(char_total=10, token_estimate=3, user_external_ratio=1.0, file_chunks_count=0, extracted_total_chars=0)
        >>> text_stub = TextEmbedStub(normalized_user="Test", normalized_external=[], emoji_descriptions=[], hmacs=[], stats=stats)
        >>> img_stub = ImageEmojiStub(image={}, emoji_summary=EmojiSummary(count=0, types=[], descriptions=[]))
        >>> metadata = MetadataInfo(request_id="test-123", timestamp="2024-01-01T00:00:00Z", rag_enabled=False, has_media=False, has_file=False, file_info=None, prep_time_ms=10.0)
        >>> prepared = PreparedInput(text_embed_stub=text_stub, image_emoji_stub=img_stub, metadata=metadata)
        >>> valid, error = validate_payload(prepared)
        >>> valid
        True
    """
    # Check request ID
    if not prepared_input.metadata.request_id:
        return False, "Missing request ID"
    
    # Check user input
    if not prepared_input.text_embed_stub.normalized_user:
        return False, "Empty user input"
    
    # Check HMAC count matches external chunks
    external_count = len(prepared_input.text_embed_stub.normalized_external)
    hmac_count = len(prepared_input.text_embed_stub.hmacs)
    
    if external_count != hmac_count:
        return False, f"HMAC count ({hmac_count}) doesn't match external chunks ({external_count})"
    
    # Check token estimate is reasonable
    if prepared_input.text_embed_stub.stats.token_estimate < 0:
        return False, "Invalid token estimate (negative)"
    
    # Check character count
    if prepared_input.text_embed_stub.stats.char_total < 0:
        return False, "Invalid character count (negative)"
    
    # Check ratio is between 0 and 1
    ratio = prepared_input.text_embed_stub.stats.user_external_ratio
    if not (0 <= ratio <= 1):
        return False, f"Invalid user/external ratio: {ratio}"
    
    return True, None


def summarize_payload(prepared_input: PreparedInput) -> str:
    """
    Create a human-readable summary of the prepared payload.
    
    Useful for logging and debugging.
    
    Args:
        prepared_input: PreparedInput object
    
    Returns:
        Summary string
    
    Example:
        >>> from app.models.schemas import PreparedInput, TextEmbedStub, ImageEmojiStub, MetadataInfo, StatsInfo, EmojiSummary
        >>> stats = StatsInfo(char_total=100, token_estimate=25, user_external_ratio=0.7, file_chunks_count=2, extracted_total_chars=50)
        >>> text_stub = TextEmbedStub(normalized_user="Test", normalized_external=["chunk1"], emoji_descriptions=[], hmacs=["sig1"], stats=stats)
        >>> img_stub = ImageEmojiStub(image={}, emoji_summary=EmojiSummary(count=1, types=['😀'], descriptions=[':grinning:']))
        >>> metadata = MetadataInfo(request_id="test-123", timestamp="2024-01-01T00:00:00Z", rag_enabled=True, has_media=False, has_file=True, file_info=None, prep_time_ms=45.5)
        >>> prepared = PreparedInput(text_embed_stub=text_stub, image_emoji_stub=img_stub, metadata=metadata)
        >>> summary = summarize_payload(prepared)
        >>> 'test-123' in summary
        True
    """
    m = prepared_input.metadata
    t = prepared_input.text_embed_stub
    i = prepared_input.image_emoji_stub
    
    summary_parts = [
        f"Request: {m.request_id}",
        f"Time: {m.prep_time_ms:.2f}ms",
        f"Tokens: {t.stats.token_estimate}",
        f"Chars: {t.stats.char_total}",
        f"External chunks: {len(t.normalized_external)}",
        f"RAG: {'Yes' if m.rag_enabled else 'No'}",
        f"File: {'Yes' if m.has_file else 'No'}",
        f"Media: {'Yes' if m.has_media else 'No'}",
        f"Emojis: {i.emoji_summary.count}"
    ]
    
    return " | ".join(summary_parts)

