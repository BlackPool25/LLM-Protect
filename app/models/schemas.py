"""
Pydantic data models for request/response validation.

These schemas define the structure of data flowing through the input preparation pipeline.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
from datetime import datetime


class FileChunk(BaseModel):
    """A chunk of extracted text from a file."""
    content: str = Field(..., description="The text content of the chunk")
    source: str = Field(..., description="Source file path")
    hash: str = Field(..., description="SHA256 hash of the original file")
    chunk_id: int = Field(..., description="Sequential chunk identifier")


class StatsInfo(BaseModel):
    """Statistics about the processed input."""
    char_total: int = Field(..., description="Total character count")
    token_estimate: int = Field(..., description="Estimated token count")
    user_external_ratio: float = Field(..., description="Ratio of user text to external data")
    file_chunks_count: int = Field(0, description="Number of file chunks")
    extracted_total_chars: int = Field(0, description="Total characters extracted from files")


class FileInfo(BaseModel):
    """Information about a processed file."""
    original_path: str = Field(..., description="Original file path or name")
    hash: str = Field(..., description="SHA256 hash of the file")
    type: str = Field(..., description="File extension (pdf, docx, txt, md)")
    chunk_count: int = Field(..., description="Number of chunks created")
    extraction_success: bool = Field(..., description="Whether extraction succeeded")
    extraction_error: Optional[str] = Field(None, description="Error message if extraction failed")


class ImageInfo(BaseModel):
    """Information about a processed image."""
    hash: str = Field(..., description="SHA256 hash of the image")
    format: str = Field(..., description="Image format (png, jpg, etc.)")
    size_bytes: int = Field(..., description="Image size in bytes")
    dimensions: Optional[tuple[int, int]] = Field(None, description="Width and height in pixels")
    description: Optional[str] = Field(None, description="AI-generated description placeholder")


class EmojiSummary(BaseModel):
    """Summary of emojis found in text."""
    count: int = Field(..., description="Total number of emojis")
    types: List[str] = Field(..., description="List of unique emoji characters")
    descriptions: List[str] = Field(..., description="Text descriptions of emojis")


class TextEmbedStub(BaseModel):
    """
    Data stub for text and embedding processing (Layer 0).
    Contains normalized text with HMAC signatures.
    """
    normalized_user: str = Field(..., description="Normalized user prompt")
    normalized_external: List[str] = Field(
        default_factory=list,
        description="List of normalized external data chunks with [EXTERNAL] delimiters"
    )
    emoji_descriptions: List[str] = Field(
        default_factory=list,
        description="Text descriptions of emojis found in input"
    )
    hmacs: List[str] = Field(
        default_factory=list,
        description="HMAC signatures for each external chunk"
    )
    stats: StatsInfo = Field(..., description="Statistics about the input")


class ImageEmojiStub(BaseModel):
    """
    Data stub for image and emoji processing.
    Contains media metadata for specialized analysis.
    """
    image: Dict[str, Any] = Field(
        default_factory=dict,
        description="Image metadata (hash, format, size, etc.)"
    )
    emoji_summary: EmojiSummary = Field(
        default_factory=lambda: EmojiSummary(count=0, types=[], descriptions=[]),
        description="Summary of emojis in the input"
    )


class MetadataInfo(BaseModel):
    """Metadata about the request and processing."""
    request_id: str = Field(..., description="Unique request identifier (UUID)")
    timestamp: str = Field(..., description="ISO 8601 timestamp")
    session_id: Optional[str] = Field(None, description="Conversation session identifier (UUID)")
    rag_enabled: bool = Field(..., description="Whether RAG/external data was used")
    has_media: bool = Field(..., description="Whether media (images) were included")
    has_file: bool = Field(..., description="Whether files were uploaded")
    file_info: Optional[FileInfo] = Field(None, description="Information about uploaded file")
    prep_time_ms: float = Field(..., description="Total preparation time in milliseconds")
    step_times: Optional[Dict[str, float]] = Field(
        None,
        description="Breakdown of time per processing step"
    )


class PreparedInput(BaseModel):
    """
    Final prepared input ready for downstream processing.
    This is the main output format of the input preparation module.
    """
    text_embed_stub: TextEmbedStub = Field(..., description="Data for Layer 0 (text processing)")
    image_emoji_stub: ImageEmojiStub = Field(..., description="Data for media processing")
    metadata: MetadataInfo = Field(..., description="Request metadata and timing")


# Request models for API endpoints

class InputRequest(BaseModel):
    """Request model for text preparation endpoint."""
    user_prompt: str = Field(..., description="The user's input text", min_length=1)
    external_data: Optional[List[str]] = Field(
        None,
        description="Optional list of external data strings (RAG)"
    )
    retrieve_from_vector_db: bool = Field(
        False,
        description="Whether to retrieve additional context from vector database"
    )
    
    @field_validator('user_prompt')
    @classmethod
    def validate_user_prompt(cls, v: str) -> str:
        """Validate that user prompt is not empty or just whitespace."""
        if not v or not v.strip():
            raise ValueError("user_prompt cannot be empty or whitespace only")
        return v


class MediaRequest(BaseModel):
    """Request model for media preparation endpoint."""
    user_prompt: str = Field(..., description="The user's input text", min_length=1)
    
    @field_validator('user_prompt')
    @classmethod
    def validate_user_prompt(cls, v: str) -> str:
        """Validate that user prompt is not empty or just whitespace."""
        if not v or not v.strip():
            raise ValueError("user_prompt cannot be empty or whitespace only")
        return v


class HealthResponse(BaseModel):
    """Response model for health check endpoint."""
    status: str = Field(..., description="Service status")
    version: str = Field(..., description="API version")
    timestamp: str = Field(..., description="Current server timestamp")
    libraries: Dict[str, bool] = Field(..., description="Availability of required libraries")
    message: Optional[str] = Field(None, description="Additional status message")

