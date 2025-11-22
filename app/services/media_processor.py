"""
Media processing service.

Handles image processing (metadata extraction, hash calculation)
and emoji processing (extraction, description, summary).
"""

import os
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any
from app.utils.hmac_utils import hash_bytes_sha256, hash_file_sha256
from app.utils.logger import get_logger
from app.models.schemas import ImageInfo, EmojiSummary

logger = get_logger(__name__)

# Try to import Pillow with graceful fallback
try:
    from PIL import Image
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False
    logger.warning("Pillow not available. Image processing will be disabled.")


def check_image_library_availability() -> bool:
    """
    Check if image processing library (Pillow) is available.
    
    Returns:
        True if Pillow is available, False otherwise
    """
    return PILLOW_AVAILABLE


def extract_image_metadata(image_path: str) -> ImageInfo:
    """
    Extract metadata from an image file.
    
    Args:
        image_path: Path to the image file
    
    Returns:
        ImageInfo object with metadata
    
    Raises:
        ImportError: If Pillow is not available
        FileNotFoundError: If image file doesn't exist
        Exception: For image processing errors
    
    Example:
        >>> info = extract_image_metadata("example.png")
        >>> info.format
        'PNG'
    """
    if not PILLOW_AVAILABLE:
        raise ImportError("Pillow is not installed. Install with: pip install Pillow")
    
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Image not found: {image_path}")
    
    # Calculate file hash
    file_hash = hash_file_sha256(image_path)
    
    # Get file size
    file_size = os.path.getsize(image_path)
    
    # Open image and extract metadata
    try:
        with Image.open(image_path) as img:
            image_format = img.format or "unknown"
            dimensions = img.size  # (width, height)
            
            logger.debug(
                f"Image metadata: format={image_format}, "
                f"dimensions={dimensions}, size={file_size}"
            )
    except Exception as e:
        logger.error(f"Failed to open image: {e}")
        raise
    
    return ImageInfo(
        hash=file_hash,
        format=image_format.lower(),
        size_bytes=file_size,
        dimensions=dimensions,
        description=None  # Placeholder for AI-generated description
    )


def extract_image_metadata_from_bytes(
    image_bytes: bytes,
    filename: str = "image"
) -> ImageInfo:
    """
    Extract metadata from image bytes.
    
    Args:
        image_bytes: Raw image data
        filename: Optional filename for context
    
    Returns:
        ImageInfo object with metadata
    
    Raises:
        ImportError: If Pillow is not available
        Exception: For image processing errors
    """
    if not PILLOW_AVAILABLE:
        raise ImportError("Pillow is not installed. Install with: pip install Pillow")
    
    # Calculate hash
    file_hash = hash_bytes_sha256(image_bytes)
    file_size = len(image_bytes)
    
    # Open image from bytes
    try:
        from io import BytesIO
        with Image.open(BytesIO(image_bytes)) as img:
            image_format = img.format or "unknown"
            dimensions = img.size
            
            logger.debug(
                f"Image metadata (from bytes): format={image_format}, "
                f"dimensions={dimensions}, size={file_size}"
            )
    except Exception as e:
        logger.error(f"Failed to process image bytes: {e}")
        raise
    
    return ImageInfo(
        hash=file_hash,
        format=image_format.lower(),
        size_bytes=file_size,
        dimensions=dimensions,
        description=None
    )


def check_steganography_placeholder(image_path: str) -> Dict[str, Any]:
    """
    Placeholder for steganography detection.
    
    This is a stub for future implementation of steganography detection.
    
    Args:
        image_path: Path to the image file
    
    Returns:
        Dictionary with detection results
    
    Note:
        Future implementation could use:
        - Statistical analysis of LSB (Least Significant Bit)
        - Frequency domain analysis
        - ML-based steganography detection
    
    Example:
        >>> result = check_steganography_placeholder("image.png")
        >>> result['implemented']
        False
    """
    logger.info(f"Steganography check requested for {image_path} (not yet implemented)")
    
    return {
        "implemented": False,
        "suspicious": False,
        "confidence": 0.0,
        "message": "Steganography detection not yet implemented"
    }


def validate_image(image_path: str, max_size_mb: int = 10) -> Tuple[bool, Optional[str]]:
    """
    Validate an image file before processing.
    
    Args:
        image_path: Path to the image file
        max_size_mb: Maximum allowed file size in MB
    
    Returns:
        Tuple of (is_valid, error_message)
    
    Example:
        >>> valid, error = validate_image("example.png")
        >>> valid
        True
    """
    # Check existence
    if not os.path.exists(image_path):
        return False, f"Image not found: {image_path}"
    
    if not os.path.isfile(image_path):
        return False, f"Not a file: {image_path}"
    
    # Check size
    file_size = os.path.getsize(image_path)
    max_size_bytes = max_size_mb * 1024 * 1024
    if file_size > max_size_bytes:
        size_mb = file_size / (1024 * 1024)
        return False, f"Image too large: {size_mb:.2f}MB (max: {max_size_mb}MB)"
    
    # Check if it's a valid image
    if PILLOW_AVAILABLE:
        try:
            with Image.open(image_path) as img:
                img.verify()  # Verify it's a valid image
        except Exception as e:
            return False, f"Invalid or corrupted image: {e}"
    else:
        # Without Pillow, just check common image extensions
        ext = Path(image_path).suffix.lower()
        if ext not in {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp'}:
            return False, f"Unsupported image format: {ext}"
    
    return True, None


def create_emoji_summary(
    emojis: List[str],
    descriptions: List[str]
) -> EmojiSummary:
    """
    Create an emoji summary from extracted emojis and descriptions.
    
    Args:
        emojis: List of emoji characters
        descriptions: List of emoji descriptions
    
    Returns:
        EmojiSummary object
    
    Example:
        >>> summary = create_emoji_summary(['😀', '🌍'], [':grinning:', ':globe:'])
        >>> summary.count
        2
    """
    return EmojiSummary(
        count=len(emojis),
        types=emojis,
        descriptions=descriptions
    )


def process_media(
    image_path: Optional[str] = None,
    image_bytes: Optional[bytes] = None,
    emojis: Optional[List[str]] = None,
    emoji_descriptions: Optional[List[str]] = None
) -> Tuple[Dict[str, Any], EmojiSummary]:
    """
    Process media (images and emojis) and return structured data.
    
    Args:
        image_path: Optional path to image file
        image_bytes: Optional raw image bytes
        emojis: Optional list of emoji characters
        emoji_descriptions: Optional list of emoji descriptions
    
    Returns:
        Tuple of (image_dict, emoji_summary)
    
    Example:
        >>> img_dict, emoji_sum = process_media(
        ...     image_path="test.png",
        ...     emojis=['😀'],
        ...     emoji_descriptions=[':grinning:']
        ... )
        >>> emoji_sum.count
        1
    """
    # Process image
    image_dict = {}
    if image_path:
        try:
            valid, error = validate_image(image_path)
            if not valid:
                logger.warning(f"Invalid image: {error}")
                image_dict = {"error": error}
            else:
                image_info = extract_image_metadata(image_path)
                image_dict = {
                    "hash": image_info.hash,
                    "format": image_info.format,
                    "size_bytes": image_info.size_bytes,
                    "dimensions": image_info.dimensions,
                    "description": image_info.description,
                }
                logger.info(f"Processed image: {image_info.format}, {image_info.dimensions}")
        except Exception as e:
            logger.error(f"Error processing image: {e}")
            image_dict = {"error": str(e)}
    
    elif image_bytes:
        try:
            image_info = extract_image_metadata_from_bytes(image_bytes)
            image_dict = {
                "hash": image_info.hash,
                "format": image_info.format,
                "size_bytes": image_info.size_bytes,
                "dimensions": image_info.dimensions,
                "description": image_info.description,
            }
            logger.info(f"Processed image bytes: {image_info.format}, {image_info.dimensions}")
        except Exception as e:
            logger.error(f"Error processing image bytes: {e}")
            image_dict = {"error": str(e)}
    
    # Process emojis
    if emojis is None:
        emojis = []
    if emoji_descriptions is None:
        emoji_descriptions = []
    
    emoji_summary = create_emoji_summary(emojis, emoji_descriptions)
    
    logger.debug(
        f"Media processing complete: "
        f"image={'present' if image_dict else 'absent'}, "
        f"emojis={emoji_summary.count}"
    )
    
    return image_dict, emoji_summary


def generate_image_description_placeholder(image_path: str) -> str:
    """
    Placeholder for AI-generated image description.
    
    Future implementation could use:
    - CLIP (OpenAI)
    - BLIP (Salesforce)
    - LLaVA (Local multimodal model)
    
    Args:
        image_path: Path to the image
    
    Returns:
        Description string (currently a placeholder)
    
    Example:
        >>> desc = generate_image_description_placeholder("test.png")
        >>> isinstance(desc, str)
        True
    """
    logger.info(f"Image description requested for {image_path} (not yet implemented)")
    return "Image description not yet implemented"

