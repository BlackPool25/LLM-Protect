"""
Text normalization service.

Normalizes text by cleaning whitespace, normalizing Unicode,
and handling emoji extraction and description.
"""

import re
import unicodedata
from typing import List, Tuple, Dict
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Try to import emoji library with graceful fallback
try:
    import emoji
    EMOJI_AVAILABLE = True
except ImportError:
    EMOJI_AVAILABLE = False
    logger.warning("emoji library not available. Emoji processing will be limited.")


def normalize_whitespace(text: str) -> str:
    """
    Normalize whitespace in text.
    
    - Replace multiple spaces with single space
    - Replace multiple newlines with single newline
    - Strip leading/trailing whitespace
    
    Args:
        text: Text to normalize
    
    Returns:
        Text with normalized whitespace
    
    Example:
        >>> normalize_whitespace("Hello    world\\n\\n\\nTest")
        'Hello world\\nTest'
    """
    # Replace multiple spaces with single space
    text = re.sub(r' +', ' ', text)
    
    # Replace multiple newlines with single newline
    text = re.sub(r'\n\n+', '\n', text)
    
    # Replace tabs with spaces
    text = text.replace('\t', ' ')
    
    # Strip leading/trailing whitespace
    text = text.strip()
    
    return text


def normalize_unicode(text: str) -> str:
    """
    Normalize Unicode characters to standard form.
    
    Uses NFKC normalization to handle compatibility characters.
    
    Args:
        text: Text to normalize
    
    Returns:
        Unicode-normalized text
    
    Example:
        >>> normalize_unicode("Café")  # Different representations of é
        'Café'
    """
    # NFKC: Compatibility decomposition followed by canonical composition
    # This handles things like ligatures, different dash types, etc.
    return unicodedata.normalize('NFKC', text)


def extract_emojis(text: str) -> List[str]:
    """
    Extract all emojis from text.
    
    Args:
        text: Text containing emojis
    
    Returns:
        List of unique emojis found
    
    Example:
        >>> extract_emojis("Hello 😀 World 🌍!")
        ['😀', '🌍']
    """
    if not EMOJI_AVAILABLE:
        # Fallback: Simple regex for common emoji ranges
        emoji_pattern = re.compile(
            "["
            "\U0001F600-\U0001F64F"  # emoticons
            "\U0001F300-\U0001F5FF"  # symbols & pictographs
            "\U0001F680-\U0001F6FF"  # transport & map
            "\U0001F700-\U0001F77F"  # alchemical symbols
            "\U0001F780-\U0001F7FF"  # Geometric Shapes Extended
            "\U0001F800-\U0001F8FF"  # Supplemental Arrows-C
            "\U0001F900-\U0001F9FF"  # Supplemental Symbols and Pictographs
            "\U0001FA00-\U0001FA6F"  # Chess Symbols
            "\U0001FA70-\U0001FAFF"  # Symbols and Pictographs Extended-A
            "\U00002702-\U000027B0"  # Dingbats
            "\U000024C2-\U0001F251"
            "]+"
        )
        found_emojis = emoji_pattern.findall(text)
        return list(set(found_emojis))
    
    # Use emoji library if available
    emojis = []
    for char in text:
        if emoji.is_emoji(char):
            emojis.append(char)
    
    return list(set(emojis))


def demojize_text(text: str) -> str:
    """
    Replace emojis with their text descriptions.
    
    Args:
        text: Text containing emojis
    
    Returns:
        Text with emojis replaced by descriptions
    
    Example:
        >>> demojize_text("Hello 😀")
        'Hello :grinning_face:'
    """
    if not EMOJI_AVAILABLE:
        # Simple fallback: just remove emojis
        emoji_pattern = re.compile(
            "["
            "\U0001F600-\U0001F64F"
            "\U0001F300-\U0001F5FF"
            "\U0001F680-\U0001F6FF"
            "\U0001F700-\U0001F77F"
            "\U0001F780-\U0001F7FF"
            "\U0001F800-\U0001F8FF"
            "\U0001F900-\U0001F9FF"
            "\U0001FA00-\U0001FA6F"
            "\U0001FA70-\U0001FAFF"
            "\U00002702-\U000027B0"
            "\U000024C2-\U0001F251"
            "]+"
        )
        return emoji_pattern.sub('', text)
    
    return emoji.demojize(text)


def get_emoji_descriptions(emojis: List[str]) -> List[str]:
    """
    Get text descriptions for emojis.
    
    Args:
        emojis: List of emoji characters
    
    Returns:
        List of text descriptions
    
    Example:
        >>> get_emoji_descriptions(['😀', '🌍'])
        [':grinning_face:', ':globe_showing_Europe-Africa:']
    """
    if not EMOJI_AVAILABLE:
        return [f"emoji_{i}" for i in range(len(emojis))]
    
    descriptions = []
    for em in emojis:
        try:
            desc = emoji.demojize(em)
            descriptions.append(desc)
        except Exception:
            descriptions.append(f"unknown_emoji")
    
    return descriptions


def remove_control_characters(text: str) -> str:
    """
    Remove control characters from text.
    
    Keeps newlines and tabs but removes other control characters.
    
    Args:
        text: Text to clean
    
    Returns:
        Text without control characters
    
    Example:
        >>> remove_control_characters("Hello\\x00World")
        'HelloWorld'
    """
    # Keep newline, carriage return, and tab
    return ''.join(
        char for char in text
        if unicodedata.category(char)[0] != 'C' or char in '\n\r\t'
    )


def normalize_text(text: str, preserve_emojis: bool = True) -> Tuple[str, List[str], List[str]]:
    """
    Normalize text with comprehensive cleaning.
    
    Performs:
    - Unicode normalization
    - Whitespace normalization
    - Control character removal
    - Emoji extraction (optional)
    
    Args:
        text: Text to normalize
        preserve_emojis: If True, keep emojis; if False, convert to descriptions
    
    Returns:
        Tuple of (normalized_text, emoji_list, emoji_descriptions)
    
    Example:
        >>> normalized, emojis, descs = normalize_text("Hello  😀  World!")
        >>> "Hello" in normalized
        True
        >>> len(emojis) > 0
        True
    """
    if not text:
        return "", [], []
    
    # Extract emojis before normalization
    emojis = extract_emojis(text)
    emoji_descriptions = get_emoji_descriptions(emojis)
    
    # Remove control characters
    text = remove_control_characters(text)
    
    # Normalize Unicode
    text = normalize_unicode(text)
    
    # Normalize whitespace
    text = normalize_whitespace(text)
    
    # Handle emojis
    if not preserve_emojis and emojis:
        text = demojize_text(text)
        # Clean up any extra whitespace from emoji removal
        text = normalize_whitespace(text)
    
    logger.debug(
        f"Normalized text: {len(text)} chars, "
        f"{len(emojis)} emojis extracted"
    )
    
    return text, emojis, emoji_descriptions


def normalize_text_with_source(
    text: str,
    source: str,
    preserve_emojis: bool = True
) -> Dict[str, any]:
    """
    Normalize text and preserve source metadata.
    
    Useful for tracking which chunk came from which source.
    
    Args:
        text: Text to normalize
        source: Source identifier (e.g., "user", "file_chunk_0", "external")
        preserve_emojis: If True, keep emojis; if False, convert to descriptions
    
    Returns:
        Dictionary with normalized text, emojis, descriptions, and source
    
    Example:
        >>> result = normalize_text_with_source("Hello 😀", "user")
        >>> result['source']
        'user'
        >>> 'normalized' in result
        True
    """
    normalized, emojis, emoji_descs = normalize_text(text, preserve_emojis)
    
    return {
        "normalized": normalized,
        "emojis": emojis,
        "emoji_descriptions": emoji_descs,
        "source": source,
        "original_length": len(text),
        "normalized_length": len(normalized),
    }


def batch_normalize(
    texts: List[str],
    sources: List[str] = None,
    preserve_emojis: bool = True
) -> List[Dict[str, any]]:
    """
    Normalize multiple texts in batch.
    
    Args:
        texts: List of texts to normalize
        sources: Optional list of source identifiers
        preserve_emojis: If True, keep emojis; if False, convert to descriptions
    
    Returns:
        List of normalization results
    
    Example:
        >>> results = batch_normalize(["Text 1", "Text 2"])
        >>> len(results) == 2
        True
    """
    if sources is None:
        sources = [f"text_{i}" for i in range(len(texts))]
    
    if len(texts) != len(sources):
        raise ValueError("texts and sources must have the same length")
    
    results = []
    for text, source in zip(texts, sources):
        result = normalize_text_with_source(text, source, preserve_emojis)
        results.append(result)
    
    logger.debug(f"Batch normalized {len(texts)} texts")
    return results

