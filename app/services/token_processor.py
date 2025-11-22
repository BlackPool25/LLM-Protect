"""
Token processing and statistics calculation service.

Estimates token counts and calculates various statistics about the input data.
"""

from typing import List, Dict, Optional
from app.config import settings
from app.models.schemas import StatsInfo
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Try to import tiktoken for accurate token counting
try:
    import tiktoken
    TIKTOKEN_AVAILABLE = True
    # Initialize tokenizer for GPT-style models (commonly used)
    try:
        TOKENIZER = tiktoken.get_encoding("cl100k_base")  # GPT-4, GPT-3.5-turbo
    except Exception:
        TOKENIZER = None
        TIKTOKEN_AVAILABLE = False
except ImportError:
    TIKTOKEN_AVAILABLE = False
    TOKENIZER = None
    logger.warning("tiktoken not available. Using character-based token estimation.")


def estimate_tokens_simple(text: str) -> int:
    """
    Simple token estimation based on character count.
    
    Uses rough approximation: 1 token ≈ 4 characters
    
    Args:
        text: Text to estimate tokens for
    
    Returns:
        Estimated token count
    
    Example:
        >>> estimate_tokens_simple("Hello world")
        3
    """
    if not text:
        return 0
    
    # Remove excessive whitespace for more accurate estimate
    text = ' '.join(text.split())
    
    # Rough approximation: 1 token ≈ 4 characters
    return len(text) // settings.CHARS_PER_TOKEN


def estimate_tokens_accurate(text: str) -> int:
    """
    Accurate token estimation using tiktoken.
    
    Falls back to simple estimation if tiktoken is not available.
    
    Args:
        text: Text to estimate tokens for
    
    Returns:
        Estimated token count
    
    Example:
        >>> estimate_tokens_accurate("Hello world")  # doctest: +SKIP
        2
    """
    if not text:
        return 0
    
    if TIKTOKEN_AVAILABLE and TOKENIZER:
        try:
            tokens = TOKENIZER.encode(text)
            return len(tokens)
        except Exception as e:
            logger.warning(f"tiktoken encoding failed: {e}. Using simple estimation.")
            return estimate_tokens_simple(text)
    else:
        return estimate_tokens_simple(text)


def estimate_tokens(text: str, accurate: bool = True) -> int:
    """
    Estimate token count for text.
    
    Args:
        text: Text to estimate tokens for
        accurate: Use accurate estimation (tiktoken) if available
    
    Returns:
        Estimated token count
    
    Example:
        >>> estimate_tokens("Hello world")
        2
    """
    if accurate and TIKTOKEN_AVAILABLE:
        return estimate_tokens_accurate(text)
    else:
        return estimate_tokens_simple(text)


def count_characters(text: str) -> int:
    """
    Count characters in text.
    
    Args:
        text: Text to count
    
    Returns:
        Character count
    """
    return len(text) if text else 0


def calculate_ratio(user_text: str, external_text: str) -> float:
    """
    Calculate ratio of user text to external data.
    
    Args:
        user_text: User's input text
        external_text: Combined external data text
    
    Returns:
        Ratio (user_chars / total_chars), or 1.0 if no external data
    
    Example:
        >>> calculate_ratio("Hello", "World")
        0.5
    """
    user_chars = count_characters(user_text)
    external_chars = count_characters(external_text)
    total_chars = user_chars + external_chars
    
    if total_chars == 0:
        return 0.0
    
    if external_chars == 0:
        return 1.0
    
    return round(user_chars / total_chars, 3)


def calculate_tokens_and_stats(
    user_text: str,
    external_chunks: List[str],
    file_chunks_count: int = 0,
    extracted_total_chars: int = 0,
    accurate: bool = True
) -> StatsInfo:
    """
    Calculate comprehensive statistics for the input.
    
    Args:
        user_text: Normalized user input text
        external_chunks: List of external data chunks (already delimited)
        file_chunks_count: Number of chunks extracted from files
        extracted_total_chars: Total characters extracted from files
        accurate: Use accurate token estimation if available
    
    Returns:
        StatsInfo object with all statistics
    
    Example:
        >>> stats = calculate_tokens_and_stats("Hello", ["World", "!"])
        >>> stats.char_total > 0
        True
    """
    # Count characters
    user_chars = count_characters(user_text)
    
    # Combine external chunks (remove delimiters for char count)
    external_text = ' '.join(external_chunks)
    external_chars = count_characters(external_text)
    
    total_chars = user_chars + external_chars
    
    # Estimate tokens
    user_tokens = estimate_tokens(user_text, accurate)
    external_tokens = sum(estimate_tokens(chunk, accurate) for chunk in external_chunks)
    total_tokens = user_tokens + external_tokens
    
    # Calculate ratio
    ratio = calculate_ratio(user_text, external_text)
    
    logger.debug(
        f"Stats calculated: {total_chars} chars, {total_tokens} tokens, "
        f"ratio={ratio:.3f}, file_chunks={file_chunks_count}"
    )
    
    return StatsInfo(
        char_total=total_chars,
        token_estimate=total_tokens,
        user_external_ratio=ratio,
        file_chunks_count=file_chunks_count,
        extracted_total_chars=extracted_total_chars
    )


def create_position_map(
    user_text: str,
    external_chunks: List[str]
) -> Dict[str, Dict[str, int]]:
    """
    Create a position map showing where each component is in the combined text.
    
    Useful for tracking source of different parts of the input.
    
    Args:
        user_text: User input text
        external_chunks: List of external data chunks
    
    Returns:
        Dictionary mapping component names to position ranges
    
    Example:
        >>> pos_map = create_position_map("Hello", ["World"])
        >>> 'user' in pos_map
        True
        >>> pos_map['user']['start']
        0
    """
    position_map = {}
    current_pos = 0
    
    # User text position
    user_len = len(user_text)
    position_map['user'] = {
        'start': current_pos,
        'end': current_pos + user_len,
        'length': user_len
    }
    current_pos += user_len
    
    # External chunks positions
    for i, chunk in enumerate(external_chunks):
        chunk_len = len(chunk)
        position_map[f'external_{i}'] = {
            'start': current_pos,
            'end': current_pos + chunk_len,
            'length': chunk_len
        }
        current_pos += chunk_len
    
    position_map['total_length'] = current_pos
    
    logger.debug(f"Position map created: {len(external_chunks)} external chunks")
    
    return position_map


def analyze_input_complexity(
    user_text: str,
    external_chunks: List[str],
    stats: StatsInfo
) -> Dict[str, any]:
    """
    Analyze the complexity of the input.
    
    Provides insights like:
    - Average chunk size
    - Complexity score
    - External data ratio
    
    Args:
        user_text: User input text
        external_chunks: List of external data chunks
        stats: StatsInfo object
    
    Returns:
        Dictionary with complexity analysis
    
    Example:
        >>> from app.models.schemas import StatsInfo
        >>> stats = StatsInfo(
        ...     char_total=100, token_estimate=25,
        ...     user_external_ratio=0.5, file_chunks_count=2,
        ...     extracted_total_chars=50
        ... )
        >>> analysis = analyze_input_complexity("Test", ["Chunk1", "Chunk2"], stats)
        >>> 'complexity_score' in analysis
        True
    """
    # Calculate average chunk size
    if external_chunks:
        avg_chunk_size = sum(len(c) for c in external_chunks) / len(external_chunks)
    else:
        avg_chunk_size = 0
    
    # Calculate complexity score (0-10 scale)
    # Factors: token count, number of chunks, ratio
    token_factor = min(stats.token_estimate / 100, 3)  # 0-3
    chunk_factor = min(len(external_chunks) / 5, 3)    # 0-3
    ratio_factor = abs(stats.user_external_ratio - 0.5) * 4  # 0-2 (penalty for imbalance)
    file_factor = min(stats.file_chunks_count / 5, 2)  # 0-2
    
    complexity_score = token_factor + chunk_factor + ratio_factor + file_factor
    complexity_score = round(min(complexity_score, 10), 2)
    
    return {
        'complexity_score': complexity_score,
        'avg_chunk_size': round(avg_chunk_size, 2),
        'num_external_chunks': len(external_chunks),
        'has_files': stats.file_chunks_count > 0,
        'external_data_ratio': round(1 - stats.user_external_ratio, 3),
        'interpretation': _interpret_complexity(complexity_score)
    }


def _interpret_complexity(score: float) -> str:
    """
    Interpret complexity score into human-readable description.
    
    Args:
        score: Complexity score (0-10)
    
    Returns:
        Description string
    """
    if score < 2:
        return "Simple input"
    elif score < 4:
        return "Moderate complexity"
    elif score < 6:
        return "Complex input"
    elif score < 8:
        return "Highly complex input"
    else:
        return "Very complex input with extensive external data"


def get_token_statistics_summary(stats: StatsInfo) -> str:
    """
    Get a human-readable summary of token statistics.
    
    Args:
        stats: StatsInfo object
    
    Returns:
        Summary string
    
    Example:
        >>> from app.models.schemas import StatsInfo
        >>> stats = StatsInfo(
        ...     char_total=100, token_estimate=25,
        ...     user_external_ratio=0.7, file_chunks_count=2,
        ...     extracted_total_chars=30
        ... )
        >>> summary = get_token_statistics_summary(stats)
        >>> 'tokens' in summary
        True
    """
    return (
        f"Total: {stats.char_total} chars, ~{stats.token_estimate} tokens | "
        f"User/External ratio: {stats.user_external_ratio:.1%} | "
        f"File chunks: {stats.file_chunks_count} "
        f"({stats.extracted_total_chars} chars)"
    )

