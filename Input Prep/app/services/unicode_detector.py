"""
Unicode obfuscation detection service.

Detects zero-width characters, invisible characters, homoglyphs,
preserves raw text snapshots, and tracks Unicode normalization changes.
"""

import unicodedata
from typing import Tuple, Dict, List, Optional
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Zero-width and invisible characters to detect
ZERO_WIDTH_CHARS = {
    '\u200B',  # Zero Width Space
    '\u200C',  # Zero Width Non-Joiner
    '\u200D',  # Zero Width Joiner
    '\u2060',  # Word Joiner
    '\u2061',  # Function Application
    '\u2062',  # Invisible Times
    '\u2063',  # Invisible Separator
    '\u2064',  # Invisible Plus
    '\uFEFF',  # Zero Width No-Break Space (BOM)
    '\u180E',  # Mongolian Vowel Separator
}

# Additional suspicious invisible characters
INVISIBLE_CHARS = {
    '\u00A0',  # No-Break Space
    '\u1680',  # Ogham Space Mark
    '\u2000',  # En Quad
    '\u2001',  # Em Quad
    '\u2002',  # En Space
    '\u2003',  # Em Space
    '\u2004',  # Three-Per-Em Space
    '\u2005',  # Four-Per-Em Space
    '\u2006',  # Six-Per-Em Space
    '\u2007',  # Figure Space
    '\u2008',  # Punctuation Space
    '\u2009',  # Thin Space
    '\u200A',  # Hair Space
    '\u202F',  # Narrow No-Break Space
    '\u205F',  # Medium Mathematical Space
    '\u3000',  # Ideographic Space
}


class UnicodeAnalysisResult:
    """Results from Unicode obfuscation detection."""
    
    def __init__(
        self,
        original_text: str,
        normalized_text: str,
        zero_width_removed: str,
        special_char_mask: str,
        zero_width_found: bool,
        invisible_chars_found: bool,
        unicode_obfuscation_flag: bool,
        zero_width_count: int,
        invisible_count: int,
        zero_width_positions: List[int],
        unicode_diff: str,
        normalization_changes: int
    ):
        self.original_text = original_text
        self.normalized_text = normalized_text
        self.zero_width_removed = zero_width_removed
        self.special_char_mask = special_char_mask
        self.zero_width_found = zero_width_found
        self.invisible_chars_found = invisible_chars_found
        self.unicode_obfuscation_flag = unicode_obfuscation_flag
        self.zero_width_count = zero_width_count
        self.invisible_count = invisible_count
        self.zero_width_positions = zero_width_positions
        self.unicode_diff = unicode_diff
        self.normalization_changes = normalization_changes
    
    def to_dict(self) -> Dict:
        """Convert to dictionary format."""
        return {
            "original_text": self.original_text,
            "normalized_text": self.normalized_text,
            "zero_width_removed": self.zero_width_removed,
            "special_char_mask": self.special_char_mask,
            "zero_width_found": self.zero_width_found,
            "invisible_chars_found": self.invisible_chars_found,
            "unicode_obfuscation_flag": self.unicode_obfuscation_flag,
            "zero_width_count": self.zero_width_count,
            "invisible_count": self.invisible_count,
            "zero_width_positions": self.zero_width_positions,
            "unicode_diff": self.unicode_diff,
            "normalization_changes": self.normalization_changes
        }


def detect_zero_width_chars(text: str) -> Tuple[List[int], int]:
    """
    Detect zero-width characters in text.
    
    Args:
        text: Text to analyze
    
    Returns:
        Tuple of (positions, count) where zero-width chars were found
    """
    positions = []
    for i, char in enumerate(text):
        if char in ZERO_WIDTH_CHARS:
            positions.append(i)
    
    return positions, len(positions)


def detect_invisible_chars(text: str) -> Tuple[List[int], int]:
    """
    Detect invisible/suspicious space characters.
    
    Args:
        text: Text to analyze
    
    Returns:
        Tuple of (positions, count) where invisible chars were found
    """
    positions = []
    for i, char in enumerate(text):
        if char in INVISIBLE_CHARS:
            positions.append(i)
    
    return positions, len(positions)


def remove_zero_width_chars(text: str) -> str:
    """
    Remove all zero-width and invisible characters from text.
    
    Args:
        text: Text to clean
    
    Returns:
        Text with zero-width characters removed
    """
    result = []
    for char in text:
        if char not in ZERO_WIDTH_CHARS and char not in INVISIBLE_CHARS:
            result.append(char)
    
    return ''.join(result)


def create_special_char_mask(text: str) -> str:
    """
    Create a mask showing positions of special characters.
    
    Uses:
    - '.' for normal characters
    - 'Z' for zero-width characters
    - 'I' for invisible spaces
    - 'H' for potential homoglyphs (non-ASCII letters/digits)
    
    Args:
        text: Text to create mask for
    
    Returns:
        Mask string of same length as input
    """
    mask = []
    for char in text:
        if char in ZERO_WIDTH_CHARS:
            mask.append('Z')
        elif char in INVISIBLE_CHARS:
            mask.append('I')
        elif ord(char) > 127 and (char.isalpha() or char.isdigit()):
            # Potential homoglyph (non-ASCII letter/digit)
            mask.append('H')
        else:
            mask.append('.')
    
    return ''.join(mask)


def calculate_unicode_diff(original: str, normalized: str) -> str:
    """
    Calculate a compact representation of changes from Unicode normalization.
    
    Args:
        original: Original text before normalization
        normalized: Text after NFKC normalization
    
    Returns:
        Summary of differences
    """
    if original == normalized:
        return "no_changes"
    
    changes = []
    min_len = min(len(original), len(normalized))
    
    # Find positions where chars differ
    diff_positions = []
    for i in range(min_len):
        if original[i] != normalized[i]:
            diff_positions.append(i)
    
    # Check length difference
    len_diff = len(normalized) - len(original)
    
    diff_summary = f"changed_positions={len(diff_positions)}"
    if len_diff != 0:
        diff_summary += f",length_diff={len_diff}"
    
    # Sample up to 3 changes for inspection
    if diff_positions:
        samples = []
        for pos in diff_positions[:3]:
            orig_char = original[pos] if pos < len(original) else ''
            norm_char = normalized[pos] if pos < len(normalized) else ''
            samples.append(f"pos{pos}:'{orig_char}'=>'{norm_char}'")
        diff_summary += f",samples=[{','.join(samples)}]"
    
    return diff_summary


def analyze_unicode_obfuscation(text: str) -> UnicodeAnalysisResult:
    """
    Comprehensive Unicode obfuscation analysis.
    
    Performs:
    1. Raw text snapshot preservation
    2. Zero-width character detection and removal
    3. Invisible character detection
    4. Unicode normalization (NFKC)
    5. Special character mask generation
    6. Unicode diff calculation
    
    Args:
        text: Text to analyze
    
    Returns:
        UnicodeAnalysisResult with all analysis data
    """
    if not text:
        return UnicodeAnalysisResult(
            original_text="",
            normalized_text="",
            zero_width_removed="",
            special_char_mask="",
            zero_width_found=False,
            invisible_chars_found=False,
            unicode_obfuscation_flag=False,
            zero_width_count=0,
            invisible_count=0,
            zero_width_positions=[],
            unicode_diff="no_changes",
            normalization_changes=0
        )
    
    # Preserve raw snapshot
    original_text = text
    
    # Detect zero-width characters
    zw_positions, zw_count = detect_zero_width_chars(text)
    
    # Detect invisible characters
    inv_positions, inv_count = detect_invisible_chars(text)
    
    # Remove zero-width and invisible chars
    zero_width_removed = remove_zero_width_chars(text)
    
    # Create special character mask (on original text)
    special_char_mask = create_special_char_mask(text)
    
    # Unicode normalization (NFKC)
    normalized_text = unicodedata.normalize('NFKC', zero_width_removed)
    
    # Calculate Unicode diff
    unicode_diff = calculate_unicode_diff(zero_width_removed, normalized_text)
    
    # Count normalization changes
    normalization_changes = 0
    if zero_width_removed != normalized_text:
        normalization_changes = sum(
            1 for a, b in zip(zero_width_removed, normalized_text) if a != b
        )
        # Account for length differences
        normalization_changes += abs(len(normalized_text) - len(zero_width_removed))
    
    # Determine flags
    zero_width_found = zw_count > 0
    invisible_chars_found = inv_count > 0
    
    # Unicode obfuscation flag: triggered if many changes or zero-width found
    unicode_obfuscation_flag = (
        zero_width_found or 
        invisible_chars_found or 
        normalization_changes > 5 or
        (normalization_changes > 0 and len(text) > 0 and normalization_changes / len(text) > 0.05)
    )
    
    logger.debug(
        f"Unicode analysis: zw={zw_count}, inv={inv_count}, "
        f"norm_changes={normalization_changes}, obfuscation={unicode_obfuscation_flag}"
    )
    
    return UnicodeAnalysisResult(
        original_text=original_text,
        normalized_text=normalized_text,
        zero_width_removed=zero_width_removed,
        special_char_mask=special_char_mask,
        zero_width_found=zero_width_found,
        invisible_chars_found=invisible_chars_found,
        unicode_obfuscation_flag=unicode_obfuscation_flag,
        zero_width_count=zw_count,
        invisible_count=inv_count,
        zero_width_positions=zw_positions,
        unicode_diff=unicode_diff,
        normalization_changes=normalization_changes
    )


def batch_analyze_texts(texts: List[str]) -> List[UnicodeAnalysisResult]:
    """
    Analyze multiple texts for Unicode obfuscation.
    
    Args:
        texts: List of texts to analyze
    
    Returns:
        List of UnicodeAnalysisResult objects
    """
    results = []
    for text in texts:
        result = analyze_unicode_obfuscation(text)
        results.append(result)
    
    return results
