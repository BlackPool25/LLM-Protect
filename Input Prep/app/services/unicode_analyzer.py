"""
Unicode analysis service.

Detects zero-width characters, invisible characters, and Unicode obfuscation.
Generates special character masks and tracks normalization changes.
"""

import unicodedata
import re
from typing import List, Tuple, Dict
from app.models.schemas import UnicodeAnalysis
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Zero-width characters
ZERO_WIDTH_CHARS = {
    '\u200B',  # ZERO WIDTH SPACE
    '\u200C',  # ZERO WIDTH NON-JOINER
    '\u200D',  # ZERO WIDTH JOINER
    '\u2060',  # WORD JOINER
    '\uFEFF',  # ZERO WIDTH NO-BREAK SPACE (BOM)
}

# Invisible/suspicious characters
INVISIBLE_CHARS = {
    '\u180E',  # MONGOLIAN VOWEL SEPARATOR
    '\u200E',  # LEFT-TO-RIGHT MARK
    '\u200F',  # RIGHT-TO-LEFT MARK
    '\u202A',  # LEFT-TO-RIGHT EMBEDDING
    '\u202B',  # RIGHT-TO-LEFT EMBEDDING
    '\u202C',  # POP DIRECTIONAL FORMATTING
    '\u202D',  # LEFT-TO-RIGHT OVERRIDE
    '\u202E',  # RIGHT-TO-LEFT OVERRIDE
    '\u2061',  # FUNCTION APPLICATION
    '\u2062',  # INVISIBLE TIMES
    '\u2063',  # INVISIBLE SEPARATOR
    '\u2064',  # INVISIBLE PLUS
    '\u206A',  # INHIBIT SYMMETRIC SWAPPING
    '\u206B',  # ACTIVATE SYMMETRIC SWAPPING
    '\u206C',  # INHIBIT ARABIC FORM SHAPING
    '\u206D',  # ACTIVATE ARABIC FORM SHAPING
    '\u206E',  # NATIONAL DIGIT SHAPES
    '\u206F',  # NOMINAL DIGIT SHAPES
}

# Homoglyphs (common substitutions)
HOMOGLYPH_PATTERNS = {
    'а': 'a',  # Cyrillic 'a' -> Latin 'a'
    'е': 'e',  # Cyrillic 'e' -> Latin 'e'
    'о': 'o',  # Cyrillic 'o' -> Latin 'o'
    'р': 'p',  # Cyrillic 'p' -> Latin 'p'
    'с': 'c',  # Cyrillic 'c' -> Latin 'c'
    'х': 'x',  # Cyrillic 'x' -> Latin 'x'
    'ѕ': 's',  # Cyrillic DZE -> Latin 's'
}


def detect_zero_width_chars(text: str) -> Tuple[List[int], int]:
    """
    Detect zero-width characters and their positions.
    
    Args:
        text: Text to analyze
        
    Returns:
        Tuple of (positions_list, count)
    """
    positions = []
    for i, char in enumerate(text):
        if char in ZERO_WIDTH_CHARS:
            positions.append(i)
    
    return positions, len(positions)


def detect_invisible_chars(text: str) -> Tuple[List[int], int]:
    """
    Detect invisible/control characters and their positions.
    
    Args:
        text: Text to analyze
        
    Returns:
        Tuple of (positions_list, count)
    """
    positions = []
    for i, char in enumerate(text):
        if char in INVISIBLE_CHARS:
            positions.append(i)
    
    return positions, len(positions)


def remove_zero_width_chars(text: str) -> Tuple[str, int]:
    """
    Remove zero-width characters from text.
    
    Args:
        text: Text to clean
        
    Returns:
        Tuple of (cleaned_text, num_removed)
    """
    cleaned = text
    count = 0
    
    for char in ZERO_WIDTH_CHARS:
        if char in cleaned:
            count += cleaned.count(char)
            cleaned = cleaned.replace(char, '')
    
    return cleaned, count


def create_special_char_mask(text: str) -> str:
    """
    Create a mask showing positions of special characters.
    
    Uses:
    - '.' for normal characters
    - 'Z' for zero-width characters
    - 'I' for invisible characters
    - 'H' for potential homoglyphs
    
    Args:
        text: Text to analyze
        
    Returns:
        Mask string of same length as input
    """
    mask = []
    
    for char in text:
        if char in ZERO_WIDTH_CHARS:
            mask.append('Z')
        elif char in INVISIBLE_CHARS:
            mask.append('I')
        elif char in HOMOGLYPH_PATTERNS:
            mask.append('H')
        else:
            mask.append('.')
    
    return ''.join(mask)


def detect_normalization_changes(original: str, normalized: str) -> Tuple[int, str]:
    """
    Detect changes made by Unicode normalization.
    
    Args:
        original: Original text
        normalized: NFKC normalized text
        
    Returns:
        Tuple of (num_changes, diff_summary)
    """
    if original == normalized:
        return 0, "No changes"
    
    changes = 0
    diff_parts = []
    
    # Simple character-by-character comparison
    min_len = min(len(original), len(normalized))
    
    for i in range(min_len):
        if original[i] != normalized[i]:
            changes += 1
            if len(diff_parts) < 5:  # Limit examples
                diff_parts.append(
                    f"pos {i}: '{original[i]}' (U+{ord(original[i]):04X}) -> "
                    f"'{normalized[i]}' (U+{ord(normalized[i]):04X})"
                )
    
    # Check length differences
    if len(original) != len(normalized):
        changes += abs(len(original) - len(normalized))
        diff_parts.append(f"Length changed: {len(original)} -> {len(normalized)}")
    
    if not diff_parts:
        diff_parts.append("Minor normalization changes")
    
    return changes, "; ".join(diff_parts[:5])


def analyze_unicode_obfuscation(text: str, raw_text: str = None) -> UnicodeAnalysis:
    """
    Comprehensive Unicode obfuscation analysis.
    
    Args:
        text: Normalized text
        raw_text: Original text before normalization (optional)
        
    Returns:
        UnicodeAnalysis object with detection results
    """
    # Detect zero-width characters
    zw_positions, zw_count = detect_zero_width_chars(text)
    
    # Detect invisible characters
    inv_positions, inv_count = detect_invisible_chars(text)
    
    # Check normalization changes if raw text provided
    norm_changes = 0
    unicode_diff = "Raw text not provided"
    
    if raw_text:
        norm_changes, unicode_diff = detect_normalization_changes(raw_text, text)
    
    # Set obfuscation flag
    obfuscation_flag = (
        zw_count > 0 or 
        inv_count > 0 or 
        norm_changes > 3  # Threshold for suspicious normalization
    )
    
    logger.debug(
        f"Unicode analysis: ZW={zw_count}, Inv={inv_count}, "
        f"NormChanges={norm_changes}, Obfuscated={obfuscation_flag}"
    )
    
    return UnicodeAnalysis(
        zero_width_found=zw_count > 0,
        invisible_chars_found=inv_count > 0,
        unicode_obfuscation_flag=obfuscation_flag,
        zero_width_count=zw_count,
        invisible_count=inv_count,
        zero_width_positions=zw_positions,
        normalization_changes=norm_changes,
        unicode_diff=unicode_diff
    )


def clean_text_unicode_safe(text: str) -> Tuple[str, UnicodeAnalysis]:
    """
    Clean text from Unicode obfuscation and return analysis.
    
    Args:
        text: Text to clean
        
    Returns:
        Tuple of (cleaned_text, analysis)
    """
    # Store raw text for comparison
    raw_text = text
    
    # Remove zero-width characters
    cleaned, zw_removed = remove_zero_width_chars(text)
    
    # Perform NFKC normalization
    normalized = unicodedata.normalize('NFKC', cleaned)
    
    # Analyze the cleaned text
    analysis = analyze_unicode_obfuscation(normalized, raw_text)
    
    return normalized, analysis
