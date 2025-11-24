"""
Fast heuristics for pre-Layer 0 pattern detection.

Implements ultra-fast regex-based checks for common injection patterns,
obfuscation attempts, and suspicious payloads.
"""

import re
from typing import Dict, List, Optional
from app.utils.logger import get_logger

logger = get_logger(__name__)


class HeuristicFlags:
    """Container for heuristic detection flags."""
    
    def __init__(
        self,
        has_long_base64: bool = False,
        has_system_delimiter: bool = False,
        has_repeated_chars: bool = False,
        has_long_single_line: bool = False,
        has_xml_tags: bool = False,
        has_html_comments: bool = False,
        has_suspicious_keywords: bool = False,
        has_many_delimiters: bool = False,
        suspicious_score: float = 0.0,
        detected_patterns: List[str] = None
    ):
        self.has_long_base64 = has_long_base64
        self.has_system_delimiter = has_system_delimiter
        self.has_repeated_chars = has_repeated_chars
        self.has_long_single_line = has_long_single_line
        self.has_xml_tags = has_xml_tags
        self.has_html_comments = has_html_comments
        self.has_suspicious_keywords = has_suspicious_keywords
        self.has_many_delimiters = has_many_delimiters
        self.suspicious_score = suspicious_score
        self.detected_patterns = detected_patterns or []
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "has_long_base64": self.has_long_base64,
            "has_system_delimiter": self.has_system_delimiter,
            "has_repeated_chars": self.has_repeated_chars,
            "has_long_single_line": self.has_long_single_line,
            "has_xml_tags": self.has_xml_tags,
            "has_html_comments": self.has_html_comments,
            "has_suspicious_keywords": self.has_suspicious_keywords,
            "has_many_delimiters": self.has_many_delimiters,
            "suspicious_score": self.suspicious_score,
            "detected_patterns": self.detected_patterns
        }
    
    def is_suspicious(self) -> bool:
        """Check if any suspicious patterns were detected."""
        return self.suspicious_score > 0.3


# System delimiters commonly used in LLM prompt injection
SYSTEM_DELIMITERS = [
    r'</system>',
    r'<\|im_end\|>',
    r'<\|im_start\|>',
    r'<\|endoftext\|>',
    r'\[INST\]',
    r'\[/INST\]',
    r'<s>',
    r'</s>',
    r'###',
    r'---END---',
    r'Assistant:',
    r'Human:',
    r'User:',
    r'System:',
]

# Suspicious keywords in prompt injection
SUSPICIOUS_KEYWORDS = [
    r'ignore\s+(?:all\s+)?previous\s+instructions',
    r'disregard\s+(?:all\s+)?(?:previous\s+)?instructions',
    r'forget\s+(?:all\s+)?(?:previous\s+)?instructions',
    r'new\s+instructions',
    r'system\s+override',
    r'admin\s+mode',
    r'developer\s+mode',
    r'maintenance\s+mode',
    r'reveal\s+(?:the\s+)?(?:system\s+)?prompt',
    r'show\s+(?:the\s+)?(?:system\s+)?prompt',
    r'print\s+(?:the\s+)?(?:system\s+)?prompt',
    r'bypass\s+(?:security|filter|restriction)',
]


def detect_long_base64(text: str, min_length: int = 50) -> bool:
    """
    Detect suspiciously long base64-encoded sequences.
    
    Args:
        text: Text to analyze
        min_length: Minimum length to consider suspicious
    
    Returns:
        True if long base64 sequence found
    """
    # Base64 pattern: alphanumeric + + / and optional = padding
    base64_pattern = re.compile(r'[A-Za-z0-9+/]{' + str(min_length) + r',}={0,2}')
    matches = base64_pattern.findall(text)
    
    return len(matches) > 0


def detect_system_delimiters(text: str) -> List[str]:
    """
    Detect system/model-specific delimiters.
    
    Args:
        text: Text to analyze
    
    Returns:
        List of detected delimiter patterns
    """
    detected = []
    text_lower = text.lower()
    
    for delimiter in SYSTEM_DELIMITERS:
        pattern = re.compile(delimiter, re.IGNORECASE)
        if pattern.search(text):
            detected.append(delimiter)
    
    return detected


def detect_repeated_chars(text: str, min_repeats: int = 20) -> bool:
    """
    Detect suspiciously repeated characters.
    
    Args:
        text: Text to analyze
        min_repeats: Minimum repetitions to flag
    
    Returns:
        True if many repeated characters found
    """
    # Pattern for same character repeated many times
    pattern = re.compile(r'(.)\1{' + str(min_repeats - 1) + r',}')
    matches = pattern.findall(text)
    
    return len(matches) > 0


def detect_long_single_line(text: str, max_length: int = 500) -> bool:
    """
    Detect unusually long single-line payloads.
    
    Args:
        text: Text to analyze
        max_length: Maximum acceptable line length
    
    Returns:
        True if long single line found
    """
    lines = text.split('\n')
    for line in lines:
        if len(line) > max_length:
            return True
    
    return False


def detect_xml_tags(text: str) -> bool:
    """
    Detect XML-like tags that might be injection attempts.
    
    Args:
        text: Text to analyze
    
    Returns:
        True if XML tags found
    """
    # Simple XML tag pattern
    xml_pattern = re.compile(r'</?[a-zA-Z][a-zA-Z0-9]*(?:\s+[^>]*)?>(?!</|>)')
    matches = xml_pattern.findall(text)
    
    # Filter out common safe tags in small quantities
    if len(matches) <= 2:
        return False
    
    return True


def detect_html_comments(text: str) -> bool:
    """
    Detect HTML comments which might hide injection payloads.
    
    Args:
        text: Text to analyze
    
    Returns:
        True if HTML comments found
    """
    html_comment_pattern = re.compile(r'<!--.*?-->', re.DOTALL)
    matches = html_comment_pattern.findall(text)
    
    return len(matches) > 0


def detect_suspicious_keywords(text: str) -> List[str]:
    """
    Detect suspicious keywords associated with prompt injection.
    
    Args:
        text: Text to analyze
    
    Returns:
        List of detected suspicious patterns
    """
    detected = []
    text_lower = text.lower()
    
    for keyword in SUSPICIOUS_KEYWORDS:
        pattern = re.compile(keyword, re.IGNORECASE)
        if pattern.search(text_lower):
            detected.append(keyword)
    
    return detected


def detect_many_delimiters(text: str, threshold: int = 5) -> bool:
    """
    Detect unusual number of delimiter-like characters.
    
    Args:
        text: Text to analyze
        threshold: Number of delimiters to consider suspicious
    
    Returns:
        True if many delimiters found
    """
    delimiters = ['###', '---', '===', '***', '|||', '<<<', '>>>']
    count = 0
    
    for delimiter in delimiters:
        count += text.count(delimiter)
    
    return count >= threshold


def calculate_suspicious_score(flags: HeuristicFlags) -> float:
    """
    Calculate an overall suspiciousness score from flags.
    
    Args:
        flags: HeuristicFlags object
    
    Returns:
        Score from 0.0 (clean) to 1.0 (very suspicious)
    """
    score = 0.0
    
    # Weight different flags
    if flags.has_long_base64:
        score += 0.2
    if flags.has_system_delimiter:
        score += 0.3
    if flags.has_repeated_chars:
        score += 0.1
    if flags.has_long_single_line:
        score += 0.15
    if flags.has_xml_tags:
        score += 0.1
    if flags.has_html_comments:
        score += 0.15
    if flags.has_suspicious_keywords:
        score += 0.4
    if flags.has_many_delimiters:
        score += 0.2
    
    # Cap at 1.0
    return min(score, 1.0)


def run_fast_heuristics(text: str) -> HeuristicFlags:
    """
    Run all fast heuristic checks on text.
    
    This is designed to be VERY fast (< 5ms) for pre-Layer 0 screening.
    
    Args:
        text: Text to analyze
    
    Returns:
        HeuristicFlags with all detection results
    """
    if not text:
        return HeuristicFlags(suspicious_score=0.0)
    
    # Only analyze first 10k chars for speed
    text_sample = text[:10000]
    
    detected_patterns = []
    
    # Run all checks
    has_long_base64 = detect_long_base64(text_sample)
    if has_long_base64:
        detected_patterns.append("long_base64")
    
    system_delimiters = detect_system_delimiters(text_sample)
    has_system_delimiter = len(system_delimiters) > 0
    if has_system_delimiter:
        detected_patterns.extend(system_delimiters)
    
    has_repeated_chars = detect_repeated_chars(text_sample)
    if has_repeated_chars:
        detected_patterns.append("repeated_chars")
    
    has_long_single_line = detect_long_single_line(text_sample)
    if has_long_single_line:
        detected_patterns.append("long_single_line")
    
    has_xml_tags = detect_xml_tags(text_sample)
    if has_xml_tags:
        detected_patterns.append("xml_tags")
    
    has_html_comments = detect_html_comments(text_sample)
    if has_html_comments:
        detected_patterns.append("html_comments")
    
    suspicious_keywords = detect_suspicious_keywords(text_sample)
    has_suspicious_keywords = len(suspicious_keywords) > 0
    if has_suspicious_keywords:
        detected_patterns.extend(suspicious_keywords)
    
    has_many_delimiters = detect_many_delimiters(text_sample)
    if has_many_delimiters:
        detected_patterns.append("many_delimiters")
    
    # Create flags object
    flags = HeuristicFlags(
        has_long_base64=has_long_base64,
        has_system_delimiter=has_system_delimiter,
        has_repeated_chars=has_repeated_chars,
        has_long_single_line=has_long_single_line,
        has_xml_tags=has_xml_tags,
        has_html_comments=has_html_comments,
        has_suspicious_keywords=has_suspicious_keywords,
        has_many_delimiters=has_many_delimiters,
        detected_patterns=detected_patterns
    )
    
    # Calculate suspiciousness score
    flags.suspicious_score = calculate_suspicious_score(flags)
    
    logger.debug(
        f"Heuristics: score={flags.suspicious_score:.2f}, "
        f"patterns={len(detected_patterns)}"
    )
    
    return flags


def run_batch_heuristics(texts: List[str]) -> List[HeuristicFlags]:
    """
    Run heuristics on multiple texts.
    
    Args:
        texts: List of texts to analyze
    
    Returns:
        List of HeuristicFlags objects
    """
    results = []
    for text in texts:
        flags = run_fast_heuristics(text)
        results.append(flags)
    
    return results
