"""Cryptographic utilities for prompt signing and verification."""

import hmac
import hashlib
from typing import Tuple, Optional

from src.config import settings


def generate_hmac_signature(prompt: str, secret_key: Optional[str] = None) -> str:
    """
    Generate HMAC-SHA256 signature for a prompt.
    
    Args:
        prompt: The prompt text to sign
        secret_key: Optional secret key (uses config default if not provided)
        
    Returns:
        Hexadecimal string representation of the signature
    """
    key = secret_key or settings.hmac_secret_key
    signature = hmac.new(
        key.encode('utf-8'),
        prompt.encode('utf-8'),
        hashlib.sha256
    )
    return signature.hexdigest()


def verify_hmac_signature(prompt: str, signature: str, secret_key: Optional[str] = None) -> bool:
    """
    Verify HMAC-SHA256 signature for a prompt.
    
    Args:
        prompt: The prompt text to verify
        signature: The signature to check against
        secret_key: Optional secret key (uses config default if not provided)
        
    Returns:
        True if signature is valid, False otherwise
    """
    key = secret_key or settings.hmac_secret_key
    expected_signature = hmac.new(
        key.encode('utf-8'),
        prompt.encode('utf-8'),
        hashlib.sha256
    )
    return hmac.compare_digest(expected_signature.hexdigest(), signature)


def sign_prompt(prompt: str) -> Tuple[str, str]:
    """
    Sign a prompt and return both prompt and signature.
    
    Args:
        prompt: The prompt text to sign
        
    Returns:
        Tuple of (prompt, signature)
    """
    signature = generate_hmac_signature(prompt)
    return prompt, signature

