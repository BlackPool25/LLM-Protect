"""
HMAC utilities for data integrity verification.

Provides cryptographically secure HMAC-SHA256 operations using a secret key
that cannot be externally modified.
"""

import hmac
import hashlib
from typing import Optional
from app.config import settings


def generate_hmac(data: str, key: Optional[str] = None) -> str:
    """
    Generate HMAC-SHA256 signature for the given data.
    
    Args:
        data: The string data to sign
        key: Optional custom key (uses settings.HMAC_SECRET_KEY if not provided)
    
    Returns:
        Hexadecimal HMAC signature
    
    Example:
        >>> signature = generate_hmac("Hello, World!")
        >>> len(signature)
        64
    """
    secret_key = key if key is not None else settings.HMAC_SECRET_KEY
    
    if not secret_key:
        raise ValueError("HMAC secret key is not configured")
    
    return hmac.new(
        secret_key.encode('utf-8'),
        data.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


def verify_hmac(data: str, signature: str, key: Optional[str] = None) -> bool:
    """
    Verify HMAC-SHA256 signature for the given data.
    
    Uses constant-time comparison (hmac.compare_digest) to prevent timing attacks.
    
    Args:
        data: The original data that was signed
        signature: The HMAC signature to verify
        key: Optional custom key (uses settings.HMAC_SECRET_KEY if not provided)
    
    Returns:
        True if signature is valid, False otherwise
    
    Example:
        >>> data = "Hello, World!"
        >>> sig = generate_hmac(data)
        >>> verify_hmac(data, sig)
        True
        >>> verify_hmac(data, "invalid_signature")
        False
    """
    try:
        expected_signature = generate_hmac(data, key)
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(expected_signature, signature)
    except Exception:
        # Return False on any error (invalid key, encoding issues, etc.)
        return False


def sign_chunks(chunks: list[str], key: Optional[str] = None) -> list[str]:
    """
    Generate HMAC signatures for a list of text chunks.
    
    Args:
        chunks: List of text chunks to sign
        key: Optional custom key (uses settings.HMAC_SECRET_KEY if not provided)
    
    Returns:
        List of HMAC signatures corresponding to each chunk
    
    Example:
        >>> chunks = ["chunk1", "chunk2", "chunk3"]
        >>> signatures = sign_chunks(chunks)
        >>> len(signatures)
        3
    """
    return [generate_hmac(chunk, key) for chunk in chunks]


def verify_chunks(chunks: list[str], signatures: list[str], key: Optional[str] = None) -> list[bool]:
    """
    Verify HMAC signatures for a list of text chunks.
    
    Args:
        chunks: List of text chunks that were signed
        signatures: List of HMAC signatures to verify
        key: Optional custom key (uses settings.HMAC_SECRET_KEY if not provided)
    
    Returns:
        List of boolean values indicating validity of each signature
    
    Example:
        >>> chunks = ["chunk1", "chunk2"]
        >>> sigs = sign_chunks(chunks)
        >>> verify_chunks(chunks, sigs)
        [True, True]
    """
    if len(chunks) != len(signatures):
        return [False] * len(chunks)
    
    return [verify_hmac(chunk, sig, key) for chunk, sig in zip(chunks, signatures)]


def hash_file_sha256(file_path: str) -> str:
    """
    Calculate SHA256 hash of a file.
    
    Reads file in chunks to handle large files efficiently.
    
    Args:
        file_path: Path to the file to hash
    
    Returns:
        Hexadecimal SHA256 hash of the file
    
    Example:
        >>> hash_file_sha256("example.txt")
        'a3b2c1d4...'
    """
    sha256_hash = hashlib.sha256()
    
    with open(file_path, 'rb') as f:
        # Read file in 64KB chunks
        for chunk in iter(lambda: f.read(65536), b''):
            sha256_hash.update(chunk)
    
    return sha256_hash.hexdigest()


def hash_bytes_sha256(data: bytes) -> str:
    """
    Calculate SHA256 hash of byte data.
    
    Args:
        data: Byte data to hash
    
    Returns:
        Hexadecimal SHA256 hash
    
    Example:
        >>> hash_bytes_sha256(b"Hello, World!")
        'dffd6021bb2bd5b0af676290809ec3a5...'
    """
    return hashlib.sha256(data).hexdigest()

