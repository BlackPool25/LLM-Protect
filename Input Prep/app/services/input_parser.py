"""
Input parsing and validation service.

Handles initial validation of user inputs and files.
"""

import os
import uuid
from datetime import datetime
from typing import Optional, Dict, Any
from pathlib import Path
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


def parse_and_validate(
    user_prompt: str,
    file_path: Optional[str] = None,
    image_path: Optional[str] = None,
    external_data: Optional[list] = None
) -> Dict[str, Any]:
    """
    Parse and validate raw input.
    
    Generates request ID, timestamp, and validates inputs.
    
    Args:
        user_prompt: User's input text
        file_path: Optional path to uploaded file
        image_path: Optional path to image file
        external_data: Optional list of external data strings
    
    Returns:
        Dictionary with parsed and validated data
    
    Example:
        >>> result = parse_and_validate("Hello world")
        >>> 'request_id' in result
        True
        >>> 'timestamp' in result
        True
    """
    # Generate request ID
    request_id = str(uuid.uuid4())
    
    # Generate timestamp
    timestamp = datetime.utcnow().isoformat() + 'Z'
    
    # Validate user prompt
    if not user_prompt or not user_prompt.strip():
        raise ValueError("user_prompt cannot be empty or whitespace only")
    
    # Validate file if provided
    raw_file = None
    file_valid = False
    file_error = None
    
    if file_path:
        if os.path.isfile(file_path):
            # Check extension
            if settings.is_allowed_extension(file_path):
                # Check size
                file_size = os.path.getsize(file_path)
                if file_size <= settings.MAX_FILE_SIZE_BYTES:
                    raw_file = file_path
                    file_valid = True
                else:
                    file_error = f"File too large: {file_size / (1024*1024):.2f}MB"
            else:
                ext = Path(file_path).suffix
                file_error = f"Unsupported file type: {ext}"
        else:
            file_error = f"File not found: {file_path}"
    
    # Validate image if provided
    raw_image = None
    image_valid = False
    image_error = None
    
    if image_path:
        if os.path.isfile(image_path):
            # Check size
            image_size = os.path.getsize(image_path)
            if image_size <= settings.MAX_FILE_SIZE_BYTES:
                raw_image = image_path
                image_valid = True
            else:
                image_error = f"Image too large: {image_size / (1024*1024):.2f}MB"
        else:
            image_error = f"Image not found: {image_path}"
    
    # Validate external data
    raw_external = []
    if external_data:
        # Filter out empty strings
        raw_external = [item for item in external_data if item and item.strip()]
    
    parsed = {
        "request_id": request_id,
        "timestamp": timestamp,
        "raw_user": user_prompt,
        "raw_external": raw_external,
        "raw_file": raw_file,
        "raw_image": raw_image,
        "validation": {
            "file_valid": file_valid,
            "file_error": file_error,
            "image_valid": image_valid,
            "image_error": image_error,
        }
    }
    
    logger.info(
        f"[{request_id}] Input parsed: "
        f"user={len(user_prompt)} chars, "
        f"external={len(raw_external)} items, "
        f"file={'yes' if file_valid else 'no'}, "
        f"image={'yes' if image_valid else 'no'}"
    )
    
    return parsed


def validate_request(
    user_prompt: str,
    max_prompt_length: int = 50000
) -> tuple[bool, Optional[str]]:
    """
    Validate a user request before processing.
    
    Args:
        user_prompt: User's input text
        max_prompt_length: Maximum allowed prompt length
    
    Returns:
        Tuple of (is_valid, error_message)
    
    Example:
        >>> valid, error = validate_request("Hello world")
        >>> valid
        True
        >>> error is None
        True
    """
    # Check if empty
    if not user_prompt or not user_prompt.strip():
        return False, "user_prompt cannot be empty"
    
    # Check length
    if len(user_prompt) > max_prompt_length:
        return False, f"user_prompt too long: {len(user_prompt)} chars (max: {max_prompt_length})"
    
    # Check for null bytes (can cause issues)
    if '\x00' in user_prompt:
        return False, "user_prompt contains null bytes"
    
    return True, None

