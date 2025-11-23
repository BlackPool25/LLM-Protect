"""
Configuration management for the Input Preparation Module.

Loads settings from environment variables with sensible defaults.
"""

import os
from pathlib import Path
from typing import Set
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Settings:
    """Application settings loaded from environment variables."""
    
    # Security
    HMAC_SECRET_KEY: str = os.getenv("HMAC_SECRET_KEY", "")
    
    # File upload settings
    MAX_FILE_SIZE_MB: int = int(os.getenv("MAX_FILE_SIZE_MB", "10"))
    MAX_FILE_SIZE_BYTES: int = MAX_FILE_SIZE_MB * 1024 * 1024
    UPLOAD_DIR: Path = Path(os.getenv("UPLOAD_DIR", "uploads"))
    
    # Media temporary storage (for further layer processing)
    MEDIA_TEMP_DIR: Path = Path(os.getenv("MEDIA_TEMP_DIR", "temp_media"))
    
    # Allowed file extensions (case-insensitive)
    ALLOWED_TEXT_EXTENSIONS: Set[str] = {".txt", ".md", ".pdf", ".docx"}
    ALLOWED_IMAGE_EXTENSIONS: Set[str] = {".png", ".jpg", ".jpeg", ".gif", ".webp"}
    ALLOWED_EXTENSIONS: Set[str] = ALLOWED_TEXT_EXTENSIONS | ALLOWED_IMAGE_EXTENSIONS
    
    # Chunking settings
    CHUNK_SIZE: int = int(os.getenv("CHUNK_SIZE", "500"))
    CHUNK_OVERLAP: int = int(os.getenv("CHUNK_OVERLAP", "50"))
    
    # API settings
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))
    API_TITLE: str = "LLM-Protect Input Preparation API"
    API_VERSION: str = "1.0.0"
    API_PREFIX: str = "/api/v1"
    
    # Token estimation (rough approximation: 1 token ≈ 4 characters)
    CHARS_PER_TOKEN: int = 4
    
    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    
    def __init__(self):
        """Initialize settings and validate critical configuration."""
        # Ensure upload directory exists
        self.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        
        # Ensure media temp directory exists (for further layer processing)
        self.MEDIA_TEMP_DIR.mkdir(parents=True, exist_ok=True)
        
        # Validate HMAC secret key
        if not self.HMAC_SECRET_KEY:
            raise ValueError(
                "HMAC_SECRET_KEY must be set in environment variables. "
                "Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'"
            )
        
        if len(self.HMAC_SECRET_KEY) < 32:
            raise ValueError(
                "HMAC_SECRET_KEY must be at least 32 characters long for security."
            )
    
    def get_file_path(self, filename: str) -> Path:
        """Get the full path for an uploaded file."""
        return self.UPLOAD_DIR / filename
    
    def get_media_temp_path(self, filename: str) -> Path:
        """Get the full path for a temporary media file."""
        return self.MEDIA_TEMP_DIR / filename
    
    def is_allowed_extension(self, filename: str) -> bool:
        """Check if a file extension is allowed."""
        ext = Path(filename).suffix.lower()
        return ext in self.ALLOWED_EXTENSIONS
    
    def is_image_file(self, filename: str) -> bool:
        """Check if a file is an image."""
        ext = Path(filename).suffix.lower()
        return ext in self.ALLOWED_IMAGE_EXTENSIONS
    
    def is_text_file(self, filename: str) -> bool:
        """Check if a file is a text document."""
        ext = Path(filename).suffix.lower()
        return ext in self.ALLOWED_TEXT_EXTENSIONS
    
    def validate_file_size(self, size_bytes: int) -> bool:
        """Check if file size is within allowed limits."""
        return size_bytes <= self.MAX_FILE_SIZE_BYTES


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get the global settings instance."""
    return settings

