"""
Output saver service.

Saves prepared inputs to disk in organized directories for Layer 0 and Media processing.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional
from app.models.schemas import PreparedInput
from app.utils.logger import get_logger

logger = get_logger(__name__)


class OutputSaver:
    """Handles saving prepared inputs to disk in organized format."""
    
    def __init__(self, base_output_dir: str = "/home/lightdesk/Projects/LLM-Protect/Outputs"):
        """
        Initialize output saver with base directory.
        
        Args:
            base_output_dir: Base directory for all outputs
        """
        self.base_dir = Path(base_output_dir)
        self.layer0_dir = self.base_dir / "layer0_text"
        self.media_dir = self.base_dir / "media_processing"
        
        # Create directories if they don't exist
        self._ensure_directories()
    
    def _ensure_directories(self):
        """Create output directories if they don't exist."""
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.layer0_dir.mkdir(parents=True, exist_ok=True)
        self.media_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Output directories initialized: {self.base_dir}")
    
    def _sanitize_filename(self, text: str, max_length: int = 50) -> str:
        """
        Create a safe filename from text.
        
        Args:
            text: Text to sanitize
            max_length: Maximum length of filename
        
        Returns:
            Sanitized filename
        """
        # Remove or replace unsafe characters
        safe = "".join(c if c.isalnum() or c in (' ', '-', '_') else '_' for c in text)
        # Truncate and strip whitespace
        safe = safe[:max_length].strip().replace(' ', '_')
        return safe if safe else "output"
    
    def _generate_filename(self, prepared: PreparedInput, processing_type: str) -> str:
        """
        Generate a unique filename for the output.
        
        Args:
            prepared: PreparedInput object
            processing_type: Either 'layer0' or 'media'
        
        Returns:
            Filename string
        """
        # Get timestamp
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        
        # Get short request ID (first 8 chars)
        request_id_short = prepared.metadata.request_id[:8]
        
        # Get sanitized preview of user text
        user_text_preview = self._sanitize_filename(
            prepared.text_embed_stub.normalized_user[:30]
        )
        
        # Construct filename
        filename = f"{timestamp}_{processing_type}_{request_id_short}_{user_text_preview}.json"
        
        return filename
    
    def save_layer0_output(self, prepared: PreparedInput) -> Optional[Path]:
        """
        Save Layer 0 (text processing) output to disk.
        
        Args:
            prepared: PreparedInput object from /prepare-text endpoint
        
        Returns:
            Path to saved file, or None if save failed
        """
        try:
            filename = self._generate_filename(prepared, "layer0")
            output_path = self.layer0_dir / filename
            
            # Convert to dict and save as JSON
            output_data = {
                "processing_type": "layer0_text",
                "saved_at": datetime.utcnow().isoformat() + 'Z',
                "prepared_input": prepared.model_dump()
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            logger.info(
                f"[{prepared.metadata.request_id}] Layer 0 output saved: {output_path.name}"
            )
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to save Layer 0 output: {e}", exc_info=True)
            return None
    
    def save_media_output(self, prepared: PreparedInput) -> Optional[Path]:
        """
        Save media processing output to disk.
        
        Args:
            prepared: PreparedInput object from /prepare-media endpoint
        
        Returns:
            Path to saved file, or None if save failed
        """
        try:
            filename = self._generate_filename(prepared, "media")
            output_path = self.media_dir / filename
            
            # Convert to dict and save as JSON
            output_data = {
                "processing_type": "media_processing",
                "saved_at": datetime.utcnow().isoformat() + 'Z',
                "prepared_input": prepared.model_dump()
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            logger.info(
                f"[{prepared.metadata.request_id}] Media output saved: {output_path.name}"
            )
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to save media output: {e}", exc_info=True)
            return None
    
    def get_recent_outputs(self, processing_type: str = "all", limit: int = 10) -> list[Path]:
        """
        Get list of recent output files.
        
        Args:
            processing_type: 'layer0', 'media', or 'all'
            limit: Maximum number of files to return
        
        Returns:
            List of Path objects, sorted by modification time (newest first)
        """
        files = []
        
        if processing_type in ("layer0", "all"):
            files.extend(self.layer0_dir.glob("*.json"))
        
        if processing_type in ("media", "all"):
            files.extend(self.media_dir.glob("*.json"))
        
        # Sort by modification time, newest first
        files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        
        return files[:limit]
    
    def get_output_stats(self) -> dict:
        """
        Get statistics about saved outputs.
        
        Returns:
            Dictionary with output statistics
        """
        layer0_count = len(list(self.layer0_dir.glob("*.json")))
        media_count = len(list(self.media_dir.glob("*.json")))
        
        return {
            "base_directory": str(self.base_dir),
            "layer0_outputs": layer0_count,
            "media_outputs": media_count,
            "total_outputs": layer0_count + media_count,
            "layer0_directory": str(self.layer0_dir),
            "media_directory": str(self.media_dir)
        }


# Global instance
_output_saver = None


def get_output_saver() -> OutputSaver:
    """Get or create the global OutputSaver instance."""
    global _output_saver
    if _output_saver is None:
        _output_saver = OutputSaver()
    return _output_saver

