#!/usr/bin/env python3
"""
Test script to verify output saving functionality.

Tests that outputs are properly saved to the Outputs directory
for both Layer 0 and media processing.
"""

import sys
import os
from pathlib import Path

# Add app directory to path
sys.path.insert(0, str(Path(__file__).parent))

from app.services.output_saver import OutputSaver
from app.models.schemas import (
    PreparedInput, TextEmbedStub, ImageEmojiStub, MetadataInfo,
    StatsInfo, EmojiSummary
)

def create_sample_layer0_input() -> PreparedInput:
    """Create a sample Layer 0 PreparedInput for testing."""
    stats = StatsInfo(
        char_total=150,
        token_estimate=38,
        user_external_ratio=0.65,
        file_chunks_count=0,
        extracted_total_chars=0
    )
    
    text_stub = TextEmbedStub(
        normalized_user="What is the weather today?",
        normalized_external=["[EXTERNAL]Sunny conditions expected[/EXTERNAL]"],
        emoji_descriptions=[],
        hmacs=["abc123hmac"],
        stats=stats
    )
    
    emoji_summary = EmojiSummary(count=0, types=[], descriptions=[])
    
    img_stub = ImageEmojiStub(
        image={},
        emoji_summary=emoji_summary
    )
    
    metadata = MetadataInfo(
        request_id="test-1234-5678-layer0",
        timestamp="2025-11-22T10:00:00Z",
        rag_enabled=True,
        has_media=False,
        has_file=False,
        file_info=None,
        prep_time_ms=45.5
    )
    
    return PreparedInput(
        text_embed_stub=text_stub,
        image_emoji_stub=img_stub,
        metadata=metadata
    )


def create_sample_media_input() -> PreparedInput:
    """Create a sample media PreparedInput for testing."""
    stats = StatsInfo(
        char_total=25,
        token_estimate=7,
        user_external_ratio=1.0,
        file_chunks_count=0,
        extracted_total_chars=0
    )
    
    text_stub = TextEmbedStub(
        normalized_user="Check this image 😀",
        normalized_external=[],
        emoji_descriptions=[":grinning:"],
        hmacs=[],
        stats=stats
    )
    
    emoji_summary = EmojiSummary(
        count=1,
        types=["😀"],
        descriptions=[":grinning:"]
    )
    
    img_stub = ImageEmojiStub(
        image={
            "hash": "sha256_test123",
            "format": "png",
            "size_bytes": 12345,
            "dimensions": [800, 600]
        },
        emoji_summary=emoji_summary
    )
    
    metadata = MetadataInfo(
        request_id="test-1234-5678-media",
        timestamp="2025-11-22T10:00:00Z",
        rag_enabled=False,
        has_media=True,
        has_file=False,
        file_info=None,
        prep_time_ms=32.1
    )
    
    return PreparedInput(
        text_embed_stub=text_stub,
        image_emoji_stub=img_stub,
        metadata=metadata
    )


def test_output_saver():
    """Test the OutputSaver functionality."""
    print("=" * 60)
    print("Testing Output Saver Functionality")
    print("=" * 60)
    
    # Create output saver
    output_saver = OutputSaver()
    print(f"\n✓ OutputSaver initialized")
    print(f"  Base directory: {output_saver.base_dir}")
    print(f"  Layer 0 directory: {output_saver.layer0_dir}")
    print(f"  Media directory: {output_saver.media_dir}")
    
    # Test Layer 0 output saving
    print("\n" + "-" * 60)
    print("Test 1: Saving Layer 0 Output")
    print("-" * 60)
    
    layer0_input = create_sample_layer0_input()
    layer0_path = output_saver.save_layer0_output(layer0_input)
    
    if layer0_path and layer0_path.exists():
        print(f"✓ Layer 0 output saved successfully")
        print(f"  File: {layer0_path.name}")
        print(f"  Path: {layer0_path}")
        print(f"  Size: {layer0_path.stat().st_size} bytes")
        
        # Read and verify
        import json
        with open(layer0_path) as f:
            data = json.load(f)
        
        assert data["processing_type"] == "layer0_text"
        assert "prepared_input" in data
        assert data["prepared_input"]["metadata"]["request_id"] == "test-1234-5678-layer0"
        print(f"✓ Content verification passed")
    else:
        print(f"✗ Failed to save Layer 0 output")
        return False
    
    # Test media output saving
    print("\n" + "-" * 60)
    print("Test 2: Saving Media Output")
    print("-" * 60)
    
    media_input = create_sample_media_input()
    media_path = output_saver.save_media_output(media_input)
    
    if media_path and media_path.exists():
        print(f"✓ Media output saved successfully")
        print(f"  File: {media_path.name}")
        print(f"  Path: {media_path}")
        print(f"  Size: {media_path.stat().st_size} bytes")
        
        # Read and verify
        import json
        with open(media_path) as f:
            data = json.load(f)
        
        assert data["processing_type"] == "media_processing"
        assert "prepared_input" in data
        assert data["prepared_input"]["metadata"]["request_id"] == "test-1234-5678-media"
        print(f"✓ Content verification passed")
    else:
        print(f"✗ Failed to save media output")
        return False
    
    # Test statistics
    print("\n" + "-" * 60)
    print("Test 3: Output Statistics")
    print("-" * 60)
    
    stats = output_saver.get_output_stats()
    print(f"✓ Statistics retrieved")
    print(f"  Total outputs: {stats['total_outputs']}")
    print(f"  Layer 0 outputs: {stats['layer0_outputs']}")
    print(f"  Media outputs: {stats['media_outputs']}")
    
    # Test recent files
    print("\n" + "-" * 60)
    print("Test 4: Recent Files Retrieval")
    print("-" * 60)
    
    recent_all = output_saver.get_recent_outputs("all", limit=10)
    recent_layer0 = output_saver.get_recent_outputs("layer0", limit=5)
    recent_media = output_saver.get_recent_outputs("media", limit=5)
    
    print(f"✓ Recent files retrieved")
    print(f"  All: {len(recent_all)} files")
    print(f"  Layer 0: {len(recent_layer0)} files")
    print(f"  Media: {len(recent_media)} files")
    
    if recent_all:
        print(f"\n  Most recent file: {recent_all[0].name}")
    
    # Summary
    print("\n" + "=" * 60)
    print("All Tests Passed! ✓")
    print("=" * 60)
    print(f"\nOutput files saved to:")
    print(f"  {output_saver.base_dir}")
    print(f"\nYou can view the outputs at:")
    print(f"  Layer 0: {output_saver.layer0_dir}")
    print(f"  Media:   {output_saver.media_dir}")
    
    return True


if __name__ == "__main__":
    try:
        success = test_output_saver()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

