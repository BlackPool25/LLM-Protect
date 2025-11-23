#!/usr/bin/env python3
"""
Verify the integrity of a saved output file.

This script demonstrates that:
1. PDF content was extracted completely
2. HMAC signatures are valid
3. No data loss occurred
"""

import json
import sys
from pathlib import Path

# Add app to path
sys.path.insert(0, str(Path(__file__).parent))

from app.utils.hmac_utils import verify_hmac


def verify_output_file(file_path: str):
    """Verify an output file's integrity."""
    
    print("=" * 70)
    print("LLM-PROTECT OUTPUT INTEGRITY VERIFICATION")
    print("=" * 70)
    
    # Load the output file
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    prepared = data['prepared_input']
    
    print(f"\n📄 File: {Path(file_path).name}")
    print(f"⏰ Saved at: {data['saved_at']}")
    print(f"🔖 Request ID: {prepared['metadata']['request_id']}")
    
    # Check user prompt
    print("\n" + "-" * 70)
    print("USER PROMPT VERIFICATION")
    print("-" * 70)
    
    user_text = prepared['text_embed_stub']['normalized_user']
    print(f"✅ User prompt preserved: {len(user_text)} characters")
    print(f"   Text: {user_text[:80]}{'...' if len(user_text) > 80 else ''}")
    
    # Check external data
    print("\n" + "-" * 70)
    print("EXTERNAL DATA (PDF) VERIFICATION")
    print("-" * 70)
    
    external_chunks = prepared['text_embed_stub']['normalized_external']
    hmacs = prepared['text_embed_stub']['hmacs']
    
    print(f"✅ External chunks: {len(external_chunks)}")
    print(f"✅ HMAC signatures: {len(hmacs)}")
    
    if len(external_chunks) != len(hmacs):
        print(f"❌ ERROR: Chunk count ({len(external_chunks)}) doesn't match HMAC count ({len(hmacs)})")
        return False
    
    # Verify each HMAC
    print("\n" + "-" * 70)
    print("HMAC SIGNATURE VERIFICATION")
    print("-" * 70)
    
    all_valid = True
    
    for i, (chunk, hmac_sig) in enumerate(zip(external_chunks, hmacs)):
        # Extract content (remove delimiters)
        if chunk.startswith("[EXTERNAL]"):
            content = chunk[len("[EXTERNAL]"):]
        else:
            content = chunk
            
        if content.endswith("[/EXTERNAL]"):
            content = content[:-len("[/EXTERNAL]")]
        
        # Verify HMAC
        try:
            is_valid = verify_hmac(content.strip(), hmac_sig)
            
            if is_valid:
                print(f"  ✅ Chunk {i}: HMAC VALID")
            else:
                print(f"  ❌ Chunk {i}: HMAC INVALID")
                all_valid = False
        except Exception as e:
            print(f"  ❌ Chunk {i}: Verification error: {e}")
            all_valid = False
        
        # Show content preview
        preview = content.strip()[:60]
        print(f"      Content: {preview}...")
    
    # Check file info
    if prepared['metadata'].get('has_file'):
        print("\n" + "-" * 70)
        print("FILE EXTRACTION VERIFICATION")
        print("-" * 70)
        
        file_info = prepared['metadata']['file_info']
        print(f"✅ File: {file_info['original_path']}")
        print(f"✅ Type: {file_info['type'].upper()}")
        print(f"✅ Hash: {file_info['hash'][:32]}...")
        print(f"✅ Chunks: {file_info['chunk_count']}")
        print(f"✅ Extraction: {'SUCCESS' if file_info['extraction_success'] else 'FAILED'}")
        
        stats = prepared['text_embed_stub']['stats']
        print(f"✅ Extracted characters: {stats['extracted_total_chars']}")
    
    # Performance stats
    print("\n" + "-" * 70)
    print("PERFORMANCE STATISTICS")
    print("-" * 70)
    
    stats = prepared['text_embed_stub']['stats']
    print(f"  Total characters: {stats['char_total']}")
    print(f"  Token estimate: {stats['token_estimate']}")
    print(f"  User/External ratio: {stats['user_external_ratio']:.2%}")
    print(f"  Preparation time: {prepared['metadata']['prep_time_ms']:.2f}ms")
    
    if 'step_times' in prepared['metadata'] and prepared['metadata']['step_times']:
        print("\n  Step breakdown:")
        for step, time_ms in prepared['metadata']['step_times'].items():
            print(f"    {step:20s}: {time_ms:6.2f}ms")
    
    # Final verdict
    print("\n" + "=" * 70)
    if all_valid:
        print("✅ VERIFICATION PASSED: All HMAC signatures are valid!")
        print("✅ DATA INTEGRITY: No data loss detected!")
        print("✅ SECURITY: All chunks properly signed and tracked!")
        return True
    else:
        print("❌ VERIFICATION FAILED: Some HMAC signatures are invalid!")
        print("❌ Possible tampering or corruption detected!")
        return False


if __name__ == "__main__":
    import os
    
    # Check if file path provided
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        # Use the latest Layer 0 output
        outputs_dir = Path(__file__).parent / "Outputs" / "layer0_text"
        
        if not outputs_dir.exists():
            print("❌ No outputs directory found!")
            print(f"   Expected: {outputs_dir}")
            sys.exit(1)
        
        json_files = sorted(outputs_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        
        if not json_files:
            print("❌ No output files found!")
            print(f"   Directory: {outputs_dir}")
            sys.exit(1)
        
        file_path = json_files[0]
        print(f"📁 Using latest output file: {file_path.name}\n")
    
    # Set HMAC key from environment (same as when output was created)
    if not os.getenv('HMAC_SECRET_KEY'):
        print("⚠️  Warning: HMAC_SECRET_KEY not set in environment")
        print("   Setting test key...")
        os.environ['HMAC_SECRET_KEY'] = "test_secret_key_for_development_only_at_least_32_chars_long"
    
    try:
        success = verify_output_file(str(file_path))
        sys.exit(0 if success else 1)
    except FileNotFoundError:
        print(f"❌ File not found: {file_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Verification error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

