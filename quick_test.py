#!/usr/bin/env python3
"""
Quick test script to verify LLM-Protect is working properly.

Tests:
1. Server is running
2. API endpoints work
3. LLM generation works
4. Outputs are being saved
5. Vector DB is accessible
"""

import requests
import json
import os
import sys
from pathlib import Path

BASE_URL = "http://localhost:8000/api/v1"
TIMEOUT = 10  # seconds

def print_section(title):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)

def test_server_running():
    """Test if server is responding."""
    print("\n1. Testing if server is running...")
    try:
        response = requests.get(f"{BASE_URL}/model-status", timeout=TIMEOUT)
        status = response.json()
        print(f"   ✓ Server is running")
        print(f"   ✓ Model: {status.get('model_name', 'Unknown')}")
        print(f"   ✓ Device: {status.get('device', 'Unknown')}")
        return True
    except requests.exceptions.ConnectionError:
        print(f"   ✗ Server not responding on port 8000")
        print(f"   → Run: bash start_server.sh")
        return False
    except Exception as e:
        print(f"   ✗ Error: {e}")
        return False

def test_prepare_text():
    """Test /prepare-text endpoint."""
    print("\n2. Testing /prepare-text endpoint...")
    try:
        response = requests.post(
            f"{BASE_URL}/prepare-text",
            data={"user_prompt": "Hello, this is a test!"},
            timeout=TIMEOUT
        )
        if response.status_code == 200:
            prepared = response.json()
            req_id = prepared['metadata']['request_id']
            tokens = prepared['text_embed_stub']['stats']['token_estimate']
            print(f"   ✓ Prepare-text works")
            print(f"   ✓ Request ID: {req_id[:16]}...")
            print(f"   ✓ Token estimate: {tokens}")
            return prepared
        else:
            print(f"   ✗ Failed with status {response.status_code}")
            return None
    except Exception as e:
        print(f"   ✗ Error: {e}")
        return None

def test_llm_generation(prepared):
    """Test LLM generation."""
    print("\n3. Testing LLM generation...")
    try:
        response = requests.post(
            f"{BASE_URL}/generate",
            json={"prepared_input": prepared, "max_new_tokens": 50},
            timeout=30  # LLM can take longer
        )
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                generated = result['generated_text']
                print(f"   ✓ LLM generation works")
                print(f"   ✓ Input tokens: {result['input_tokens']}")
                print(f"   ✓ Output tokens: {result['output_tokens']}")
                print(f"   ✓ Time: {result['total_time_ms']:.2f}ms")
                print(f"   ✓ Generated: {generated[:80]}{'...' if len(generated) > 80 else ''}")
                return True
            else:
                print(f"   ✗ Generation failed: {result.get('error', 'Unknown')}")
                return False
        else:
            print(f"   ✗ Failed with status {response.status_code}")
            return False
    except requests.exceptions.Timeout:
        print(f"   ✗ Timeout (LLM took too long)")
        return False
    except Exception as e:
        print(f"   ✗ Error: {e}")
        return False

def test_outputs_saved():
    """Test if outputs are being saved."""
    print("\n4. Testing output saving...")
    try:
        output_dir = Path("Outputs/layer0_text")
        if not output_dir.exists():
            print(f"   ✗ Output directory doesn't exist: {output_dir}")
            return False
        
        output_files = list(output_dir.glob("*.json"))
        if len(output_files) > 0:
            latest = max(output_files, key=lambda p: p.stat().st_mtime)
            print(f"   ✓ Outputs are being saved")
            print(f"   ✓ Total files: {len(output_files)}")
            print(f"   ✓ Latest: {latest.name}")
            return True
        else:
            print(f"   ✗ No output files found in {output_dir}")
            return False
    except Exception as e:
        print(f"   ✗ Error: {e}")
        return False

def test_vector_db():
    """Test vector database."""
    print("\n5. Testing vector database...")
    try:
        db_path = Path("chroma_db")
        if not db_path.exists():
            print(f"   ✗ Vector DB not found at {db_path}")
            print(f"   → Run: python3 populate_vector_db.py")
            return False
        
        # Test with RAG query
        response = requests.post(
            f"{BASE_URL}/prepare-text",
            data={
                "user_prompt": "What is DSA?",
                "retrieve_from_vector_db": "true"
            },
            timeout=TIMEOUT
        )
        
        if response.status_code == 200:
            prepared = response.json()
            external_chunks = len(prepared['text_embed_stub']['normalized_external'])
            if external_chunks > 0:
                print(f"   ✓ Vector DB is working")
                print(f"   ✓ Retrieved {external_chunks} documents")
                return True
            else:
                print(f"   ⚠ Vector DB exists but no results retrieved")
                print(f"   → DB might be empty, run: python3 populate_vector_db.py")
                return False
        else:
            print(f"   ✗ Failed with status {response.status_code}")
            return False
    except Exception as e:
        print(f"   ✗ Error: {e}")
        return False

def test_conversation_session():
    """Test session creation."""
    print("\n6. Testing conversation sessions...")
    try:
        response = requests.post(f"{BASE_URL}/sessions/create", timeout=TIMEOUT)
        if response.status_code == 200:
            session = response.json()
            session_id = session['session_id']
            print(f"   ✓ Session creation works")
            print(f"   ✓ Session ID: {session_id[:16]}...")
            
            # Test session info
            response = requests.get(f"{BASE_URL}/sessions/{session_id}", timeout=TIMEOUT)
            if response.status_code == 200:
                print(f"   ✓ Session retrieval works")
                return True
        
        print(f"   ✗ Failed with status {response.status_code}")
        return False
    except Exception as e:
        print(f"   ✗ Error: {e}")
        return False

def main():
    """Run all tests."""
    print_section("LLM-PROTECT QUICK TEST")
    
    results = {
        "Server Running": test_server_running(),
    }
    
    if not results["Server Running"]:
        print("\n" + "=" * 70)
        print("❌ Server is not running. Start it with: bash start_server.sh")
        print("=" * 70)
        sys.exit(1)
    
    prepared = test_prepare_text()
    results["Prepare Text"] = prepared is not None
    
    if prepared:
        results["LLM Generation"] = test_llm_generation(prepared)
    else:
        results["LLM Generation"] = False
    
    results["Output Saving"] = test_outputs_saved()
    results["Vector DB"] = test_vector_db()
    results["Sessions"] = test_conversation_session()
    
    # Summary
    print_section("TEST SUMMARY")
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, passed_flag in results.items():
        status = "✓ PASS" if passed_flag else "✗ FAIL"
        print(f"  {status:8} {test_name}")
    
    print(f"\n  Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n  ✅ ALL TESTS PASSED! System is working properly.")
        print("=" * 70)
        sys.exit(0)
    else:
        print("\n  ⚠ SOME TESTS FAILED. See errors above for details.")
        print("=" * 70)
        sys.exit(1)

if __name__ == "__main__":
    main()

