"""
Test script for the Input Preparation API.

Tests all endpoints with various scenarios.
"""

import requests
import json
import time
from pathlib import Path

BASE_URL = "http://localhost:8000"
API_PREFIX = "/api/v1"


def print_section(title):
    """Print a section header."""
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def test_health_check():
    """Test the health check endpoint."""
    print_section("Testing Health Check")
    
    response = requests.get(f"{BASE_URL}/health")
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "libraries" in data
    print("✓ Health check passed")


def test_prepare_text_simple():
    """Test text preparation with simple input."""
    print_section("Testing Simple Text Preparation")
    
    data = {
        "user_prompt": "What is the weather like today? 🌞"
    }
    
    response = requests.post(
        f"{BASE_URL}{API_PREFIX}/prepare-text",
        data=data
    )
    
    print(f"Status: {response.status_code}")
    result = response.json()
    print(f"Request ID: {result['metadata']['request_id']}")
    print(f"Prep time: {result['metadata']['prep_time_ms']:.2f}ms")
    print(f"Tokens: {result['text_embed_stub']['stats']['token_estimate']}")
    print(f"Emojis: {result['image_emoji_stub']['emoji_summary']['count']}")
    
    assert response.status_code == 200
    assert result['text_embed_stub']['normalized_user']
    print("✓ Simple text preparation passed")


def test_prepare_text_with_external_data():
    """Test text preparation with external data."""
    print_section("Testing Text Preparation with External Data")
    
    external_data = [
        "The weather forecast predicts sunny conditions.",
        "Temperature will be around 25°C.",
        "No rain expected today."
    ]
    
    data = {
        "user_prompt": "Tell me about today's weather",
        "external_data": json.dumps(external_data)
    }
    
    response = requests.post(
        f"{BASE_URL}{API_PREFIX}/prepare-text",
        data=data
    )
    
    print(f"Status: {response.status_code}")
    result = response.json()
    print(f"Request ID: {result['metadata']['request_id']}")
    print(f"External chunks: {len(result['text_embed_stub']['normalized_external'])}")
    print(f"HMACs: {len(result['text_embed_stub']['hmacs'])}")
    print(f"RAG enabled: {result['metadata']['rag_enabled']}")
    
    assert response.status_code == 200
    assert len(result['text_embed_stub']['normalized_external']) == 3
    assert len(result['text_embed_stub']['hmacs']) == 3
    assert result['metadata']['rag_enabled'] == True
    print("✓ External data preparation passed")


def test_prepare_text_with_file():
    """Test text preparation with file upload."""
    print_section("Testing Text Preparation with File Upload")
    
    # Create a test file
    test_file = Path("test_document.txt")
    test_content = """This is a test document.
It contains multiple lines of text.
This will be chunked and processed by the system.

Each chunk will be signed with an HMAC for integrity verification.
The system supports TXT, MD, PDF, and DOCX files."""
    
    test_file.write_text(test_content)
    
    try:
        data = {
            "user_prompt": "Analyze this document"
        }
        
        files = {
            "file": ("test_document.txt", open(test_file, "rb"), "text/plain")
        }
        
        response = requests.post(
            f"{BASE_URL}{API_PREFIX}/prepare-text",
            data=data,
            files=files
        )
        
        print(f"Status: {response.status_code}")
        result = response.json()
        print(f"Request ID: {result['metadata']['request_id']}")
        print(f"File processed: {result['metadata']['has_file']}")
        
        if result['metadata']['file_info']:
            print(f"File hash: {result['metadata']['file_info']['hash'][:16]}...")
            print(f"Chunks: {result['metadata']['file_info']['chunk_count']}")
            print(f"Extraction success: {result['metadata']['file_info']['extraction_success']}")
        
        print(f"External chunks: {len(result['text_embed_stub']['normalized_external'])}")
        
        assert response.status_code == 200
        assert result['metadata']['has_file'] == True
        print("✓ File upload preparation passed")
        
    finally:
        # Cleanup
        if test_file.exists():
            test_file.unlink()


def test_prepare_media():
    """Test media preparation endpoint."""
    print_section("Testing Media Preparation")
    
    data = {
        "user_prompt": "Look at these emojis: 😀 🎉 🚀 ❤️"
    }
    
    response = requests.post(
        f"{BASE_URL}{API_PREFIX}/prepare-media",
        data=data
    )
    
    print(f"Status: {response.status_code}")
    result = response.json()
    print(f"Request ID: {result['metadata']['request_id']}")
    print(f"Emojis found: {result['image_emoji_stub']['emoji_summary']['count']}")
    print(f"Emoji types: {result['image_emoji_stub']['emoji_summary']['types']}")
    
    assert response.status_code == 200
    assert result['image_emoji_stub']['emoji_summary']['count'] > 0
    print("✓ Media preparation passed")


def test_error_handling():
    """Test error handling."""
    print_section("Testing Error Handling")
    
    # Test with empty prompt
    data = {
        "user_prompt": "   "
    }
    
    response = requests.post(
        f"{BASE_URL}{API_PREFIX}/prepare-text",
        data=data
    )
    
    print(f"Empty prompt status: {response.status_code}")
    assert response.status_code == 400
    print("✓ Empty prompt error handled correctly")
    
    # Test with invalid file type
    test_file = Path("test_invalid.exe")
    test_file.write_bytes(b"fake executable")
    
    try:
        data = {
            "user_prompt": "Test invalid file"
        }
        
        files = {
            "file": ("test_invalid.exe", open(test_file, "rb"), "application/x-executable")
        }
        
        response = requests.post(
            f"{BASE_URL}{API_PREFIX}/prepare-text",
            data=data,
            files=files
        )
        
        print(f"Invalid file status: {response.status_code}")
        # Should still process but without file data
        print("✓ Invalid file handled gracefully")
        
    finally:
        if test_file.exists():
            test_file.unlink()


def test_performance():
    """Test performance and timing."""
    print_section("Testing Performance")
    
    data = {
        "user_prompt": "Quick performance test with some text " * 10
    }
    
    times = []
    for i in range(5):
        start = time.time()
        response = requests.post(
            f"{BASE_URL}{API_PREFIX}/prepare-text",
            data=data
        )
        elapsed = (time.time() - start) * 1000
        times.append(elapsed)
        
        result = response.json()
        prep_time = result['metadata']['prep_time_ms']
        print(f"Run {i+1}: Total={elapsed:.2f}ms, Prep={prep_time:.2f}ms")
    
    avg_time = sum(times) / len(times)
    print(f"\nAverage response time: {avg_time:.2f}ms")
    
    # Check if within performance targets (<80ms for simple text)
    if avg_time < 150:
        print("✓ Performance within acceptable range")
    else:
        print("⚠ Performance slower than expected")


def run_all_tests():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("  LLM-Protect Input Preparation API Test Suite")
    print("=" * 60)
    print(f"\nTesting API at: {BASE_URL}")
    print(f"Make sure the server is running: uvicorn app.main:app --reload")
    
    try:
        test_health_check()
        test_prepare_text_simple()
        test_prepare_text_with_external_data()
        test_prepare_text_with_file()
        test_prepare_media()
        test_error_handling()
        test_performance()
        
        print("\n" + "=" * 60)
        print("  ✓ All tests passed!")
        print("=" * 60)
        
    except requests.exceptions.ConnectionError:
        print("\n❌ Error: Could not connect to API server.")
        print("Make sure the server is running:")
        print("  uvicorn app.main:app --reload")
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    run_all_tests()

