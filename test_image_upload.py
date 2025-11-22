#!/usr/bin/env python3
"""
Test image upload functionality through the web API.
"""

import requests
from pathlib import Path

BASE_URL = "http://localhost:8000/api/v1"

def test_image_upload():
    """Test uploading a PNG image."""
    print("=" * 70)
    print("  TESTING IMAGE UPLOAD")
    print("=" * 70)
    
    # Create a simple test image if one doesn't exist
    print("\n1. Checking for test image...")
    
    # Try to find any PNG in test_samples or create one
    test_image_path = None
    possible_paths = [
        "test_samples/test.png",
        "uploads/test.png",
        "/tmp/test.png"
    ]
    
    for path in possible_paths:
        if Path(path).exists():
            test_image_path = path
            print(f"   ✓ Found test image: {test_image_path}")
            break
    
    if not test_image_path:
        # Create a simple 1x1 PNG
        print("   Creating test PNG image...")
        try:
            from PIL import Image
            img = Image.new('RGB', (100, 100), color='red')
            test_image_path = '/tmp/test.png'
            img.save(test_image_path)
            print(f"   ✓ Created test image: {test_image_path}")
        except ImportError:
            print("   ⚠ Pillow not available, cannot create test image")
            print("   Please provide a test PNG manually")
            return
    
    # Test upload
    print("\n2. Uploading image through API...")
    
    with open(test_image_path, 'rb') as f:
        files = {'file': ('test.png', f, 'image/png')}
        data = {'user_prompt': 'Analyze this image'}
        
        try:
            response = requests.post(
                f"{BASE_URL}/prepare-text",
                data=data,
                files=files,
                timeout=30
            )
            
            print(f"   Response status: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                print("   ✓ Upload successful!")
                print(f"   Request ID: {result['metadata']['request_id'][:16]}...")
                print(f"   Has media: {result['metadata']['has_media']}")
                
                if result['image_emoji_stub']['image']:
                    image_info = result['image_emoji_stub']['image']
                    print(f"   Image format: {image_info.get('format', 'N/A')}")
                    print(f"   Image dimensions: {image_info.get('dimensions', 'N/A')}")
                    print("   ✅ Image processed successfully!")
                else:
                    print("   ⚠ No image info in response")
            else:
                print(f"   ✗ Upload failed: {response.status_code}")
                print(f"   Error: {response.text[:200]}")
                
        except Exception as e:
            print(f"   ✗ Request failed: {e}")
    
    print("\n" + "=" * 70)

if __name__ == "__main__":
    test_image_upload()

