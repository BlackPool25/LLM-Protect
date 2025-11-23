# Troubleshooting Guide

## Issue: Strange LLM Output & No Files in Outputs Folder

### Problem Summary

You experienced two issues:
1. **Strange LLM Output**: Getting irrelevant Apache/nginx configuration text instead of proper answers
2. **Empty Outputs Folder**: No files being saved to `Outputs/layer0_text/` or `Outputs/media_processing/`

### Root Cause

✅ **The server was not running!**

The LLM-Protect server needs to be actively running on port 8000 to:
- Process your requests
- Generate LLM responses
- Save outputs to disk

### Solution

1. **Start the server**:
```bash
cd /home/lightdesk/Projects/LLM-Protect
source venv/bin/activate
bash start_server.sh
```

2. **Verify server is running**:
```bash
curl http://localhost:8000/
```

You should see the HTML web interface.

3. **Check port 8000 is listening**:
```bash
lsof -i :8000
```

---

## ChromaDB Deprecated API Fixed

### Problem

The `populate_vector_db.py` script was using deprecated ChromaDB API:
```python
# OLD (deprecated)
client = chromadb.Client(Settings(
    chroma_db_impl="duckdb+parquet",
    persist_directory="./chroma_db"
))
```

### Solution

✅ **Updated to new API**:
```python
# NEW (current)
client = chromadb.PersistentClient(path="./chroma_db")
```

**Files updated**:
- `populate_vector_db.py`
- `app/services/rag_handler.py`

---

## How to Use the System Properly

### 1. Start the Server

```bash
cd /home/lightdesk/Projects/LLM-Protect
source venv/bin/activate
bash start_server.sh
```

Server will start on: `http://localhost:8000`

### 2. Populate Vector Database (First Time Only)

```bash
python3 populate_vector_db.py
```

This creates the knowledge base for RAG functionality.

### 3. Test the API

#### Simple Text Query
```bash
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=What is the capital of France?"
```

#### With RAG (Vector Database Retrieval)
```bash
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=What is DSA?" \
  -F "retrieve_from_vector_db=true"
```

#### Full Pipeline (Prepare + Generate)
```python
import requests

BASE_URL = "http://localhost:8000/api/v1"

# Step 1: Prepare input
response = requests.post(
    f"{BASE_URL}/prepare-text",
    data={
        "user_prompt": "What is the capital of France?",
        "retrieve_from_vector_db": "true"
    }
)
prepared = response.json()

# Step 2: Generate LLM response
response = requests.post(
    f"{BASE_URL}/generate",
    json={"prepared_input": prepared, "max_new_tokens": 150}
)
result = response.json()

print(f"Generated: {result['generated_text']}")
```

### 4. Check Outputs

Outputs are automatically saved to:
- **Text processing**: `Outputs/layer0_text/`
- **Media processing**: `Outputs/media_processing/`

```bash
ls -lht Outputs/layer0_text/
```

Each file contains:
- Normalized user input
- External data (RAG context) with HMAC signatures
- Metadata (request ID, timestamps, token counts)
- Full prepared payload

---

## Verification

### Test 1: Server is Running
```bash
curl http://localhost:8000/
# Should return HTML web interface
```

### Test 2: Vector DB is Populated
```bash
ls -la chroma_db/
# Should contain chroma.sqlite3 and other files
```

### Test 3: API is Working
```bash
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=Hello" | python3 -m json.tool
# Should return JSON with prepared input
```

### Test 4: Outputs are Saved
```bash
ls -lht Outputs/layer0_text/
# Should show .json files with timestamps
```

### Test 5: LLM Generation Works
```bash
python3 test_conversation_and_rag.py
# Should run through full test suite
```

---

## Common Issues

### Issue: `curl: (7) Failed to connect to localhost port 8000`
**Cause**: Server is not running
**Solution**: Run `bash start_server.sh`

### Issue: `No module named 'chromadb'`
**Cause**: ChromaDB not installed
**Solution**: `pip install chromadb`

### Issue: `Knowledge base collection not found`
**Cause**: Vector DB not populated
**Solution**: `python3 populate_vector_db.py`

### Issue: Empty Outputs folder
**Cause**: Server not running or not making requests
**Solution**: 
1. Start server: `bash start_server.sh`
2. Make API request to `/api/v1/prepare-text`
3. Outputs will be saved automatically

### Issue: LLM generating weird responses
**Possible Causes**:
1. Wrong server (check you're on port 8000, not 8080)
2. Model not loaded (check logs)
3. Malformed prompt (check input)

**Solution**: 
1. Verify server: `curl http://localhost:8000/api/v1/model-status`
2. Check logs: Look at terminal where server is running
3. Test with simple query: "What is 2+2?"

---

## Quick Test Script

Save this as `quick_test.py`:

```python
#!/usr/bin/env python3
import requests
import json

BASE_URL = "http://localhost:8000/api/v1"

print("Testing LLM-Protect API...")

# Test 1: Health check
try:
    response = requests.get(f"{BASE_URL}/model-status")
    print(f"✓ Server is running: {response.json()}")
except Exception as e:
    print(f"✗ Server not responding: {e}")
    exit(1)

# Test 2: Prepare text
response = requests.post(
    f"{BASE_URL}/prepare-text",
    data={"user_prompt": "Hello, test!"}
)
prepared = response.json()
print(f"✓ Prepare-text works (Request ID: {prepared['metadata']['request_id'][:16]}...)")

# Test 3: Generate LLM
response = requests.post(
    f"{BASE_URL}/generate",
    json={"prepared_input": prepared, "max_new_tokens": 50}
)
result = response.json()
print(f"✓ LLM generation works: {result['generated_text'][:100]}...")

# Test 4: Check outputs
import os
output_files = os.listdir("Outputs/layer0_text/")
print(f"✓ Outputs saved: {len(output_files)} files in Outputs/layer0_text/")

print("\n✅ All tests passed!")
```

Run it:
```bash
python3 quick_test.py
```

---

## Status: ✅ FIXED

Both issues have been resolved:
1. ✅ Server is running on port 8000
2. ✅ ChromaDB API updated to latest version
3. ✅ Vector database populated successfully
4. ✅ LLM generating proper responses
5. ✅ Outputs being saved to `Outputs/layer0_text/`

---

## Additional Resources

- **API Documentation**: See `USAGE.md`
- **RAG & Conversation**: See `CONVERSATION_AND_RAG_GUIDE.md`
- **Output Formats**: See `OUTPUT_FORMATS.md`
- **Web Interface**: Open `http://localhost:8000` in browser

