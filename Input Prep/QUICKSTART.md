# Quick Start Guide

## 5-Minute Setup

### 1. Install Dependencies (1 min)

```bash
pip install -r requirements.txt
```

### 2. Start Server (30 sec)

```bash
uvicorn app.main:app --reload
```

Server running at: http://localhost:8000

### 3. Test Basic Request (1 min)

```bash
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=Hello, world! 🌍"
```

### 4. View API Documentation (30 sec)

Open in browser: http://localhost:8000/docs

### 5. Run Full Test Suite (2 min)

```bash
python test_api.py
```

## Example Requests

### Simple Text

```bash
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=What is machine learning?"
```

### With External Data (RAG)

```bash
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=Explain AI" \
  -F 'external_data=["AI is artificial intelligence", "It uses machine learning"]'
```

### With File Upload

```bash
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=Analyze this document" \
  -F "file=@test_samples/sample.txt"
```

### Media Processing

```bash
curl -X POST "http://localhost:8000/api/v1/prepare-media" \
  -F "user_prompt=Check these emojis: 😀 🚀 ❤️"
```

## Python Example

```python
import requests

# Prepare text
response = requests.post(
    "http://localhost:8000/api/v1/prepare-text",
    data={"user_prompt": "Hello, world!"}
)

result = response.json()
print(f"Tokens: {result['text_embed_stub']['stats']['token_estimate']}")
print(f"Time: {result['metadata']['prep_time_ms']:.2f}ms")
```

## What's Next?

1. Read the full [USAGE.md](USAGE.md) for detailed documentation
2. Check [README.md](README.md) for architecture details
3. Explore the interactive API docs at `/docs`
4. Integrate with Layer 0 (heuristics layer)

## Key Features

✅ **Fast**: 20-80ms processing time  
✅ **Secure**: HMAC-signed external data  
✅ **Multi-format**: TXT, MD, PDF, DOCX support  
✅ **RAG-ready**: External data processing  
✅ **Complete**: All metadata and timing info  

## Troubleshooting

**Can't connect?**
- Make sure server is running: `uvicorn app.main:app --reload`

**Import errors?**
- Reinstall dependencies: `pip install -r requirements.txt`

**HMAC key error?**
- Check `.env` file exists and has `HMAC_SECRET_KEY`

## Support

For detailed documentation, see:
- [USAGE.md](USAGE.md) - Complete usage guide
- [README.md](README.md) - Architecture and design
- API Docs: http://localhost:8000/docs

