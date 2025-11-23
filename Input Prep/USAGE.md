# Usage Guide - LLM-Protect Input Preparation Module

## Quick Start

### 1. Installation

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration

The `.env` file has been created with a secure HMAC key. You can modify settings:

```bash
# View current configuration
cat .env

# Customize settings as needed
nano .env
```

### 3. Start the Server

```bash
# Development mode (with auto-reload)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Production mode
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

The API will be available at: http://localhost:8000

- Interactive docs: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- Health check: http://localhost:8000/health

## API Endpoints

### 1. Health Check

**GET** `/health`

Check service status and library availability.

```bash
curl http://localhost:8000/health
```

Response:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2024-01-01T00:00:00Z",
  "libraries": {
    "txt": true,
    "md": true,
    "pdf": true,
    "docx": true,
    "image": true
  },
  "message": "All systems operational"
}
```

### 2. Text Preparation (for Layer 0)

**POST** `/api/v1/prepare-text`

Prepare text input with optional files and external data.

#### Basic Usage (Text Only)

```bash
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=What is the weather today?"
```

#### With External Data (RAG)

```bash
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=What is the weather today?" \
  -F 'external_data=["The forecast shows sunny conditions", "Temperature around 25C"]'
```

#### With File Upload

```bash
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=Analyze this document" \
  -F "file=@test_samples/sample.txt"
```

#### With File Path (Server-side)

```bash
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=Process this file" \
  -F "file_path=/path/to/document.pdf"
```

#### With Vector DB Retrieval

```bash
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=Tell me about AI" \
  -F "retrieve_from_vector_db=true"
```

#### Response Format

```json
{
  "text_embed_stub": {
    "normalized_user": "What is the weather today?",
    "normalized_external": [
      "[EXTERNAL]The forecast shows sunny conditions[/EXTERNAL]",
      "[EXTERNAL]Temperature around 25C[/EXTERNAL]"
    ],
    "emoji_descriptions": [],
    "hmacs": ["abc123...", "def456..."],
    "stats": {
      "char_total": 150,
      "token_estimate": 38,
      "user_external_ratio": 0.35,
      "file_chunks_count": 0,
      "extracted_total_chars": 0
    }
  },
  "image_emoji_stub": {
    "image": {},
    "emoji_summary": {
      "count": 0,
      "types": [],
      "descriptions": []
    }
  },
  "metadata": {
    "request_id": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2024-01-01T10:00:00Z",
    "rag_enabled": true,
    "has_media": false,
    "has_file": false,
    "file_info": null,
    "prep_time_ms": 45.2,
    "step_times": {
      "parse_validate": 0.5,
      "file_extraction": 0.0,
      "rag_processing": 2.1,
      "normalization": 3.2,
      "token_calculation": 1.8,
      "packaging": 0.3
    }
  }
}
```

### 3. Media Preparation (for Image/Emoji Processing)

**POST** `/api/v1/prepare-media`

Process images and emojis for specialized analysis.

#### With Emojis

```bash
curl -X POST "http://localhost:8000/api/v1/prepare-media" \
  -F "user_prompt=Look at these: 😀 🎉 🚀"
```

#### With Image Upload

```bash
curl -X POST "http://localhost:8000/api/v1/prepare-media" \
  -F "user_prompt=Analyze this image" \
  -F "image=@photo.jpg"
```

## Python Client Example

```python
import requests
import json

# Prepare text with external data
def prepare_text(prompt, external_data=None, file_path=None):
    url = "http://localhost:8000/api/v1/prepare-text"
    
    data = {"user_prompt": prompt}
    
    if external_data:
        data["external_data"] = json.dumps(external_data)
    
    files = None
    if file_path:
        files = {"file": open(file_path, "rb")}
    
    response = requests.post(url, data=data, files=files)
    
    if files:
        files["file"].close()
    
    return response.json()

# Example usage
result = prepare_text(
    prompt="What is AI?",
    external_data=["AI stands for Artificial Intelligence", "It's a field of computer science"]
)

print(f"Request ID: {result['metadata']['request_id']}")
print(f"Tokens: {result['text_embed_stub']['stats']['token_estimate']}")
print(f"RAG enabled: {result['metadata']['rag_enabled']}")
```

## Supported File Types

### Text Files
- **.txt** - Plain text files
- **.md** - Markdown documents

### Documents
- **.pdf** - PDF documents (requires PyMuPDF)
- **.docx** - Microsoft Word documents (requires python-docx)

### Images
- **.jpg, .jpeg** - JPEG images
- **.png** - PNG images
- **.gif** - GIF images
- **.webp** - WebP images
- **.bmp** - Bitmap images

## Performance Characteristics

Based on the design specifications:

| Operation | Target Time | Notes |
|-----------|-------------|-------|
| Parse/Validate | <1ms | Basic validation |
| TXT/MD Extraction | 1-5ms | Plain text files |
| PDF Extraction | 20-50ms | Depends on page count |
| DOCX Extraction | 15-40ms | Depends on content |
| RAG/HMAC Processing | 1-3ms | Per chunk |
| Text Normalization | 2-6ms | Per chunk |
| Media Processing | 5-10ms | If images present |
| Token Calculation | 5-10ms | Full input |
| **Total (Text only)** | **20-80ms** | Simple requests |
| **Total (With file)** | **40-130ms** | Including extraction |

## HMAC Verification

All external data chunks are signed with HMAC-SHA256:

```python
# External chunks are delimited and signed
chunk = "[EXTERNAL]content[/EXTERNAL]"
hmac = generate_hmac("content")  # Signs original content

# Verify integrity
is_valid = verify_hmac("content", hmac)
```

The HMAC signatures ensure:
- Data integrity (no tampering)
- Non-repudiation (chunks came from this system)
- Protection against prompt injection through external data

## Error Handling

The API handles errors gracefully:

### Client Errors (400)
- Empty or whitespace-only prompts
- Invalid file types
- Files exceeding size limits
- Malformed JSON in external_data

### Server Errors (500)
- File extraction failures
- Processing errors
- Payload validation failures

All errors return structured responses with details.

## Testing

Run the comprehensive test suite:

```bash
# Make sure server is running
uvicorn app.main:app --reload

# In another terminal, run tests
python test_api.py
```

Test individual components:

```bash
# Test file extraction
python -c "from app.services.file_extractor import extract_file_text; print(extract_file_text('test_samples/sample.txt'))"

# Test HMAC
python -c "from app.utils.hmac_utils import generate_hmac; print(generate_hmac('test'))"

# Test normalization
python -c "from app.services.text_normalizer import normalize_text; print(normalize_text('Hello  world!'))"
```

## Integration with Layer 0

The prepared output is designed to feed directly into Layer 0 (heuristics layer):

```python
# Layer 0 receives the prepared input
prepared = api_response

# Access normalized text
user_text = prepared['text_embed_stub']['normalized_user']
external_chunks = prepared['text_embed_stub']['normalized_external']

# Verify HMAC signatures
hmacs = prepared['text_embed_stub']['hmacs']
for chunk, sig in zip(external_chunks, hmacs):
    # Extract content from delimiters
    content = chunk.replace('[EXTERNAL]', '').replace('[/EXTERNAL]', '')
    is_valid = verify_hmac(content, sig)
    
    if not is_valid:
        # Handle tampered data
        raise SecurityError("HMAC verification failed")

# Proceed with heuristics checks...
```

## Vector Database Integration (Future)

Placeholder for vector DB integration in `app/services/rag_handler.py`:

```python
def retrieve_from_vector_db(query: str, top_k: int = 5):
    # Example with ChromaDB
    from chromadb import Client
    client = Client()
    collection = client.get_collection("documents")
    results = collection.query(query_texts=[query], n_results=top_k)
    return results['documents'][0]
```

## Monitoring and Logging

All requests are logged with:
- Request ID (UUID)
- Timing breakdown per step
- Token/character counts
- File information
- Error details

Example log output:
```
2024-01-01 10:00:00 | INFO | [550e8400...] Starting request processing
2024-01-01 10:00:00 | DEBUG | [550e8400...] Step 'rag_processing' completed in 2.10ms
2024-01-01 10:00:00 | INFO | [550e8400...] Request completed in 45.20ms
2024-01-01 10:00:00 | INFO | Request: 550e8400... | Time: 45.20ms | Tokens: 38 | External chunks: 2
```

## Security Considerations

1. **HMAC Secret Key**: Keep the `HMAC_SECRET_KEY` secure and rotate periodically
2. **File Uploads**: Validate file types and sizes to prevent abuse
3. **Input Validation**: All inputs are validated before processing
4. **No External Modification**: HMAC signatures prevent tampering with external data
5. **Logging**: Sensitive data should not be logged (currently logs metadata only)

## 💾 Output Saving

All successfully processed inputs are automatically saved to disk for auditing, debugging, and analysis.

### Directory Structure

```
/home/lightdesk/Projects/LLM-Protect/Outputs/
├── layer0_text/          # Text processing outputs
│   └── *.json            # Saved Layer 0 preparations
└── media_processing/     # Media processing outputs
    └── *.json            # Saved media preparations
```

### Automatic Saving

- **Layer 0 outputs**: Saved after successful `/api/v1/prepare-text` requests
- **Media outputs**: Saved after successful `/api/v1/prepare-media` requests
- **Format**: JSON with complete PreparedInput data plus save timestamp
- **Filename**: `YYYYMMDD_HHMMSS_<type>_<request_id>_<text_preview>.json`

### View Output Statistics

**GET** `/api/v1/output-stats`

Returns statistics about saved outputs:

```bash
curl http://localhost:8000/api/v1/output-stats
```

**Response**:
```json
{
  "base_directory": "/home/lightdesk/Projects/LLM-Protect/Outputs",
  "layer0_outputs": 25,
  "media_outputs": 10,
  "total_outputs": 35,
  "recent_layer0_files": ["20251122_103045_layer0_a1b2c3d4_What.json", ...],
  "recent_media_files": ["20251122_103512_media_e5f6g7h8_Check.json", ...]
}
```

### Output File Format

Each saved file contains:

```json
{
  "processing_type": "layer0_text",  // or "media_processing"
  "saved_at": "2025-11-22T10:30:45Z",
  "prepared_input": {
    // Complete PreparedInput object
  }
}
```

### Benefits

1. **Audit Trail**: Complete record of all processed requests
2. **Debugging**: Easy inspection of prepared inputs
3. **Testing**: Can replay or analyze saved outputs
4. **Compliance**: Maintains records for security monitoring
5. **Analysis**: Useful for training data or research

### Cleanup Old Outputs

To manage disk space:

```bash
# Remove Layer 0 outputs older than 7 days
find Outputs/layer0_text/ -name "*.json" -mtime +7 -delete

# Remove media outputs older than 7 days
find Outputs/media_processing/ -name "*.json" -mtime +7 -delete

# Or remove all test outputs
rm -rf Outputs/layer0_text/* Outputs/media_processing/*
```

### Programmatic Access

Load and analyze saved outputs:

```python
import json
from pathlib import Path

# Load a saved output
output_file = Path("Outputs/layer0_text/20251122_103045_layer0_a1b2c3d4_What.json")
with open(output_file) as f:
    data = json.load(f)

# Access the data
prepared = data['prepared_input']
print(f"Request: {prepared['metadata']['request_id']}")
print(f"User text: {prepared['text_embed_stub']['normalized_user']}")
print(f"Tokens: {prepared['text_embed_stub']['stats']['token_estimate']}")
```

See `Outputs/README.md` for detailed documentation.

## Troubleshooting

### Library Import Errors

If you see warnings about missing libraries:

```bash
# Install missing libraries
pip install PyMuPDF python-docx emoji Pillow tiktoken

# Or reinstall all dependencies
pip install -r requirements.txt --force-reinstall
```

### HMAC Key Error

If you see "HMAC_SECRET_KEY must be set":

```bash
# Generate a new key
python3 -c "import secrets; print('HMAC_SECRET_KEY=' + secrets.token_hex(32))" > .env
```

### Performance Issues

If processing is slower than expected:

1. Check file sizes (large PDFs take longer)
2. Reduce external data chunks
3. Use simpler token estimation (set `accurate=False`)
4. Monitor step timing in response metadata

## Next Steps

After the Input Preparation Module:

1. **Layer 0**: Implement heuristics (regex, separator detection, latency ~1ms)
2. **Layer 1**: Semantic guard with embeddings (isolation forest, latency ~15-80ms)
3. **Layer 2**: LLM inference (Gemma 2B, latency ~300-3000ms)

The output format is designed to integrate seamlessly with these layers.

