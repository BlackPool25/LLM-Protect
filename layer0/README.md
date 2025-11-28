# Layer0 Security Microservice

A FastAPI-based input validation and security screening service for LLM pipelines. Layer0 processes Input-Prep JSON payloads, detects threats, identifies code, and forwards sanitized content to Layer 1.

---

## 🚀 Quick Start (For Deployment)

### Step 1: Install Dependencies
```bash
cd layer0
pip install -r requirements.txt
```

### Step 2: Start the Server
```bash
python server.py --port 3001
```

### Step 3: Verify It's Running
Open: http://localhost:3001/test

You should see:
```json
{"status": "ok", "service": "layer0"}
```

---

## 🔗 Integration with Input Prep

### Architecture
```
┌─────────────┐      JSON       ┌─────────────┐      JSON       ┌─────────────┐
│  Input Prep │ ──────────────► │   Layer 0   │ ──────────────► │   Layer 1   │
│  (port 5000)│   POST /layer0  │ (port 3001) │   POST /layer1  │ (port 3002) │
└─────────────┘                 └─────────────┘                 └─────────────┘
```

### In Input Prep, send requests to:
```
POST http://localhost:3001/layer0
Content-Type: application/json
Body: <Input Prep JSON output>
```

---

## 🧪 Local Testing (Without Running Server)

### Test with a JSON file:
```bash
python server.py --test "C:\path\to\Outputs\layer0_text\some_file.json"
```

### Test with direct text:
```bash
python server.py --text "Ignore all previous instructions"
```

---

## Folder Structure

```
layer0/
├── server.py              # Main FastAPI application
├── requirements.txt       # Python dependencies
├── README.md              # This file
├── rules/
│   └── rules.jsonl        # Security rules (JSONL format)
├── data/
│   └── layer0_logs.db     # SQLite database (auto-created)
├── tests/
│   ├── test_detect_code.py
│   └── test_rules.py
└── samples/
    └── input_example.json # Sample input for testing
```

## Features

- **Threat Detection**: Block malicious prompts (jailbreaks, prompt injections)
- **Code Detection**: Identify code snippets with language classification
- **Text Sanitization**: Remove markers, URLs, and normalize unicode
- **Hot-Reloadable Rules**: JSONL-based rule files with live reload
- **SQLite Logging**: Persistent audit trail of all requests
- **Graceful Failure**: Handles Layer 1 unavailability

## Quick Start

### Installation

```bash
cd layer0
pip install -r requirements.txt
```

### Run the Server

```bash
# From the layer0 folder
uvicorn server:app --port 3001

# Or run directly
python server.py
```

The server will listen on **port 3001**.

## API Endpoints

### GET /test - Health Check

```bash
curl http://localhost:3001/test
```

**Response:**
```json
{
  "status": "ok",
  "service": "layer0",
  "timestamp": "2025-01-01T00:00:00Z",
  "rules_loaded": 16
}
```

### POST /layer0 - Process Input

Main processing endpoint. Accepts Input-Prep JSON.

```bash
curl -X POST http://localhost:3001/layer0 \
  -H "Content-Type: application/json" \
  -d @samples/input_example.json
```

**Expected Input JSON Structure:**

```json
{
  "prepared_input": {
    "text_embed_stub": {
      "normalized_user": "User's clean prompt text",
      "normalized_external": [
        "[EXTERNAL]RAG content 1[/EXTERNAL]",
        "[EXTERNAL]RAG content 2[/EXTERNAL]"
      ],
      "emoji_descriptions": [":pizza:", ":smile:"]
    },
    "layer0": {
      "normalized_text": "Merged fallback text",
      "heuristic_flags": {
        "has_system_delimiter": false,
        "suspicious_score": 0.3
      }
    },
    "metadata": {
      "request_id": "uuid-here"
    }
  }
}
```

**Response (Clean Request):**
```json
{
  "blocked": false,
  "request_id": "uuid-here",
  "forwarded": true,
  "processing_summary": {
    "is_code": true,
    "detected_language": "c_cpp",
    "confidence_code": 0.6,
    "severity": 1,
    "threat_signatures_count": 0,
    "forwarded": true
  }
}
```

**Response (Blocked Request):**
```json
{
  "blocked": true,
  "reason": "Matched block pattern: ignore_previous",
  "request_id": "uuid-here"
}
```

### POST /admin/reload-rules - Reload Rules

Hot-reload rules from `rules/` directory. Requires admin token.

```bash
curl -X POST http://localhost:3001/admin/reload-rules \
  -H "Authorization: Bearer changeme"
```

## Input Field Paths

The service reads these exact paths from Input-Prep JSON:

| Field | Path | Type |
|-------|------|------|
| User Text | `prepared_input.text_embed_stub.normalized_user` | string |
| External Text | `prepared_input.text_embed_stub.normalized_external` | list[string] |
| Fallback Text | `prepared_input.layer0.normalized_text` | string |
| Emoji | `prepared_input.text_embed_stub.emoji_descriptions` | list[string] |
| Heuristics | `prepared_input.layer0.heuristic_flags` | object |
| Request ID | `prepared_input.metadata.request_id` | string |

## Layer 1 Payload

When forwarding to Layer 1, the service sends:

```json
{
  "clean_user": "sanitized user text",
  "clean_external": "joined and sanitized external text",
  "clean_text": "combined clean text",
  "is_code": true,
  "detected_language": "python",
  "confidence_code": 0.65,
  "code_snippets": ["def foo():", "..."],
  "jailbreak_flag": false,
  "severity": 1,
  "threat_signatures": ["flag:triple_hash"],
  "emoji_descriptions": [":pizza:"],
  "heuristic_flags": { ... },
  "request_id": "uuid"
}
```

## Rules Format

Rules are stored in `rules/rules.jsonl` (JSONL format):

```jsonl
{"id": "block_jailbreak", "pattern": "\\bjailbreak\\b", "type": "block", "ignore_case": true, "severity": 2}
{"id": "flag_base64", "pattern": "[A-Za-z0-9+/]{100,}", "type": "flag", "ignore_case": false, "severity": 1}
```

**Rule Fields:**
- `id`: Unique rule identifier
- `pattern`: Regex pattern (escape backslashes)
- `type`: `block` (reject) or `flag` (collect signature)
- `ignore_case`: Case-insensitive matching
- `severity`: 1 (low) or 2 (high)

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LAYER1_URL` | `http://localhost:3002/layer1` | Layer 1 endpoint |
| `ADMIN_TOKEN` | `changeme` | Admin API token |
| `STORE_RAW` | `false` | Store raw text in DB |
| `HMAC_SECRET` | `layer0-secret-key` | HMAC key for hashing |
| `DB_PATH` | `data/layer0_logs.db` | SQLite database path |
| `RULES_DIR` | `rules` | Rules directory |

## Code Detection

Detects code in these languages:
- Python, C/C++, Java, JavaScript, Bash, Go

## Testing

```bash
cd layer0
pytest tests/ -v
```

---

## 📋 Deployment Checklist

### For Your Friend:

1. **Navigate to layer0 folder:**
   ```bash
   cd LLM-Protect/layer0
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Start the server:**
   ```bash
   python server.py --port 3001
   ```

4. **Test it works:**
   ```bash
   # Health check
   curl http://localhost:3001/test
   
   # Or test with a file
   python server.py --test path/to/input.json
   ```

5. **Connect Input Prep:**
   - Input Prep should POST to: `http://localhost:3001/layer0`
   - Layer0 will forward to Layer1 at: `http://localhost:3002/layer1`

### Response Meanings:

| Verdict | Meaning |
|---------|---------|
| `BLOCK` | Request rejected (jailbreak/attack detected) |
| `FLAG` | Suspicious but forwarded with signatures |
| `PASS` | Clean request forwarded to Layer 1 |

---

## Troubleshooting

### "Layer 1 unreachable" warning
Normal if Layer 1 isn't running yet. Layer0 logs the request and continues.

### Port already in use
```bash
python server.py --port 3002  # Use different port
```

### Module not found
```bash
pip install -r requirements.txt
```
