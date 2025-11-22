# Conversation Memory & RAG Guide

## Overview

Your LLM-Protect system now supports:
1. **Conversation Memory**: Multi-turn conversations with context like ChatGPT
2. **RAG (Vector Database)**: Knowledge base retrieval for enhanced responses

## 🧠 Feature 1: Conversation Memory

### What It Does

Maintains conversation history across multiple requests so the LLM can understand context from previous messages.

**Example**:
```
User: "What is DSA?"
Bot: "DSA is Data Structures and Algorithms..."

User: "How do I learn it?"
Bot: "To learn DSA..." ← Bot remembers "it" means DSA!
```

### How It Works

1. **Session Creation**: Each conversation gets a unique session ID
2. **Message Storage**: User and assistant messages are stored in memory
3. **Context Injection**: Previous messages are added as external_data (with HMAC)
4. **Automatic Cleanup**: Sessions expire after 60 minutes of inactivity

### API Usage

#### Create a Session

```bash
curl -X POST http://localhost:8000/api/v1/sessions/create
```

Response:
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "message": "Session created successfully"
}
```

#### Use Session in Requests

```bash
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=What is DSA?" \
  -F "session_id=550e8400-e29b-41d4-a716-446655440000" \
  -F "use_conversation_history=true"
```

#### Follow-up Question (with Context)

```bash
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=How do I learn it in 2 months?" \
  -F "session_id=550e8400-e29b-41d4-a716-446655440000" \
  -F "use_conversation_history=true"
```

The system will automatically:
1. Retrieve last 5 messages from session
2. Format them as conversation context
3. Add as [EXTERNAL] data with HMAC signatures
4. Send to LLM with current question

#### Get Session Info

```bash
curl http://localhost:8000/api/v1/sessions/550e8400-e29b-41d4-a716-446655440000
```

Response:
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "message_count": 4,
  "messages": [
    {"role": "user", "content": "What is DSA?", "timestamp": 1700000000},
    {"role": "assistant", "content": "DSA is...", "timestamp": 1700000001},
    ...
  ],
  "inactive_seconds": 45.2
}
```

#### Clear Session

```bash
curl -X POST http://localhost:8000/api/v1/sessions/550e8400-.../clear
```

#### Delete Session

```bash
curl -X DELETE http://localhost:8000/api/v1/sessions/550e8400-...
```

#### List All Sessions

```bash
curl http://localhost:8000/api/v1/sessions
```

### Configuration

In `app/services/session_manager.py`:

```python
SessionManager(
    max_inactive_minutes=60,      # Session expires after 60 min
    max_messages_per_session=20,  # Keep last 20 messages
    cleanup_interval_seconds=300  # Cleanup every 5 minutes
)
```

### Security Features

✅ **HMAC Protection**: Conversation history is treated as external_data
✅ **Delimiters**: Wrapped in `[EXTERNAL]` tags
✅ **Source Tracking**: Tagged as conversation context
✅ **Tampering Detection**: Layer 0 can verify HMAC signatures

---

## 📚 Feature 2: RAG (Vector Database)

### What It Does

Retrieves relevant information from a knowledge base to enhance LLM responses.

**Example**:
```
User: "What is the capital of France?"

Vector DB retrieves: "Paris is the capital of France..."
                   ↓
LLM receives: User question + Retrieved context
                   ↓
LLM responds with accurate, context-aware answer
```

### How It Works

1. **Storage**: Documents are converted to embeddings and stored in ChromaDB
2. **Retrieval**: User query is converted to embedding
3. **Search**: Find most similar documents (cosine similarity)
4. **Injection**: Retrieved documents added as external_data
5. **HMAC**: All retrieved content gets HMAC signatures

### Setup

#### Install ChromaDB

```bash
pip install chromadb
```

Or add to your environment:
```bash
cd /home/lightdesk/Projects/LLM-Protect
source venv/bin/activate
pip install chromadb
```

#### Populate Knowledge Base

```bash
python populate_vector_db.py
```

This creates a `chroma_db/` directory with sample knowledge about:
- Programming (DSA, Python, ML)
- Education & learning tips
- General knowledge
- Security concepts
- Sample conversation responses

#### Add Your Own Documents

Modify `populate_vector_db.py` to add your documents:

```python
documents = [
    "Your custom knowledge here",
    "More information about your domain",
    ...
]
```

### API Usage

#### Enable RAG in Requests

```bash
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=What is the capital of France?" \
  -F "retrieve_from_vector_db=true"
```

The system will:
1. Convert question to embedding
2. Search ChromaDB for similar documents (top 5)
3. Add retrieved docs as [EXTERNAL] data
4. Apply HMAC signatures
5. Send to LLM with original question

#### Combine with Conversation Memory

```bash
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=How do I learn DSA?" \
  -F "session_id=550e8400-..." \
  -F "use_conversation_history=true" \
  -F "retrieve_from_vector_db=true"
```

This combines:
- Conversation history (last 5 messages)
- Vector DB knowledge (top 5 documents)
- All with HMAC signatures for security

### Configuration

In `app/services/rag_handler.py`, the `retrieve_from_vector_db` function:

```python
def retrieve_from_vector_db(query: str, top_k: int = 5):
    # Returns top 5 most relevant documents
    # Stored in ./chroma_db/
    # Collection name: "knowledge_base"
```

### Security Features

✅ **HMAC Protection**: All retrieved documents signed
✅ **Delimiters**: Wrapped in `[EXTERNAL]` tags
✅ **Source Tracking**: Tagged as "from vector DB"
✅ **RAG Poisoning Defense**: Layer 0 can detect modified content

---

## 🔐 Security Implications

### Why Security Matters

Both features introduce **new attack surfaces**:

1. **Conversation Poisoning**: Attacker injects malicious message into history
2. **RAG Poisoning**: Attacker adds malicious documents to vector DB

### How We Defend

#### All External Data is Secured:

```python
# Conversation history
"[EXTERNAL]Previous: User asked 'What is DSA?'
            Bot replied 'DSA is...'[/EXTERNAL]"
HMAC: abc123...

# RAG retrieved
"[EXTERNAL]Paris is the capital of France[/EXTERNAL]"
HMAC: def456...
```

#### Layer 0 Verification (TODO):

```python
# In Layer 0 (not yet implemented)
for chunk, hmac in zip(external_chunks, hmacs):
    if not verify_hmac(chunk, hmac):
        return {"error": "Tampered data detected!"}
```

---

## 📊 Complete Example

### Python Script

```python
import requests

BASE_URL = "http://localhost:8000/api/v1"

# 1. Create session
resp = requests.post(f"{BASE_URL}/sessions/create")
session_id = resp.json()["session_id"]

# 2. First question with RAG
resp = requests.post(
    f"{BASE_URL}/prepare-text",
    data={
        "user_prompt": "What is DSA?",
        "session_id": session_id,
        "retrieve_from_vector_db": "true"
    }
)
prepared = resp.json()

# 3. Generate response
resp = requests.post(
    f"{BASE_URL}/generate",
    json={"prepared_input": prepared, "max_new_tokens": 150}
)
result = resp.json()
print(f"Bot: {result['generated_text']}")

# 4. Follow-up (with conversation memory + RAG)
resp = requests.post(
    f"{BASE_URL}/prepare-text",
    data={
        "user_prompt": "How do I learn it?",
        "session_id": session_id,
        "use_conversation_history": "true",
        "retrieve_from_vector_db": "true"
    }
)
prepared = resp.json()

# 5. Generate response
resp = requests.post(
    f"{BASE_URL}/generate",
    json={"prepared_input": prepared, "max_new_tokens": 150}
)
result = resp.json()
print(f"Bot: {result['generated_text']}")
```

### What Happens Behind the Scenes

```
Request 2 normalized_external contains:
  1. "[EXTERNAL]Previous conversation...[/EXTERNAL]" ← From session
  2. "[EXTERNAL]DSA is Data Structures...[/EXTERNAL]" ← From vector DB  
  3. "[EXTERNAL]To learn DSA...[/EXTERNAL]" ← From vector DB
  
All with HMAC signatures: ["abc123...", "def456...", "ghi789..."]

LLM sees:
  User: "How do I learn it?"
  Context: Previous conversation + Knowledge base
  
LLM generates contextually aware response!
```

---

## 🧪 Testing

### Automated Test

```bash
python test_conversation_and_rag.py
```

This tests:
1. ✅ Session creation
2. ✅ Multi-turn conversation
3. ✅ Context retention
4. ✅ RAG retrieval
5. ✅ Session management

### Manual Testing

See test commands above or use the web interface at `http://localhost:8000`.

---

## 📁 File Structure

```
/home/lightdesk/Projects/LLM-Protect/
├── app/
│   └── services/
│       ├── session_manager.py       # NEW: Conversation memory
│       ├── rag_handler.py           # UPDATED: Vector DB implementation
│       └── ...
├── chroma_db/                        # NEW: Vector database storage
├── populate_vector_db.py            # NEW: Setup script
├── test_conversation_and_rag.py    # NEW: Test script
└── requirements.txt                 # UPDATED: Added chromadb
```

---

## 🎯 Next Steps

1. **Populate Your Knowledge Base**:
   ```bash
   python populate_vector_db.py
   ```

2. **Test the Features**:
   ```bash
   python test_conversation_and_rag.py
   ```

3. **Implement Layer 0**: Add HMAC verification to detect tampering

4. **Production Considerations**:
   - Use persistent session storage (Redis/PostgreSQL)
   - Implement rate limiting
   - Add authentication
   - Monitor session/vector DB usage

---

## 🐛 Troubleshooting

### ChromaDB Not Installed

```bash
pip install chromadb
```

### Vector DB Empty

```bash
python populate_vector_db.py
```

### Session Not Found

Sessions expire after 60 minutes of inactivity. Create a new one:

```bash
curl -X POST http://localhost:8000/api/v1/sessions/create
```

### No Context in Responses

Check:
1. `use_conversation_history=true` is set
2. `retrieve_from_vector_db=true` for RAG
3. Session has previous messages
4. Vector DB is populated

---

## 📚 Additional Resources

- [OUTPUT_FORMATS.md](OUTPUT_FORMATS.md) - Data formats and flows
- [USAGE.md](USAGE.md) - API usage guide
- [ANSWERS_TO_YOUR_QUESTIONS.md](ANSWERS_TO_YOUR_QUESTIONS.md) - Detailed explanations
- [ChromaDB Docs](https://docs.trychroma.com/) - Vector database documentation

---

**Congratulations! Your LLM-Protect system now has conversation memory and knowledge base retrieval! 🎉**

