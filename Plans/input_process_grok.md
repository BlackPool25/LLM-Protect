
This extends your prior checklist to handle *common file uploads* (TXT, MD, PDF, DOCX; ignore exotics like XLSX for now—use openpyxl if needed). **Only extraction + conversion to text**—no analysis here (defer to layers). If file: Read → extract plain text → split into ~500-char chunks → add to external_data for RAG-like treatment (delimit/HMAC). Preserves originals for forensics. Total steps now 7; still <60ms on CPU (extraction ~20-40ms avg for <10MB files). Aligned: Feeds "Text + Embed Stub" with doc text for heuristics/embeddings; images unchanged.

#### **Processing Order (Updated Flowchart-Aligned)**
1. Parse raw (now includes file_path optional) → 1.5. Extract file text (if present) → 2. RAG/External merge (now includes file chunks) → 3. Normalize → 4. Media stubs → 5. Token prep → 6. Package → READY.

#### **1. Parse and Validate Raw Input (Updated)**
   - Receive: `{"user_prompt": str, "external_data": list[str] or None, "file_path": str or None, "image_path": str or None}` (add file_path for uploads).
   - Validate: File exists, <10MB, allowed types (txt/md/pdf/docx—case-insensitive ext check). Reject others (e.g., .exe) with metadata flag (but pass empty).
   - Generate request ID/timestamp.
   - **New**: If file, flag type for extraction.
   ```python
   import os
   import uuid
   from datetime import datetime
   ALLOWED_EXTS = {'.txt', '.md', '.pdf', '.docx'}
   def parse_raw(user_prompt, external_data=None, file_path=None, image_path=None):
       parsed = {
           "request_id": str(uuid.uuid4()),
           "timestamp": datetime.utcnow().isoformat(),
           "raw_user": user_prompt,
           "raw_external": external_data or [],
           "raw_file": file_path if file_path and os.path.isfile(file_path) and os.path.splitext(file_path)[1].lower() in ALLOWED_EXTS else None,
           "raw_image": image_path,
           "validation": {"file_valid": bool(file_path and os.path.getsize(file_path) < 10*1024*1024) if file_path else False}
       }
       if not parsed["validation"]["file_valid"]:
           parsed["raw_file"] = None  # Skip invalid
       return parsed
   ```

#### **1.5. File Upload Text Extraction (New Step)**
   - If file_path: Extract plain text based on type → chunk into list[str] (~500 chars each, overlap 50 for context) → treat as initial external_data.
     - **TXT**: Built-in open() + .read().
     - **MD**: open() + .read() (Markdown is plain text).
     - **PDF**: Use pdfplumber (pre-install offline: ~5MB; extract_text() per page, concat).
     - **DOCX**: Use python-docx (pre-install: ~1MB; iterate paragraphs/tables, .text).
   - Chunking: Simple split on sentences/periods to avoid mid-word breaks.
   - Store: Original file hash (SHA256) + extracted chunks + page/char counts.
   - If no file/external: Empty list.
   - **Why?** Converts uploads to detectable text; aligns with RAG poisoning defense. Latency: TXT/MD <5ms; PDF/DOCX 20-50ms (small files).
   - **Lib Note**: For offline hackathon, bundle via requirements.txt + Docker (TM1 Week 4). If env blocks (no pip), fallback to TXT/MD only—flag in dashboard.
   ```python
   import hashlib
   # Assume pre-installed: pip install pdfplumber python-docx (offline wheel)
   try:
       import pdfplumber
       from docx import Document
   except ImportError:
       pdfplumber = None  # Fallback msg in metadata
   def extract_file_text(file_path):
       if not file_path:
           return []
       with open(file_path, 'rb') as f:
           file_hash = hashlib.sha256(f.read()).hexdigest()
       ext = os.path.splitext(file_path)[1].lower()
       text = ""
       if ext == '.txt' or ext == '.md':
           with open(file_path, 'r', encoding='utf-8') as f:
               text = f.read()
       elif ext == '.pdf' and pdfplumber:
           with pdfplumber.open(file_path) as pdf:
               text = '\n'.join(page.extract_text() or '' for page in pdf.pages)
       elif ext == '.docx' and 'Document' in globals():
           doc = Document(file_path)
           text = '\n'.join(para.text for para in doc.paragraphs)
       else:
           raise ValueError(f"Unsupported: {ext} (install pdfplumber/docx offline)")
       
       # Chunk: ~500 chars
       chunks = [text[i:i+500] for i in range(0, len(text), 450)]  # Overlap 50
       return [{"content": chunk, "source": file_path, "hash": file_hash, "chunk_id": i} for i, chunk in enumerate(chunks)]
   # Usage: file_chunks = extract_file_text(parsed["raw_file"])
   ```

#### **2. Handle RAG/External Data Separation (Updated)**
   - Merge: external_data + file_chunks (if any) → apply delimiters/HMAC per chunk (now includes file sources).
   - Update metadata: Add "file_extracted": True, chunk counts.
   - **Change**: File text becomes signed external chunks—enables indirect injection checks.
   ```python
   # Same as before, but input now: raw_external + file_chunks
   def process_external(all_chunks):  # all_chunks = raw_external + file_chunks
       # ... (delimit/HMAC as before)
       return signed_chunks
   ```

#### **3. Normalize Text (User + External/File Chunks)**
   - Apply to user_prompt *and each* external/file chunk (unchanged).
   - **New**: For file chunks, preserve source metadata in norm output (e.g., "source": "pdf_chunk_2").
   ```python
   # Extend normalize_text to return {"normalized": ..., "source": original_source}
   ```

#### **4. Create Media Stubs (Unchanged)**
   - Images/emojis only; files now text, so no overlap.

#### **5. Component Separation and Token Prep (Updated)**
   - Separate: user + external (now incl. file chunks).
   - Stats: Add "file_chunks_count", "extracted_chars_total".
   - Position map: Extend for multi-chunk external (cumulative ranges).
   ```python
   # Update stats: {"...": ..., "file_chunks": len(file_chunks), "extracted_total_chars": sum(len(c) for c in file_text)}
   ```

#### **6. Package Final Payloads/Stubs (Unchanged Core, Extended Fields)**
   - Same stubs, but enrich metadata/file-specific.

#### **7. Error Handling & Logging (New, Light)**
   - If extraction fails (e.g., corrupt PDF): Flag chunk as "skipped" with reason; pass partial text.
   - Log: Prep time per step; file hash for audit.

#### **Expected Latency (Updated, CPU-Ollama)**
| Step | Time (ms) | Notes |
|------|-----------|-------|
| 1. Parse/Validate | <1 | + File ext check |
| 1.5. File Extract | 5-50 | TXT:1ms; PDF:30ms avg (<5 pages) |
| 2. RAG/HMAC | 1-3 | + File chunks (max 10) |
| 3. Normalize | 2-6 | Per chunk |
| 4. Media | 5-10 | If image |
| 5. Token Prep | 5-10 | + Chunk tokens |
| 6. Package | <1 | |
| **Total** | **20-80** | Files add ~30ms; still <150ms with layers |

#### **Key Libraries (Updated, Offline-Cacheable)**
```bash
# Core (unchanged)
pip install emoji unicodedata Pillow transformers
# New for Files (pre-bundle wheels in Docker; ~10MB total)
pip install pdfplumber python-docx
# If env blocks: TXT/MD only; note in Plan.pdf as "MVP limitation"
```

### Format of the Final Prepared Input

Output: Single Python dict (serializable to JSON for API). Two core stubs (flowchart) + metadata. Files integrate as external chunks—no separate field, keeps simple. Example with PDF upload:

```python
{
    "text_embed_stub": {
        "normalized_user": "What's the weather?",  # Clean user prompt
        "normalized_external": [  # List of delimited, normalized chunks (RAG + file)
            "[EXTERNAL]Page 1: Extracted PDF text about weather APIs.[/EXTERNAL]",
            "[EXTERNAL]Page 2: Ignore this; it's a jailbreak attempt hidden in doc.[/EXTERNAL]"
        ],
        "emoji_descriptions": [],  # If any
        "hmacs": ["abc123hmac_pdf_chunk1", "def456hmac_pdf_chunk2"],  # Per chunk
        "stats": {
            "char_total": 1200,
            "token_estimate": 250,
            "user_external_ratio": 0.1,
            "file_chunks_count": 2,  # New: File-specific
            "extracted_total_chars": 1100  # New
        }
    },
    "image_emoji_stub": {  # Unchanged
        "image": {},  # Empty if no image
        "emoji_summary": {"count": 0, "types": []}
    },
    "metadata": {
        "request_id": "uuid-1234",
        "timestamp": "2025-11-22T10:00:00Z",
        "rag_enabled": True,  # Or file-derived
        "has_media": False,
        "has_file": True,  # New flag
        "file_info": {  # New: Forensics
            "original_path": "/uploads/weather.pdf",
            "hash": "sha256_of_pdf",
            "type": "pdf",
            "chunk_count": 2,
            "extraction_success": True
        },
        "prep_time_ms": 45
    }
}
```

