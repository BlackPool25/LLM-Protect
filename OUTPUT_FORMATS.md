# Output Formats Documentation

## Overview

This document details the exact output formats for both endpoints and explains how information is preserved throughout the pipeline.

## 📝 Information Preservation Guarantee

### What's Preserved:

1. **All Text Content**: Every character from user input is preserved
2. **Emojis**: Stored in BOTH normalized text AND separately in emoji_summary
3. **External Data**: All RAG/external data with HMAC signatures
4. **File Content**: Complete text extraction from uploaded files
5. **Metadata**: Request IDs, timestamps, source tracking

### How Emojis Are Handled:

```python
# Emojis are preserved in TWO places:
1. In normalized text: "Hello 😀 World" → "Hello 😀 World"
2. In emoji_summary: {
   "count": 1,
   "types": ["😀"],
   "descriptions": [":grinning_face:"]
}
```

The `preserve_emojis=True` (default) ensures emojis remain in the normalized text for the LLM while also being extracted for analysis.

## 🔗 Endpoint 1: `/api/v1/prepare-text`

**Purpose**: Prepare text input for Layer 0 (text processing/heuristics)

**Input**:
- `user_prompt` (required): User's text input
- `file` (optional): File upload (TXT/MD/PDF/DOCX)
- `file_path` (optional): Server-side file path
- `external_data` (optional): JSON array of external data strings
- `retrieve_from_vector_db` (optional): Boolean for vector DB retrieval

**Output Format** (PreparedInput):

```json
{
  "text_embed_stub": {
    "normalized_user": "What is the weather today? 🌞",
    "normalized_external": [
      "[EXTERNAL]The forecast shows sunny conditions[/EXTERNAL]",
      "[EXTERNAL]Temperature around 25°C[/EXTERNAL]"
    ],
    "emoji_descriptions": [":sun:"],
    "hmacs": [
      "a1b2c3d4e5f6...",
      "f6e5d4c3b2a1..."
    ],
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
      "count": 1,
      "types": ["🌞"],
      "descriptions": [":sun:"]
    }
  },
  "metadata": {
    "request_id": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2024-01-01T10:00:00.000Z",
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

### Field Descriptions:

#### text_embed_stub (for Layer 0):
- `normalized_user`: Cleaned user input (Unicode normalized, whitespace cleaned, **emojis preserved**)
- `normalized_external`: List of external data chunks wrapped in `[EXTERNAL]...[/EXTERNAL]` delimiters
- `emoji_descriptions`: Text descriptions of emojis found (e.g., ":grinning_face:")
- `hmacs`: HMAC-SHA256 signatures for each external chunk (signs the content WITHOUT delimiters)
- `stats`:
  - `char_total`: Total characters across all input
  - `token_estimate`: Estimated token count (using tiktoken or char/4 approximation)
  - `user_external_ratio`: Ratio of user text to total (0.0 to 1.0)
  - `file_chunks_count`: Number of chunks extracted from files
  - `extracted_total_chars`: Total characters extracted from files

#### image_emoji_stub (for media processing):
- `image`: Empty dict for text endpoint (used by media endpoint)
- `emoji_summary`:
  - `count`: Number of emojis found
  - `types`: List of unique emoji characters
  - `descriptions`: Text descriptions for each emoji

#### metadata (for monitoring):
- `request_id`: Unique UUID for this request
- `timestamp`: ISO 8601 timestamp
- `rag_enabled`: Whether external data was included
- `has_media`: Whether images were processed
- `has_file`: Whether files were uploaded
- `file_info`: Details about uploaded file (if any)
- `prep_time_ms`: Total preparation time
- `step_times`: Breakdown of time per processing step

### Example with File Upload:

```json
{
  "text_embed_stub": {
    "normalized_user": "Analyze this document",
    "normalized_external": [
      "[EXTERNAL]This is the first chunk from the PDF... [Source: document.pdf, Chunk: 0][/EXTERNAL]",
      "[EXTERNAL]This is the second chunk from the PDF... [Source: document.pdf, Chunk: 1][/EXTERNAL]"
    ],
    "emoji_descriptions": [],
    "hmacs": ["abc123...", "def456..."],
    "stats": {
      "char_total": 1200,
      "token_estimate": 300,
      "user_external_ratio": 0.02,
      "file_chunks_count": 2,
      "extracted_total_chars": 1180
    }
  },
  "image_emoji_stub": {
    "image": {},
    "emoji_summary": {"count": 0, "types": [], "descriptions": []}
  },
  "metadata": {
    "request_id": "...",
    "timestamp": "2024-01-01T10:00:00Z",
    "rag_enabled": true,
    "has_media": false,
    "has_file": true,
    "file_info": {
      "original_path": "/uploads/document.pdf",
      "hash": "sha256_abc123...",
      "type": "pdf",
      "chunk_count": 2,
      "extraction_success": true,
      "extraction_error": null
    },
    "prep_time_ms": 68.5,
    "step_times": {...}
  }
}
```

## 🎨 Endpoint 2: `/api/v1/prepare-media`

**Purpose**: Prepare media input for image/emoji processing layers

**Input**:
- `user_prompt` (required): User's text input
- `image` (optional): Image file upload
- `image_path` (optional): Server-side image path

**Output Format** (PreparedInput):

```json
{
  "text_embed_stub": {
    "normalized_user": "Look at these emojis: 😀 🎉 🚀",
    "normalized_external": [],
    "emoji_descriptions": [":grinning_face:", ":party_popper:", ":rocket:"],
    "hmacs": [],
    "stats": {
      "char_total": 32,
      "token_estimate": 10,
      "user_external_ratio": 1.0,
      "file_chunks_count": 0,
      "extracted_total_chars": 0
    }
  },
  "image_emoji_stub": {
    "image": {
      "hash": "sha256_def789...",
      "format": "png",
      "size_bytes": 245678,
      "dimensions": [1920, 1080],
      "description": null
    },
    "emoji_summary": {
      "count": 3,
      "types": ["😀", "🎉", "🚀"],
      "descriptions": [":grinning_face:", ":party_popper:", ":rocket:"]
    }
  },
  "metadata": {
    "request_id": "...",
    "timestamp": "2024-01-01T10:00:00Z",
    "rag_enabled": false,
    "has_media": true,
    "has_file": false,
    "file_info": null,
    "prep_time_ms": 25.8,
    "step_times": {...}
  }
}
```

### Field Descriptions (Media Endpoint):

#### image_emoji_stub:
- `image`:
  - `hash`: SHA256 hash of the image file
  - `format`: Image format (png, jpg, gif, etc.)
  - `size_bytes`: File size in bytes
  - `dimensions`: [width, height] in pixels
  - `description`: AI-generated description (placeholder for future implementation)
- `emoji_summary`: Same as text endpoint

## 🤖 Endpoint 3: `/api/v1/generate`

**Purpose**: Generate LLM response from prepared input

**Input** (GenerateRequest):

```json
{
  "prepared_input": { /* PreparedInput object from /prepare-text */ },
  "max_new_tokens": 512,
  "temperature": 0.7,
  "top_p": 0.9,
  "do_sample": true
}
```

**Output Format** (GenerateResponse):

```json
{
  "success": true,
  "generated_text": "Based on the forecast, today will be sunny with temperatures around 25°C. It's a perfect day to go outside!",
  "input_tokens": 38,
  "output_tokens": 28,
  "total_time_ms": 2340.5,
  "model": "gemma-2b",
  "error": null,
  "preparation_metadata": {
    "request_id": "550e8400-e29b-41d4-a716-446655440000",
    "prep_time_ms": 45.2,
    "input_tokens_estimated": 38,
    "rag_chunks": 2,
    "hmac_signatures": 2
  }
}
```

### Field Descriptions:
- `success`: Whether generation succeeded
- `generated_text`: The LLM's response
- `input_tokens`: Actual token count of input
- `output_tokens`: Number of tokens generated
- `total_time_ms`: Time taken for generation (not including preparation)
- `model`: Model identifier
- `error`: Error message if failed
- `preparation_metadata`: Metadata from the preparation step

## 📊 Complete Flow Example

### User Request:
```bash
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=What's the weather? 🌞" \
  -F 'external_data=["Sunny today", "25°C temperature"]'
```

### Step 1 Output (Preparation):
```json
{
  "text_embed_stub": {
    "normalized_user": "What's the weather? 🌞",
    "normalized_external": [
      "[EXTERNAL]Sunny today[/EXTERNAL]",
      "[EXTERNAL]25°C temperature[/EXTERNAL]"
    ],
    "emoji_descriptions": [":sun:"],
    "hmacs": ["hmac1", "hmac2"],
    "stats": {...}
  },
  ...
}
```

### Step 2 Input (Generation):
The entire PreparedInput object is sent to `/api/v1/generate`

### Step 2 Output (LLM Response):
```json
{
  "success": true,
  "generated_text": "The weather today is sunny with temperatures around 25°C...",
  "input_tokens": 18,
  "output_tokens": 25,
  "total_time_ms": 1850.3,
  ...
}
```

## 🔒 HMAC Verification

Each external chunk has a corresponding HMAC signature:

```python
# Chunk with delimiters (stored in normalized_external)
chunk = "[EXTERNAL]Sunny today[/EXTERNAL]"

# Original content (what's signed)
content = "Sunny today"

# HMAC signature (in hmacs array)
hmac = generate_hmac(content)  # Uses HMAC-SHA256

# Verification
is_valid = verify_hmac(content, hmac)  # Returns True/False
```

**Important**: The HMAC signs the **original content** without delimiters, not the delimited version.

## 🎯 Where Data Goes

### After `/prepare-text`:
- **Layer 0 (Heuristics)**: Uses `text_embed_stub` for regex checks, separator detection
- **Layer 1 (Semantic Guard)**: Uses `text_embed_stub` for embedding analysis
- **Image Processing**: Uses `image_emoji_stub` for media analysis
- **Monitoring**: Uses `metadata` for logging and analytics

### After `/generate`:
- **User Response**: The `generated_text` is returned to the user
- **Logs**: All metadata is logged for audit trail
- **Analytics**: Token counts, timing data stored

## 📈 Information Flow Diagram

```
User Input → /prepare-text → PreparedInput
                              ↓
                     text_embed_stub → Layer 0 → Layer 1 → /generate
                              ↓
                   image_emoji_stub → Image Processing
                              ↓
                       metadata → Logs & Monitoring
```

## ✅ Data Integrity Guarantees

1. **No Data Loss**: All input text is preserved in `normalized_user`
2. **Emoji Preservation**: Emojis stay in text AND are extracted separately
3. **Source Tracking**: Each chunk tracks its source file/location
4. **Tamper Detection**: HMAC signatures detect any modification
5. **Audit Trail**: Complete metadata for tracing processing
6. **Error Handling**: Errors logged with context, partial data preserved

## 🔍 Verification Example

```python
# Verify that all information is preserved
prepared = api_response

# 1. Check user input is preserved
assert prepared['text_embed_stub']['normalized_user']

# 2. Check emojis are in both places
user_text = prepared['text_embed_stub']['normalized_user']
emoji_summary = prepared['image_emoji_stub']['emoji_summary']
assert "😀" in user_text  # Preserved in text
assert "😀" in emoji_summary['types']  # Also extracted

# 3. Verify HMAC signatures
for chunk, hmac in zip(
    prepared['text_embed_stub']['normalized_external'],
    prepared['text_embed_stub']['hmacs']
):
    content = chunk.replace('[EXTERNAL]', '').replace('[/EXTERNAL]', '')
    assert verify_hmac(content, hmac)  # Should be True

# 4. Check file extraction
if prepared['metadata']['has_file']:
    file_info = prepared['metadata']['file_info']
    assert file_info['extraction_success']
    assert file_info['chunk_count'] > 0
```

## 🚨 Error Responses

If processing fails, an error response is returned:

```json
{
  "text_embed_stub": {
    "normalized_user": "ERROR: File extraction failed: corrupted PDF",
    "normalized_external": [],
    "emoji_descriptions": [],
    "hmacs": [],
    "stats": {"char_total": 0, "token_estimate": 0, ...}
  },
  "image_emoji_stub": {
    "image": {"error": "File extraction failed"},
    "emoji_summary": {"count": 0, "types": [], "descriptions": []}
  },
  "metadata": {
    "request_id": "...",
    "timestamp": "...",
    "prep_time_ms": 5.2,
    ...
  }
}
```

The structure is maintained even on errors for consistent parsing.

