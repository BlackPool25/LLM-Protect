# LLM-Protect Output Directory

This directory contains saved outputs from the LLM-Protect Input Preparation Module.

## Directory Structure

```
Outputs/
├── layer0_text/          # Layer 0 text processing outputs
│   └── *.json            # Prepared text inputs with HMAC verification
└── media_processing/     # Image and emoji processing outputs
    └── *.json            # Prepared media inputs with metadata
```

## Output Formats

All outputs are saved as JSON files with the following structure:

### Layer 0 (Text Processing) Outputs

Location: `layer0_text/`

These files contain prepared text inputs from the `/api/v1/prepare-text` endpoint, including:
- Normalized user prompts
- Processed RAG/external data with HMAC signatures
- Extracted text from uploaded files (TXT, MD, PDF, DOCX)
- Token statistics and metadata

**Filename format**: `YYYYMMDD_HHMMSS_layer0_<request_id>_<text_preview>.json`

**Example structure**:
```json
{
  "processing_type": "layer0_text",
  "saved_at": "2025-11-22T10:30:45Z",
  "prepared_input": {
    "text_embed_stub": {
      "normalized_user": "What is the weather?",
      "normalized_external": [
        "[EXTERNAL]Context from RAG system[/EXTERNAL]"
      ],
      "emoji_descriptions": [],
      "hmacs": ["abc123..."],
      "stats": {
        "char_total": 150,
        "token_estimate": 38,
        "user_external_ratio": 0.65,
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
      "request_id": "uuid-1234-5678",
      "timestamp": "2025-11-22T10:30:45Z",
      "rag_enabled": true,
      "has_media": false,
      "has_file": false,
      "file_info": null,
      "prep_time_ms": 45.5,
      "step_times": {
        "parse_validate": 1.2,
        "file_extraction": 0.0,
        "rag_processing": 12.5,
        "normalization": 8.3,
        "token_calculation": 2.1,
        "packaging": 0.8
      }
    }
  }
}
```

### Media Processing Outputs

Location: `media_processing/`

These files contain prepared media inputs from the `/api/v1/prepare-media` endpoint, including:
- Image metadata (hash, format, size, dimensions)
- Emoji analysis and descriptions
- Media-specific processing information

**Filename format**: `YYYYMMDD_HHMMSS_media_<request_id>_<text_preview>.json`

**Example structure**:
```json
{
  "processing_type": "media_processing",
  "saved_at": "2025-11-22T10:35:12Z",
  "prepared_input": {
    "text_embed_stub": {
      "normalized_user": "Check this image 😀",
      "normalized_external": [],
      "emoji_descriptions": [":grinning:"],
      "hmacs": [],
      "stats": {
        "char_total": 18,
        "token_estimate": 5,
        "user_external_ratio": 1.0,
        "file_chunks_count": 0,
        "extracted_total_chars": 0
      }
    },
    "image_emoji_stub": {
      "image": {
        "hash": "sha256_of_image",
        "format": "png",
        "size_bytes": 45678,
        "dimensions": [800, 600]
      },
      "emoji_summary": {
        "count": 1,
        "types": ["😀"],
        "descriptions": [":grinning:"]
      }
    },
    "metadata": {
      "request_id": "uuid-5678-9012",
      "timestamp": "2025-11-22T10:35:12Z",
      "rag_enabled": false,
      "has_media": true,
      "has_file": false,
      "file_info": null,
      "prep_time_ms": 32.1,
      "step_times": {
        "parse_validate": 1.0,
        "normalization": 6.5,
        "media_processing": 18.2,
        "token_calculation": 1.8,
        "packaging": 0.5
      }
    }
  }
}
```

## API Endpoints

### View Output Statistics

```bash
GET /api/v1/output-stats
```

Returns:
```json
{
  "base_directory": "/home/lightdesk/Projects/LLM-Protect/Outputs",
  "layer0_outputs": 25,
  "media_outputs": 10,
  "total_outputs": 35,
  "layer0_directory": "/home/lightdesk/Projects/LLM-Protect/Outputs/layer0_text",
  "media_directory": "/home/lightdesk/Projects/LLM-Protect/Outputs/media_processing",
  "recent_layer0_files": [
    "20251122_103045_layer0_uuid1234_What_is_the_weather.json",
    "..."
  ],
  "recent_media_files": [
    "20251122_103512_media_uuid5678_Check_this_image.json",
    "..."
  ]
}
```

## Usage

Outputs are automatically saved when you use the preparation endpoints:

1. **For text processing**:
   ```bash
   curl -X POST "http://localhost:8000/api/v1/prepare-text" \
     -F "user_prompt=What is the weather?" \
     -F "file=@document.pdf"
   ```
   → Saves to `layer0_text/`

2. **For media processing**:
   ```bash
   curl -X POST "http://localhost:8000/api/v1/prepare-media" \
     -F "user_prompt=Check this image 😀" \
     -F "image=@photo.jpg"
   ```
   → Saves to `media_processing/`

## Notes

- Outputs are saved **after** successful validation
- Failed requests do not generate output files
- Filenames include timestamps and truncated user text for easy identification
- All outputs use UTF-8 encoding with pretty-printed JSON (indent=2)
- Request IDs can be used to correlate outputs with API logs

## Cleanup

To manage disk space, periodically clean old outputs:

```bash
# Remove Layer 0 outputs older than 7 days
find layer0_text/ -name "*.json" -mtime +7 -delete

# Remove media outputs older than 7 days
find media_processing/ -name "*.json" -mtime +7 -delete
```

