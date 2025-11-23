# LLM-Protect: Input Preparation Module

A high-performance FastAPI service for preparing and validating inputs before they reach the LLM protection pipeline.

## Features

- **Multi-format File Support**: Extract text from TXT, MD, PDF, and DOCX files
- **RAG Integration**: Support for direct external data and vector database retrieval
- **HMAC Verification**: Non-externally modifiable integrity checking
- **Media Processing**: Handle images and emojis with metadata extraction
- **High Performance**: Target latency of 20-80ms for typical operations

## Architecture

The module follows a 6-step processing pipeline:

1. **Parse & Validate**: Validate input structure and file constraints
2. **File Extraction**: Extract and chunk text from supported file formats
3. **RAG Handling**: Merge external data with HMAC signing
4. **Text Normalization**: Clean and normalize all text inputs
5. **Media Processing**: Handle images and emojis
6. **Token Processing**: Calculate stats and prepare final output
7. **Payload Packaging**: Format output for downstream layers

## Installation

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env and set your HMAC_SECRET_KEY
```

## Configuration

Generate a secure HMAC key:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Add the generated key to your `.env` file.

## Running the Service

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Access the API documentation at: http://localhost:8000/docs

## API Endpoints

### 1. Text Preparation (for Layer 0)

**POST** `/api/v1/prepare-text`

Prepares text inputs with optional file uploads and RAG data.

### 2. Media Preparation (for Image/Emoji Processing)

**POST** `/api/v1/prepare-media`

Processes images and emojis for media-specific analysis.

### 3. Health Check

**GET** `/health`

Returns service status and library availability.

## Output Format

The service returns a structured `PreparedInput` object containing:

- `text_embed_stub`: Normalized text data with HMACs for Layer 0
- `image_emoji_stub`: Media data for image/emoji processing
- `metadata`: Request tracking, timing, and forensic information

## Performance Targets

- Parse/Validate: <1ms
- File Extract: 5-50ms (TXT: 1ms, PDF: 30ms avg)
- RAG/HMAC: 1-3ms
- Normalize: 2-6ms per chunk
- Media: 5-10ms if image present
- Token Prep: 5-10ms
- Package: <1ms
- **Total: 20-80ms**

## Development

Project structure:

```
app/
├── main.py                 # FastAPI application
├── config.py               # Configuration management
├── models/
│   └── schemas.py          # Pydantic data models
├── services/
│   ├── input_parser.py     # Input validation
│   ├── file_extractor.py   # File text extraction
│   ├── rag_handler.py      # RAG data processing
│   ├── text_normalizer.py  # Text normalization
│   ├── media_processor.py  # Image/emoji handling
│   ├── token_processor.py  # Token stats
│   └── payload_packager.py # Output formatting
└── utils/
    ├── hmac_utils.py       # HMAC operations
    └── logger.py           # Logging utilities
```

## License

[Your License Here]

