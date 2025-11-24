# Layer 0 Integration Guide

## Overview

Layer 0 is the **fast security analysis layer** that performs immediate pattern detection and obfuscation analysis on all incoming text. This document explains how to integrate with Layer 0, consume its outputs, and connect it to downstream systems.

## Architecture

```
User Input → Input Prep → Layer 0 Analysis → Downstream Systems
                  ↓
            [unicode detection]
            [heuristics]
            [text embeddings]
                  ↓
            Layer0Output
```

## Layer 0 Components

### 1. Unicode Obfuscation Detection
- **Zero-width character detection** (U+200B, U+200C, U+200D, U+FEFF)
- **Invisible character detection** (various Unicode categories)
- **NFKC normalization** with change tracking
- **Position tracking** for detected anomalies

### 2. Fast Heuristics
- Long base64 sequences
- System delimiters (`<|im_start|>`, `<|im_end|>`, etc.)
- Repeated character patterns
- Unusually long single lines
- XML/HTML tags and comments
- Suspicious injection keywords
- Overall suspiciousness scoring (0-1)

### 3. Text Embeddings
- **Semantic fingerprinting** using sentence-transformers
- **Model**: all-MiniLM-L6-v2 (lightweight, fast)
- **Output**: SHA256 hash of embedding vector (32 chars)
- **Use case**: Detect semantic similarity, duplicate detection

## API Endpoints

### 1. Main Text Preparation Endpoint (includes Layer 0)

**Endpoint**: `POST /api/v1/prepare-text`

**Request**:
```json
{
  "user_prompt": "Your text here",
  "external_data": ["chunk1", "chunk2"],  // optional RAG data
  "retrieve_from_vector_db": false,
  "session_id": "uuid-optional"
}
```

**Response**: `PreparedInput` object with embedded `layer0` field

**Layer 0 Data Location**: `response.layer0`

### 2. Standalone Layer 0 Endpoint (future)

**Endpoint**: `POST /api/v1/prepare-layer0`

Not yet implemented, but will provide Layer 0 analysis without full input preparation.

## Layer0Output Schema

```python
class Layer0Output(BaseModel):
    # Identifiers
    request_id: str
    timestamp: str  # ISO 8601
    
    # Text data
    normalized_text: str                    # NFKC normalized, zero-width removed
    special_char_mask: str                  # Marks special char positions
    token_count: int                        # Estimated tokens
    text_embedding_hash: Optional[str]      # SHA256 of embedding (32 chars)
    
    # Analysis flags
    unicode_analysis: UnicodeAnalysis       # Detailed Unicode analysis
    heuristic_flags: HeuristicFlags         # Pattern detection results
    
    # Context
    hmac_verified: bool                     # External data integrity
    external_data_count: int                # Number of RAG chunks
    attachment_texts: List[str]             # EXIF/OCR/caption texts
    
    # Emojis
    emoji_count: int
    emoji_descriptions: List[str]
    
    # Metadata
    char_total: int
    suspicious_score: float                 # 0.0 - 1.0
    raw_text_snapshot_stored: bool
    prep_time_ms: float
```

## Consuming Layer0Output

### Example 1: Python Client

```python
import requests

# Prepare input with Layer 0 analysis
response = requests.post(
    "http://localhost:8000/api/v1/prepare-text",
    json={
        "user_prompt": "Analyze this text",
        "retrieve_from_vector_db": False
    }
)

prepared = response.json()

# Access Layer 0 data
layer0 = prepared.get("layer0")
if layer0:
    # Check security flags
    if layer0["unicode_analysis"]["unicode_obfuscation_flag"]:
        print("⚠️ Unicode obfuscation detected!")
    
    # Check heuristics
    if layer0["heuristic_flags"]["has_system_delimiter"]:
        print("🚨 System delimiter found!")
    
    # Check suspicion score
    if layer0["suspicious_score"] > 0.5:
        print(f"⚠️ High suspicion: {layer0['suspicious_score']:.2%}")
    
    # Get semantic fingerprint
    embedding = layer0.get("text_embedding_hash")
    if embedding:
        print(f"Fingerprint: {embedding}")
```

### Example 2: Downstream Layer 0 Processing

```python
def process_layer0_output(layer0_data: dict):
    """
    Process Layer 0 output for downstream security analysis.
    
    Args:
        layer0_data: Layer0Output as dictionary
    
    Returns:
        Security decision (allow/block/review)
    """
    # Extract key flags
    unicode_flags = layer0_data["unicode_analysis"]
    heuristics = layer0_data["heuristic_flags"]
    suspicion = layer0_data["suspicious_score"]
    
    # Decision logic
    if unicode_flags["zero_width_found"]:
        return {
            "decision": "block",
            "reason": "Zero-width characters detected",
            "details": {
                "count": unicode_flags["zero_width_count"],
                "positions": unicode_flags["zero_width_positions"]
            }
        }
    
    if heuristics["has_system_delimiter"]:
        return {
            "decision": "block",
            "reason": "System delimiter injection attempt",
            "patterns": heuristics["detected_patterns"]
        }
    
    if suspicion > 0.7:
        return {
            "decision": "review",
            "reason": f"High suspicion score: {suspicion:.2%}",
            "flags": [
                k for k, v in heuristics.items()
                if k.startswith("has_") and v
            ]
        }
    
    return {"decision": "allow", "reason": "Passed Layer 0 checks"}
```

### Example 3: Semantic Similarity Check

```python
def check_duplicate_input(new_embedding: str, previous_embeddings: set):
    """
    Check if input is semantically similar to previous inputs.
    
    Args:
        new_embedding: text_embedding_hash from Layer0Output
        previous_embeddings: Set of known embeddings
    
    Returns:
        bool: True if duplicate detected
    """
    if new_embedding in previous_embeddings:
        return True
    
    # Add to cache
    previous_embeddings.add(new_embedding)
    return False

# Usage
embedding_cache = set()

# On each request
layer0 = prepared["layer0"]
embedding = layer0.get("text_embedding_hash")

if embedding and check_duplicate_input(embedding, embedding_cache):
    print("⚠️ Duplicate or very similar input detected!")
```

## Integration Patterns

### Pattern 1: Pre-LLM Security Gate

```python
# Before sending to LLM
prepared = await prepare_text_input(user_prompt)
layer0 = prepared.layer0

# Security check
if layer0.suspicious_score > 0.8:
    raise SecurityException("Input blocked by Layer 0")

# Proceed to LLM
response = await generate_llm_response(prepared)
```

### Pattern 2: Logging and Monitoring

```python
# Log all Layer 0 detections
if layer0.unicode_analysis.unicode_obfuscation_flag:
    log.warning(
        f"Unicode obfuscation detected: {layer0.request_id}",
        extra={
            "zero_width_count": layer0.unicode_analysis.zero_width_count,
            "positions": layer0.unicode_analysis.zero_width_positions
        }
    )

if layer0.heuristic_flags.detected_patterns:
    log.info(
        f"Patterns detected: {layer0.heuristic_flags.detected_patterns}",
        extra={"request_id": layer0.request_id}
    )
```

### Pattern 3: Multi-Layer Defense

```python
# Layer 0: Fast checks
layer0_result = process_layer0_output(prepared.layer0)
if layer0_result["decision"] == "block":
    return {"error": layer0_result["reason"]}

# Layer 1: Advanced checks (if needed)
if layer0_result["decision"] == "review":
    layer1_result = await deep_analysis(prepared)
    if not layer1_result["safe"]:
        return {"error": "Blocked by advanced analysis"}

# Proceed to LLM
return await generate_response(prepared)
```

## Stored Output Files

Layer 0 output is automatically saved to disk:

**Location**: `/Outputs/layer0_text/`

**Filename format**: `{timestamp}_layer0_{hash}_{sanitized_text}.json`

**Example**: `20251124_120000_layer0_a1b2c3d4_Hello_world.json`

**Content**: Complete `PreparedInput` object including `layer0` field

## Data Flow

```
1. User submits prompt via /api/v1/prepare-text
2. Input Preparation processes text
   - Normalize text
   - Extract emojis
   - Process RAG data
   - Generate HMACs
3. Layer 0 Analysis runs
   - Unicode detection
   - Heuristics
   - Text embeddings
4. Layer0Output created and embedded in PreparedInput
5. PreparedInput saved to disk (includes layer0)
6. PreparedInput returned to client
7. Client sends PreparedInput to /api/v1/generate
8. LLM generates response
```

## Best Practices

### 1. Always Check suspicious_score
```python
if layer0.suspicious_score > 0.5:
    # Trigger additional review
```

### 2. Monitor Zero-Width Characters
```python
if layer0.unicode_analysis.zero_width_found:
    # Log incident, potentially block
```

### 3. Use Text Embeddings for Deduplication
```python
if layer0.text_embedding_hash:
    # Check against cache
```

### 4. Combine Multiple Signals
```python
risk_score = (
    layer0.suspicious_score * 0.5 +
    (0.3 if layer0.unicode_analysis.unicode_obfuscation_flag else 0) +
    (0.2 if layer0.heuristic_flags.has_system_delimiter else 0)
)
```

## Troubleshooting

### Issue: layer0 field is None

**Cause**: Layer 0 analysis failed or was skipped

**Solution**: Check logs for errors in unicode_detector or heuristics modules

### Issue: text_embedding_hash is None

**Cause**: sentence-transformers not installed or model failed to load

**Solution**:
```bash
pip install sentence-transformers
```

### Issue: suspicious_score always 0

**Cause**: No patterns detected (input is clean)

**Solution**: This is normal for safe inputs

## Future Enhancements

1. **Standalone Layer 0 endpoint** - `/api/v1/prepare-layer0` for lightweight analysis
2. **Configurable thresholds** - Adjust suspicion score thresholds
3. **Custom pattern rules** - Add domain-specific detection patterns
4. **Real-time alerts** - Webhook notifications on high-risk detections
5. **Layer 0 statistics** - Aggregated metrics and dashboards

## Support

For issues or questions:
- Check logs in `Input Prep/logs/`
- Review Layer 0 saved outputs in `/Outputs/layer0_text/`
- Examine `app/services/unicode_detector.py` and `app/services/heuristics.py`

## Related Documentation

- [Web Interface Guide](WEB_INTERFACE_GUIDE.md)
- [Output Formats](OUTPUT_FORMATS.md)
- [Conversation and RAG Guide](CONVERSATION_AND_RAG_GUIDE.md)
