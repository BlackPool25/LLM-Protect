# Quick Installation Guide for New Features

## Prerequisites

### System Packages (for OCR)
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install tesseract-ocr tesseract-ocr-eng

# macOS
brew install tesseract

# Windows
# Download installer from: https://github.com/UB-Mannheim/tesseract/wiki
```

## Installation Steps

### 1. Activate Virtual Environment
```bash
cd "/home/lightdesk/Projects/LLM-Protect"
source venv/bin/activate
```

### 2. Install New Python Packages
```bash
cd "Input Prep"
pip install -r requirements.txt
```

This will install:
- `imagehash==4.3.1` - Perceptual hashing
- `piexif==1.1.3` - EXIF extraction
- `pytesseract==0.3.10` - OCR wrapper
- `sentence-transformers>=2.2.2` - Text embeddings (prepared for future)
- `numpy>=1.24.0` and `scipy>=1.10.0` - Mathematical operations

### 3. Verify Installation
```bash
python -c "import imagehash, piexif, pytesseract, numpy, scipy; print('✅ All packages installed')"
```

### 4. Test New Endpoints

#### Start the server:
```bash
cd "Input Prep"
python app/main.pyc
```

#### Check health:
```bash
curl http://localhost:8000/health | jq
```

Expected output should show all new libraries:
```json
{
  "status": "healthy",
  "libraries": {
    "txt": true,
    "md": true,
    "pdf": true,
    "docx": true,
    "image": true,
    "pillow": true,
    "imagehash": true,
    "piexif": true,
    "pytesseract": true
  }
}
```

## Testing New Features

### Test Layer 0 Processing
```bash
curl -X POST "http://localhost:8000/api/v1/prepare-layer0" \
  -F "user_prompt=Test message with suspicious </system> delimiter" \
  | jq
```

### Test Image Processing
```bash
curl -X POST "http://localhost:8000/api/v1/process-images" \
  -F "user_prompt=Analyze this image" \
  -F "images=@/path/to/test_image.png" \
  -F "run_ocr=false" \
  | jq
```

### Test with PDF Image Extraction
```bash
curl -X POST "http://localhost:8000/api/v1/process-images" \
  -F "user_prompt=Extract images from PDF" \
  -F "pdf_file=@/path/to/document.pdf" \
  -F "run_ocr=true" \
  -F "ocr_confidence=60.0" \
  | jq
```

## Troubleshooting

### Issue: pytesseract command not found
**Solution:** Install tesseract-ocr system package (see Prerequisites)

### Issue: Import errors for imagehash/piexif
**Solution:** 
```bash
pip install --upgrade imagehash piexif
```

### Issue: OCR not working
**Test:**
```bash
tesseract --version
```

If not found, install tesseract-ocr system package.

### Issue: NumPy/SciPy errors
**Solution:**
```bash
pip install --upgrade numpy scipy
```

## Feature Flags

### Disable OCR (Resource Intensive)
Set `run_ocr=false` in API requests (default)

### Skip Image Processing
Simply don't send image/PDF files in requests

## Documentation

- **Full Implementation Summary:** `IMPLEMENTATION_SUMMARY.md`
- **Original Plan:** `Plans/Input_To_Do.md`
- **Missing Features (Now Fixed):** `Plans/missing-todo.txt`

## Quick Reference

### New Endpoints
- `POST /api/v1/prepare-layer0` - Advanced Layer 0 processing
- `POST /api/v1/process-images` - Comprehensive image analysis

### New Libraries
- `imagehash` - pHash calculation
- `piexif` - EXIF extraction
- `pytesseract` - OCR
- `numpy`/`scipy` - Steganography detection

### Key Features
- ✅ Zero-width character detection
- ✅ Unicode obfuscation analysis
- ✅ Fast heuristic pattern matching
- ✅ pHash calculation
- ✅ EXIF metadata extraction
- ✅ OCR text extraction
- ✅ Steganography detection
- ✅ PDF image extraction

## Next Steps

1. ✅ Install dependencies
2. ✅ Test health endpoint
3. ✅ Test new endpoints with sample data
4. Review `IMPLEMENTATION_SUMMARY.md` for detailed usage
5. Integrate with Layer 0 processing pipeline

**Implementation Status: COMPLETE** ✅
