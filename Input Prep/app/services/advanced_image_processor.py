"""
Advanced image processing service.

Implements pHash, EXIF extraction, OCR, steganography detection,
and vision-based captioning for comprehensive image analysis.
"""

import os
import io
import hashlib
import numpy as np
from pathlib import Path
from typing import Dict, Optional, Tuple, List, Any
from app.utils.logger import get_logger
from app.config import settings

logger = get_logger(__name__)

# Try to import required libraries with graceful fallback
try:
    from PIL import Image
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False
    logger.warning("Pillow not available. Image processing disabled.")

try:
    import imagehash
    IMAGEHASH_AVAILABLE = True
except ImportError:
    IMAGEHASH_AVAILABLE = False
    logger.warning("imagehash not available. pHash disabled.")

try:
    import piexif
    PIEXIF_AVAILABLE = True
except ImportError:
    PIEXIF_AVAILABLE = False
    logger.warning("piexif not available. EXIF extraction disabled.")

try:
    import pytesseract
    PYTESSERACT_AVAILABLE = True
except ImportError:
    PYTESSERACT_AVAILABLE = False
    logger.warning("pytesseract not available. OCR disabled.")


class AdvancedImageAnalysis:
    """Results from advanced image analysis."""
    
    def __init__(
        self,
        file_hash: str,
        phash: Optional[str] = None,
        exif_data: Optional[Dict] = None,
        exif_description: Optional[str] = None,
        embedded_text_from_exif: Optional[str] = None,
        suspicious_metadata: bool = False,
        ocr_text: Optional[str] = None,
        ocr_confidence: Optional[float] = None,
        stego_score: float = 0.0,
        file_entropy: Optional[float] = None,
        suspicious_entropy: bool = False,
        extracted_payload: Optional[str] = None,
        caption: Optional[str] = None,
        vision_embedding: Optional[str] = None,
        dimensions: Optional[Tuple[int, int]] = None,
        format: Optional[str] = None,
        size_bytes: Optional[int] = None
    ):
        self.file_hash = file_hash
        self.phash = phash
        self.exif_data = exif_data or {}
        self.exif_description = exif_description
        self.embedded_text_from_exif = embedded_text_from_exif
        self.suspicious_metadata = suspicious_metadata
        self.ocr_text = ocr_text
        self.ocr_confidence = ocr_confidence
        self.stego_score = stego_score
        self.file_entropy = file_entropy
        self.suspicious_entropy = suspicious_entropy
        self.extracted_payload = extracted_payload
        self.caption = caption
        self.vision_embedding = vision_embedding
        self.dimensions = dimensions
        self.format = format
        self.size_bytes = size_bytes
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "file_hash": self.file_hash,
            "phash": self.phash,
            "exif_data": self.exif_data,
            "exif_description": self.exif_description,
            "embedded_text_from_exif": self.embedded_text_from_exif,
            "suspicious_metadata": self.suspicious_metadata,
            "ocr_text": self.ocr_text,
            "ocr_confidence": self.ocr_confidence,
            "stego_score": self.stego_score,
            "file_entropy": self.file_entropy,
            "suspicious_entropy": self.suspicious_entropy,
            "extracted_payload": self.extracted_payload,
            "caption": self.caption,
            "vision_embedding": self.vision_embedding,
            "dimensions": self.dimensions,
            "format": self.format,
            "size_bytes": self.size_bytes
        }


def calculate_phash(image_path: str) -> Optional[str]:
    """
    Calculate perceptual hash (pHash) of an image.
    
    Args:
        image_path: Path to image file
    
    Returns:
        pHash as hex string, or None if failed
    """
    if not IMAGEHASH_AVAILABLE or not PILLOW_AVAILABLE:
        logger.warning("imagehash or Pillow not available")
        return None
    
    try:
        with Image.open(image_path) as img:
            phash = imagehash.phash(img)
            return str(phash)
    except Exception as e:
        logger.error(f"Failed to calculate pHash: {e}")
        return None


def calculate_phash_from_bytes(image_bytes: bytes) -> Optional[str]:
    """
    Calculate pHash from image bytes.
    
    Args:
        image_bytes: Raw image data
    
    Returns:
        pHash as hex string, or None if failed
    """
    if not IMAGEHASH_AVAILABLE or not PILLOW_AVAILABLE:
        return None
    
    try:
        with Image.open(io.BytesIO(image_bytes)) as img:
            phash = imagehash.phash(img)
            return str(phash)
    except Exception as e:
        logger.error(f"Failed to calculate pHash from bytes: {e}")
        return None


def extract_exif_metadata(image_path: str) -> Dict[str, Any]:
    """
    Extract EXIF metadata from image.
    
    Args:
        image_path: Path to image file
    
    Returns:
        Dictionary of EXIF data
    """
    if not PIEXIF_AVAILABLE:
        logger.warning("piexif not available")
        return {}
    
    try:
        exif_dict = piexif.load(image_path)
        
        # Extract readable metadata
        metadata = {}
        
        # Process each IFD (Image File Directory)
        for ifd_name in ["0th", "Exif", "GPS", "1st"]:
            if ifd_name in exif_dict:
                ifd = exif_dict[ifd_name]
                for tag, value in ifd.items():
                    try:
                        tag_name = piexif.TAGS[ifd_name].get(tag, {}).get("name", f"Unknown_{tag}")
                        
                        # Convert bytes to string if possible
                        if isinstance(value, bytes):
                            try:
                                value = value.decode('utf-8', errors='ignore').strip('\x00')
                            except:
                                value = str(value)
                        
                        metadata[tag_name] = value
                    except Exception as e:
                        logger.debug(f"Error processing EXIF tag {tag}: {e}")
        
        return metadata
    
    except Exception as e:
        logger.error(f"Failed to extract EXIF: {e}")
        return {}


def extract_text_from_exif(exif_data: Dict) -> Tuple[Optional[str], bool]:
    """
    Extract textual descriptions from EXIF and check for suspicious content.
    
    Args:
        exif_data: EXIF metadata dictionary
    
    Returns:
        Tuple of (extracted_text, is_suspicious)
    """
    text_fields = []
    suspicious = False
    
    # Common text fields in EXIF
    text_keys = [
        'ImageDescription', 'UserComment', 'XPComment', 
        'XPTitle', 'XPSubject', 'XPKeywords', 'Artist',
        'Copyright', 'Software', 'Make', 'Model'
    ]
    
    for key in text_keys:
        if key in exif_data and exif_data[key]:
            value = str(exif_data[key])
            if value and len(value.strip()) > 0:
                text_fields.append(f"{key}: {value}")
                
                # Check for suspicious patterns
                if any(pattern in value.lower() for pattern in [
                    'ignore', 'system', 'override', '<', '>', 'script',
                    'base64', '===', 'admin', 'bypass'
                ]):
                    suspicious = True
    
    combined_text = ' | '.join(text_fields) if text_fields else None
    
    return combined_text, suspicious


def perform_ocr(image_path: str, confidence_threshold: float = 50.0) -> Tuple[Optional[str], Optional[float]]:
    """
    Perform OCR on image to extract text.
    
    Args:
        image_path: Path to image file
        confidence_threshold: Minimum confidence to include text
    
    Returns:
        Tuple of (extracted_text, average_confidence)
    """
    if not PYTESSERACT_AVAILABLE or not PILLOW_AVAILABLE:
        logger.warning("pytesseract or Pillow not available")
        return None, None
    
    try:
        with Image.open(image_path) as img:
            # Get detailed OCR data with confidence
            ocr_data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
            
            # Filter by confidence and extract text
            confident_text = []
            confidences = []
            
            for i in range(len(ocr_data['text'])):
                text = ocr_data['text'][i].strip()
                conf = float(ocr_data['conf'][i])
                
                if text and conf >= confidence_threshold:
                    confident_text.append(text)
                    confidences.append(conf)
            
            if confident_text:
                extracted_text = ' '.join(confident_text)
                avg_confidence = sum(confidences) / len(confidences)
                return extracted_text, avg_confidence
            else:
                return None, None
    
    except Exception as e:
        logger.error(f"OCR failed: {e}")
        return None, None


def calculate_image_entropy(image_path: str) -> Optional[float]:
    """
    Calculate Shannon entropy of image data.
    
    High entropy might indicate encrypted/steganographic content.
    
    Args:
        image_path: Path to image file
    
    Returns:
        Entropy value, or None if failed
    """
    if not PILLOW_AVAILABLE:
        return None
    
    try:
        with Image.open(image_path) as img:
            # Convert to grayscale for simpler analysis
            img_gray = img.convert('L')
            
            # Get pixel data
            pixels = np.array(img_gray)
            
            # Calculate histogram
            histogram, _ = np.histogram(pixels, bins=256, range=(0, 256))
            
            # Calculate probabilities
            histogram = histogram / histogram.sum()
            
            # Calculate Shannon entropy
            entropy = -np.sum(histogram * np.log2(histogram + 1e-10))
            
            return float(entropy)
    
    except Exception as e:
        logger.error(f"Failed to calculate entropy: {e}")
        return None


def detect_lsb_steganography(image_path: str) -> Tuple[float, Optional[str]]:
    """
    Detect potential LSB (Least Significant Bit) steganography.
    
    This is a heuristic check, not definitive detection.
    
    Args:
        image_path: Path to image file
    
    Returns:
        Tuple of (stego_score, extracted_payload)
    """
    if not PILLOW_AVAILABLE:
        return 0.0, None
    
    try:
        with Image.open(image_path) as img:
            # Convert to RGB
            img_rgb = img.convert('RGB')
            pixels = np.array(img_rgb)
            
            # Extract LSBs from each channel
            lsb_data = pixels & 1
            
            # Flatten to 1D
            lsb_flat = lsb_data.flatten()
            
            # Calculate randomness of LSBs (chi-square test approximation)
            ones = np.sum(lsb_flat)
            zeros = len(lsb_flat) - ones
            expected = len(lsb_flat) / 2
            
            # Chi-square statistic
            chi_square = ((ones - expected) ** 2 + (zeros - expected) ** 2) / expected
            
            # Normalize to 0-1 score (higher = more suspicious)
            # Threshold based on typical chi-square values
            stego_score = min(chi_square / 100.0, 1.0)
            
            # Try to extract potential hidden message from LSBs
            # (This is a simplified extraction - real stego uses more complex encoding)
            extracted_payload = None
            if stego_score > 0.6:
                # Try to extract first 100 bytes as ASCII
                try:
                    lsb_bytes = np.packbits(lsb_flat[:800])  # 100 bytes
                    decoded = lsb_bytes.tobytes().decode('ascii', errors='ignore')
                    if any(c.isprintable() and c not in ' \n\r\t' for c in decoded):
                        extracted_payload = decoded[:100]
                except:
                    pass
            
            return float(stego_score), extracted_payload
    
    except Exception as e:
        logger.error(f"LSB detection failed: {e}")
        return 0.0, None


def analyze_image_advanced(
    image_path: str,
    run_ocr: bool = False,
    ocr_confidence_threshold: float = 50.0
) -> AdvancedImageAnalysis:
    """
    Perform comprehensive advanced image analysis.
    
    Args:
        image_path: Path to image file
        run_ocr: Whether to run OCR (resource-intensive)
        ocr_confidence_threshold: Minimum OCR confidence
    
    Returns:
        AdvancedImageAnalysis object with all results
    """
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Image not found: {image_path}")
    
    # Calculate file hash
    with open(image_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    
    # Get basic image info
    dimensions = None
    image_format = None
    size_bytes = os.path.getsize(image_path)
    
    if PILLOW_AVAILABLE:
        try:
            with Image.open(image_path) as img:
                dimensions = img.size
                image_format = img.format or "unknown"
        except Exception as e:
            logger.error(f"Failed to read image info: {e}")
    
    # Calculate pHash
    phash = calculate_phash(image_path)
    
    # Extract EXIF
    exif_data = extract_exif_metadata(image_path)
    embedded_text, suspicious_metadata = extract_text_from_exif(exif_data)
    exif_description = exif_data.get('ImageDescription')
    
    # OCR (optional - resource intensive)
    ocr_text = None
    ocr_confidence = None
    if run_ocr:
        ocr_text, ocr_confidence = perform_ocr(image_path, ocr_confidence_threshold)
    
    # Calculate entropy
    file_entropy = calculate_image_entropy(image_path)
    suspicious_entropy = file_entropy is not None and file_entropy > 7.5
    
    # LSB steganography detection
    stego_score, extracted_payload = detect_lsb_steganography(image_path)
    
    # Placeholder for vision caption (would require transformer model)
    caption = None
    vision_embedding = None
    
    logger.info(
        f"Advanced image analysis complete: "
        f"phash={phash is not None}, exif_fields={len(exif_data)}, "
        f"entropy={file_entropy:.2f if file_entropy else 0}, "
        f"stego_score={stego_score:.2f}"
    )
    
    return AdvancedImageAnalysis(
        file_hash=file_hash,
        phash=phash,
        exif_data=exif_data,
        exif_description=exif_description,
        embedded_text_from_exif=embedded_text,
        suspicious_metadata=suspicious_metadata,
        ocr_text=ocr_text,
        ocr_confidence=ocr_confidence,
        stego_score=stego_score,
        file_entropy=file_entropy,
        suspicious_entropy=suspicious_entropy,
        extracted_payload=extracted_payload,
        caption=caption,
        vision_embedding=vision_embedding,
        dimensions=dimensions,
        format=image_format.lower() if image_format else None,
        size_bytes=size_bytes
    )


def check_libraries_available() -> Dict[str, bool]:
    """
    Check which advanced image processing libraries are available.
    
    Returns:
        Dictionary of library availability
    """
    return {
        "pillow": PILLOW_AVAILABLE,
        "imagehash": IMAGEHASH_AVAILABLE,
        "piexif": PIEXIF_AVAILABLE,
        "pytesseract": PYTESSERACT_AVAILABLE,
    }
