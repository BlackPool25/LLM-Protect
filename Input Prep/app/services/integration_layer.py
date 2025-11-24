"""
Integration layer for all advanced processing services.

Combines unicode detection, heuristics, text embeddings, and advanced image processing
into a unified pipeline.
"""

import time
from typing import List, Optional, Dict, Any
from pathlib import Path

from app.utils.logger import get_logger
from app.models.schemas import (
    Layer0Output, ImageProcessingOutput, UnicodeAnalysis, HeuristicFlags as HeuristicFlagsSchema,
    ExifData, SteganographyAnalysis, AdvancedImageData, EmojiSummary
)

# Import processing modules
from app.services.unicode_detector import analyze_unicode_obfuscation
from app.services.heuristics import run_fast_heuristics
from app.services.text_embeddings import generate_text_embedding
from app.services.advanced_image_processor import analyze_image_advanced, check_libraries_available
from app.services.file_extractor import extract_images_from_pdf

logger = get_logger(__name__)


def prepare_layer0_output(
    request_id: str,
    timestamp: str,
    user_text: str,
    external_texts: List[str],
    hmac_verified: bool,
    emoji_count: int,
    emoji_descriptions: List[str],
    token_count: int,
    char_total: int,
    attachment_texts: List[str],
    prep_time_ms: float,
    store_raw_snapshot: bool = True
) -> Layer0Output:
    """
    Prepare Layer 0 output with all advanced analysis.
    
    Args:
        request_id: Unique request identifier
        timestamp: ISO timestamp
        user_text: User input text
        external_texts: List of external data texts
        hmac_verified: Whether HMACs are verified
        emoji_count: Number of emojis
        emoji_descriptions: Emoji descriptions
        token_count: Estimated token count
        char_total: Total character count
        attachment_texts: Text from attachments (EXIF, OCR, captions)
        prep_time_ms: Preparation time
        store_raw_snapshot: Whether to store raw text snapshot
    
    Returns:
        Layer0Output with comprehensive analysis
    """
    start_time = time.time()
    
    # Combine all text for analysis
    combined_text = user_text + ' ' + ' '.join(external_texts)
    
    # Unicode obfuscation analysis
    unicode_result = analyze_unicode_obfuscation(combined_text)
    normalized_text = unicode_result.normalized_text
    
    # Convert to schema
    unicode_analysis = UnicodeAnalysis(
        zero_width_found=unicode_result.zero_width_found,
        invisible_chars_found=unicode_result.invisible_chars_found,
        unicode_obfuscation_flag=unicode_result.unicode_obfuscation_flag,
        zero_width_count=unicode_result.zero_width_count,
        invisible_count=unicode_result.invisible_count,
        zero_width_positions=unicode_result.zero_width_positions,
        normalization_changes=unicode_result.normalization_changes,
        unicode_diff=unicode_result.unicode_diff
    )
    
    # Fast heuristics
    heuristic_result = run_fast_heuristics(combined_text)
    
    heuristic_flags = HeuristicFlagsSchema(
        has_long_base64=heuristic_result.has_long_base64,
        has_system_delimiter=heuristic_result.has_system_delimiter,
        has_repeated_chars=heuristic_result.has_repeated_chars,
        has_long_single_line=heuristic_result.has_long_single_line,
        has_xml_tags=heuristic_result.has_xml_tags,
        has_html_comments=heuristic_result.has_html_comments,
        has_suspicious_keywords=heuristic_result.has_suspicious_keywords,
        has_many_delimiters=heuristic_result.has_many_delimiters,
        suspicious_score=heuristic_result.suspicious_score,
        detected_patterns=heuristic_result.detected_patterns
    )
    
    # Generate text embedding for semantic fingerprinting
    embedding_hash = generate_text_embedding(normalized_text)
    if embedding_hash:
        logger.info(f"[{request_id[:8]}] Generated text embedding: {embedding_hash}")
    
    # Calculate combined suspicious score
    suspicious_score = (heuristic_result.suspicious_score * 0.7 + 
                       (0.3 if unicode_result.unicode_obfuscation_flag else 0.0))
    
    analysis_time = (time.time() - start_time) * 1000
    logger.info(
        f"[{request_id[:8]}] Layer 0 analysis: "
        f"unicode_obfuscation={unicode_result.unicode_obfuscation_flag}, "
        f"suspicious_score={suspicious_score:.2f}, "
        f"embedding={'yes' if embedding_hash else 'no'}, "
        f"time={analysis_time:.1f}ms"
    )
    
    return Layer0Output(
        request_id=request_id,
        timestamp=timestamp,
        normalized_text=normalized_text,
        special_char_mask=unicode_result.special_char_mask,
        token_count=token_count,
        text_embedding_hash=embedding_hash,
        unicode_analysis=unicode_analysis,
        heuristic_flags=heuristic_flags,
        hmac_verified=hmac_verified,
        external_data_count=len(external_texts),
        attachment_texts=attachment_texts,
        emoji_count=emoji_count,
        emoji_descriptions=emoji_descriptions,
        char_total=char_total,
        suspicious_score=suspicious_score,
        raw_text_snapshot_stored=store_raw_snapshot,
        prep_time_ms=prep_time_ms + analysis_time
    )


def prepare_image_processing_output(
    request_id: str,
    timestamp: str,
    image_paths: List[str],
    pdf_path: Optional[str],
    emoji_summary: EmojiSummary,
    run_ocr: bool = False,
    ocr_confidence: float = 50.0
) -> ImageProcessingOutput:
    """
    Prepare image processing output with advanced analysis.
    
    Args:
        request_id: Unique request identifier
        timestamp: ISO timestamp
        image_paths: List of image file paths
        pdf_path: Optional PDF file path (to extract images from)
        emoji_summary: Emoji summary data
        run_ocr: Whether to run OCR
        ocr_confidence: OCR confidence threshold
    
    Returns:
        ImageProcessingOutput with comprehensive image analysis
    """
    start_time = time.time()
    
    analyzed_images = []
    images_from_pdf = []
    all_exif_texts = []
    all_ocr_texts = []
    
    suspicious_count = 0
    exif_found = False
    ocr_found = False
    stego_detected = False
    
    # Process regular uploaded images
    for img_path in image_paths:
        try:
            analysis = analyze_image_advanced(
                img_path,
                run_ocr=run_ocr,
                ocr_confidence_threshold=ocr_confidence
            )
            
            # Convert to schema
            image_data = AdvancedImageData(
                file_hash=analysis.file_hash,
                phash=analysis.phash,
                exif=ExifData(
                    raw_data=analysis.exif_data,
                    description=analysis.exif_description,
                    embedded_text=analysis.embedded_text_from_exif,
                    suspicious=analysis.suspicious_metadata
                ),
                ocr_text=analysis.ocr_text,
                ocr_confidence=analysis.ocr_confidence,
                steganography=SteganographyAnalysis(
                    stego_score=analysis.stego_score,
                    file_entropy=analysis.file_entropy,
                    suspicious_entropy=analysis.suspicious_entropy,
                    extracted_payload=analysis.extracted_payload
                ),
                caption=analysis.caption,
                vision_embedding=analysis.vision_embedding,
                dimensions=analysis.dimensions,
                format=analysis.format,
                size_bytes=analysis.size_bytes
            )
            
            analyzed_images.append(image_data)
            
            # Collect texts
            if analysis.embedded_text_from_exif:
                all_exif_texts.append(analysis.embedded_text_from_exif)
                exif_found = True
            
            if analysis.ocr_text:
                all_ocr_texts.append(analysis.ocr_text)
                ocr_found = True
            
            # Check suspiciousness
            if (analysis.suspicious_metadata or 
                analysis.stego_score > 0.6 or 
                analysis.suspicious_entropy):
                suspicious_count += 1
            
            if analysis.stego_score > 0.6:
                stego_detected = True
                
        except Exception as e:
            logger.error(f"Failed to analyze image {img_path}: {e}")
    
    # Extract and process images from PDF if provided
    if pdf_path:
        try:
            extracted_images_info = extract_images_from_pdf(pdf_path)
            
            for img_info in extracted_images_info:
                img_path = img_info['path']
                
                try:
                    analysis = analyze_image_advanced(
                        img_path,
                        run_ocr=run_ocr,
                        ocr_confidence_threshold=ocr_confidence
                    )
                    
                    image_data = AdvancedImageData(
                        file_hash=analysis.file_hash,
                        phash=analysis.phash,
                        exif=ExifData(
                            raw_data=analysis.exif_data,
                            description=analysis.exif_description,
                            embedded_text=analysis.embedded_text_from_exif,
                            suspicious=analysis.suspicious_metadata
                        ),
                        ocr_text=analysis.ocr_text,
                        ocr_confidence=analysis.ocr_confidence,
                        steganography=SteganographyAnalysis(
                            stego_score=analysis.stego_score,
                            file_entropy=analysis.file_entropy,
                            suspicious_entropy=analysis.suspicious_entropy,
                            extracted_payload=analysis.extracted_payload
                        ),
                        caption=analysis.caption,
                        vision_embedding=analysis.vision_embedding,
                        dimensions=analysis.dimensions,
                        format=analysis.format,
                        size_bytes=analysis.size_bytes
                    )
                    
                    images_from_pdf.append(image_data)
                    
                    # Collect texts
                    if analysis.embedded_text_from_exif:
                        all_exif_texts.append(analysis.embedded_text_from_exif)
                        exif_found = True
                    
                    if analysis.ocr_text:
                        all_ocr_texts.append(analysis.ocr_text)
                        ocr_found = True
                    
                    if (analysis.suspicious_metadata or 
                        analysis.stego_score > 0.6 or 
                        analysis.suspicious_entropy):
                        suspicious_count += 1
                    
                    if analysis.stego_score > 0.6:
                        stego_detected = True
                        
                except Exception as e:
                    logger.error(f"Failed to analyze PDF image {img_path}: {e}")
                    
        except Exception as e:
            logger.error(f"Failed to extract images from PDF {pdf_path}: {e}")
    
    total_images = len(analyzed_images) + len(images_from_pdf)
    prep_time = (time.time() - start_time) * 1000
    
    logger.info(
        f"[{request_id[:8]}] Image processing: "
        f"total={total_images}, suspicious={suspicious_count}, "
        f"exif={exif_found}, ocr={ocr_found}, stego={stego_detected}, "
        f"time={prep_time:.1f}ms"
    )
    
    return ImageProcessingOutput(
        request_id=request_id,
        timestamp=timestamp,
        images=analyzed_images,
        images_from_pdf=images_from_pdf,
        total_images=total_images,
        suspicious_images_count=suspicious_count,
        exif_metadata_found=exif_found,
        ocr_text_found=ocr_found,
        steganography_detected=stego_detected,
        all_exif_texts=all_exif_texts,
        all_ocr_texts=all_ocr_texts,
        emoji_summary=emoji_summary,
        prep_time_ms=prep_time,
        libraries_used=check_libraries_available()
    )
