"""
Main FastAPI application for the Input Preparation Module.

Provides endpoints for text and media preparation with HMAC verification.
"""

import time
import os
from typing import Optional, List
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.models.schemas import PreparedInput, HealthResponse, InputRequest, MediaRequest
from app.utils.logger import setup_logging, get_logger, RequestLogger
from app.services.input_parser import parse_and_validate, validate_request
from app.services.file_extractor import (
    extract_file_text,
    validate_file,
    check_library_availability
)
from app.services.rag_handler import process_rag_data
from app.services.text_normalizer import normalize_text
from app.services.media_processor import (
    process_media,
    check_image_library_availability
)
from app.services.token_processor import calculate_tokens_and_stats
from app.services.payload_packager import (
    package_payload,
    validate_payload,
    summarize_payload,
    create_error_response
)

# Setup logging
setup_logging()
logger = get_logger(__name__)

# Create FastAPI app
app = FastAPI(
    title=settings.API_TITLE,
    version=settings.API_VERSION,
    description=(
        "Input Preparation Module for LLM-Protect pipeline. "
        "Handles file extraction, RAG data processing, text normalization, "
        "and HMAC verification for secure LLM input preparation."
    ),
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    """Initialize application on startup."""
    logger.info("=" * 60)
    logger.info(f"Starting {settings.API_TITLE} v{settings.API_VERSION}")
    logger.info(f"Upload directory: {settings.UPLOAD_DIR}")
    logger.info(f"Max file size: {settings.MAX_FILE_SIZE_MB}MB")
    logger.info(f"Allowed extensions: {settings.ALLOWED_EXTENSIONS}")
    
    # Check library availability
    file_libs = check_library_availability()
    logger.info(f"File extraction libraries: {file_libs}")
    logger.info(f"Image processing: {'enabled' if check_image_library_availability() else 'disabled'}")
    logger.info("=" * 60)


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint.
    
    Returns service status and library availability.
    """
    file_libs = check_library_availability()
    image_available = check_image_library_availability()
    
    all_libs = {
        **file_libs,
        "image": image_available,
    }
    
    # Determine status
    critical_missing = not all([file_libs["txt"], file_libs["md"]])
    
    if critical_missing:
        status_msg = "degraded"
        message = "Some critical libraries are missing"
    else:
        status_msg = "healthy"
        message = "All systems operational"
    
    return HealthResponse(
        status=status_msg,
        version=settings.API_VERSION,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        libraries=all_libs,
        message=message
    )


@app.post(
    f"{settings.API_PREFIX}/prepare-text",
    response_model=PreparedInput,
    status_code=status.HTTP_200_OK,
    summary="Prepare text input for Layer 0",
    description=(
        "Accepts text input with optional file uploads and external data. "
        "Processes through normalization, RAG handling, and HMAC signing. "
        "Returns structured data ready for Layer 0 (text processing)."
    )
)
async def prepare_text_input(
    user_prompt: str = Form(..., description="User's input text"),
    external_data: Optional[str] = Form(None, description="JSON array of external data strings"),
    file: Optional[UploadFile] = File(None, description="Optional file upload (TXT/MD/PDF/DOCX)"),
    file_path: Optional[str] = Form(None, description="Optional path to file on server"),
    retrieve_from_vector_db: bool = Form(False, description="Retrieve from vector database")
):
    """
    Prepare text input with comprehensive processing.
    
    Steps:
    1. Parse and validate input
    2. Extract text from file (if provided)
    3. Process RAG/external data
    4. Normalize text
    5. Calculate tokens and stats
    6. Package final payload with HMAC signatures
    """
    start_time = time.time()
    step_times = {}
    
    # Parse external_data if it's a JSON string
    import json
    external_data_list = None
    if external_data:
        try:
            external_data_list = json.loads(external_data)
        except json.JSONDecodeError:
            # Treat as single string
            external_data_list = [external_data]
    
    try:
        # Step 1: Parse and validate
        step_start = time.time()
        
        # Validate request
        valid, error = validate_request(user_prompt)
        if not valid:
            raise HTTPException(status_code=400, detail=error)
        
        # Handle file upload
        temp_file_path = None
        if file:
            # Save uploaded file
            filename = file.filename
            temp_file_path = str(settings.get_file_path(filename))
            
            with open(temp_file_path, "wb") as f:
                content = await file.read()
                f.write(content)
            
            logger.info(f"File uploaded: {filename} ({len(content)} bytes)")
            file_path = temp_file_path
        
        parsed = parse_and_validate(
            user_prompt=user_prompt,
            file_path=file_path,
            external_data=external_data_list
        )
        
        request_id = parsed["request_id"]
        step_times["parse_validate"] = (time.time() - step_start) * 1000
        
        with RequestLogger(request_id, logger) as req_logger:
            # Step 2: Extract file text (if file provided)
            step_start = time.time()
            file_chunks = []
            file_info = None
            
            if parsed["raw_file"] and parsed["validation"]["file_valid"]:
                valid_file, error = validate_file(parsed["raw_file"])
                if valid_file:
                    try:
                        file_chunks, file_info = extract_file_text(parsed["raw_file"])
                        req_logger.log_step("file_extraction", (time.time() - step_start) * 1000)
                    except Exception as e:
                        logger.error(f"File extraction failed: {e}")
                        # Continue without file data
                else:
                    logger.warning(f"File validation failed: {error}")
            
            step_times["file_extraction"] = (time.time() - step_start) * 1000
            
            # Step 3: Process RAG data
            step_start = time.time()
            external_chunks, hmacs, rag_enabled = process_rag_data(
                user_prompt=parsed["raw_user"],
                external_data=parsed["raw_external"],
                file_chunks=file_chunks,
                retrieve_from_db=retrieve_from_vector_db
            )
            step_times["rag_processing"] = (time.time() - step_start) * 1000
            req_logger.log_step("rag_processing", step_times["rag_processing"])
            
            # Step 4: Normalize text
            step_start = time.time()
            normalized_user, user_emojis, user_emoji_descs = normalize_text(
                parsed["raw_user"],
                preserve_emojis=True
            )
            
            # Normalize external chunks (already have delimiters)
            # The chunks are already delimited, so we just use them as-is
            normalized_external = external_chunks
            
            step_times["normalization"] = (time.time() - step_start) * 1000
            req_logger.log_step("normalization", step_times["normalization"])
            
            # Step 5: Process media (emojis only for text endpoint)
            step_start = time.time()
            image_dict, emoji_summary = process_media(
                emojis=user_emojis,
                emoji_descriptions=user_emoji_descs
            )
            step_times["media_processing"] = (time.time() - step_start) * 1000
            
            # Step 6: Calculate tokens and stats
            step_start = time.time()
            
            # Calculate total extracted chars from file
            extracted_total_chars = sum(len(chunk.content) for chunk in file_chunks)
            
            stats = calculate_tokens_and_stats(
                user_text=normalized_user,
                external_chunks=normalized_external,
                file_chunks_count=len(file_chunks),
                extracted_total_chars=extracted_total_chars
            )
            step_times["token_calculation"] = (time.time() - step_start) * 1000
            req_logger.log_step("token_calculation", step_times["token_calculation"])
            
            # Step 7: Package payload
            step_start = time.time()
            total_time = (time.time() - start_time) * 1000
            
            prepared = package_payload(
                normalized_user=normalized_user,
                normalized_external=normalized_external,
                emoji_descriptions=user_emoji_descs,
                hmacs=hmacs,
                stats=stats,
                image_dict={},  # No image for text endpoint
                emoji_summary=emoji_summary,
                request_id=request_id,
                rag_enabled=rag_enabled,
                has_media=False,
                has_file=bool(file_chunks),
                file_info=file_info,
                prep_time_ms=total_time,
                step_times=step_times
            )
            step_times["packaging"] = (time.time() - step_start) * 1000
            
            # Validate payload
            valid_payload, payload_error = validate_payload(prepared)
            if not valid_payload:
                logger.error(f"Payload validation failed: {payload_error}")
                raise HTTPException(status_code=500, detail=f"Payload validation failed: {payload_error}")
            
            # Log summary
            logger.info(summarize_payload(prepared))
            
            # Cleanup temp file
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                except Exception as e:
                    logger.warning(f"Failed to cleanup temp file: {e}")
            
            return prepared
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing request: {e}", exc_info=True)
        total_time = (time.time() - start_time) * 1000
        return create_error_response(str(e), prep_time_ms=total_time)


@app.post(
    f"{settings.API_PREFIX}/prepare-media",
    response_model=PreparedInput,
    status_code=status.HTTP_200_OK,
    summary="Prepare media input for image/emoji processing",
    description=(
        "Accepts text with images and emojis. "
        "Processes media metadata and returns data ready for "
        "specialized image/emoji analysis layers."
    )
)
async def prepare_media_input(
    user_prompt: str = Form(..., description="User's input text"),
    image: Optional[UploadFile] = File(None, description="Optional image upload"),
    image_path: Optional[str] = Form(None, description="Optional path to image on server")
):
    """
    Prepare media input (images and emojis).
    
    Steps:
    1. Parse and validate input
    2. Process image metadata
    3. Extract and process emojis
    4. Package payload
    """
    start_time = time.time()
    step_times = {}
    
    try:
        # Step 1: Parse and validate
        step_start = time.time()
        
        valid, error = validate_request(user_prompt)
        if not valid:
            raise HTTPException(status_code=400, detail=error)
        
        # Handle image upload
        temp_image_path = None
        if image:
            filename = image.filename
            temp_image_path = str(settings.get_file_path(filename))
            
            with open(temp_image_path, "wb") as f:
                content = await image.read()
                f.write(content)
            
            logger.info(f"Image uploaded: {filename} ({len(content)} bytes)")
            image_path = temp_image_path
        
        parsed = parse_and_validate(
            user_prompt=user_prompt,
            image_path=image_path
        )
        
        request_id = parsed["request_id"]
        step_times["parse_validate"] = (time.time() - step_start) * 1000
        
        with RequestLogger(request_id, logger) as req_logger:
            # Step 2: Normalize text and extract emojis
            step_start = time.time()
            normalized_user, user_emojis, user_emoji_descs = normalize_text(
                parsed["raw_user"],
                preserve_emojis=True
            )
            step_times["normalization"] = (time.time() - step_start) * 1000
            req_logger.log_step("normalization", step_times["normalization"])
            
            # Step 3: Process media
            step_start = time.time()
            image_dict, emoji_summary = process_media(
                image_path=parsed["raw_image"] if parsed["validation"]["image_valid"] else None,
                emojis=user_emojis,
                emoji_descriptions=user_emoji_descs
            )
            step_times["media_processing"] = (time.time() - step_start) * 1000
            req_logger.log_step("media_processing", step_times["media_processing"])
            
            # Step 4: Calculate stats (minimal for media endpoint)
            step_start = time.time()
            stats = calculate_tokens_and_stats(
                user_text=normalized_user,
                external_chunks=[],
                file_chunks_count=0,
                extracted_total_chars=0
            )
            step_times["token_calculation"] = (time.time() - step_start) * 1000
            
            # Step 5: Package payload
            step_start = time.time()
            total_time = (time.time() - start_time) * 1000
            
            prepared = package_payload(
                normalized_user=normalized_user,
                normalized_external=[],
                emoji_descriptions=user_emoji_descs,
                hmacs=[],
                stats=stats,
                image_dict=image_dict,
                emoji_summary=emoji_summary,
                request_id=request_id,
                rag_enabled=False,
                has_media=bool(image_dict and "error" not in image_dict),
                has_file=False,
                file_info=None,
                prep_time_ms=total_time,
                step_times=step_times
            )
            step_times["packaging"] = (time.time() - step_start) * 1000
            
            # Validate payload
            valid_payload, payload_error = validate_payload(prepared)
            if not valid_payload:
                logger.error(f"Payload validation failed: {payload_error}")
                raise HTTPException(status_code=500, detail=f"Payload validation failed: {payload_error}")
            
            # Log summary
            logger.info(summarize_payload(prepared))
            
            # Cleanup temp file
            if temp_image_path and os.path.exists(temp_image_path):
                try:
                    os.remove(temp_image_path)
                except Exception as e:
                    logger.warning(f"Failed to cleanup temp image: {e}")
            
            return prepared
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing media request: {e}", exc_info=True)
        total_time = (time.time() - start_time) * 1000
        return create_error_response(str(e), prep_time_ms=total_time)


@app.get("/")
async def root():
    """Root endpoint - redirect to docs."""
    return {
        "message": "LLM-Protect Input Preparation API",
        "version": settings.API_VERSION,
        "docs": "/docs",
        "health": "/health"
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=True,
        log_level=settings.LOG_LEVEL.lower()
    )

