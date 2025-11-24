"""
Main FastAPI application for the Input Preparation Module.

Provides endpoints for text and media preparation with HMAC verification.
"""

import time
import os
from datetime import datetime
from typing import Optional, List
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, status, Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.config import settings
from app.models.schemas import (
    PreparedInput, HealthResponse, InputRequest, MediaRequest,
    Layer0Output, ImageProcessingOutput, EmojiSummary
)
from app.utils.logger import setup_logging, get_logger, RequestLogger
from app.services.input_parser import parse_and_validate, validate_request
from app.services.file_extractor import (
    extract_file_text,
    validate_file,
    check_library_availability,
    extract_images_from_pdf
)
from app.services.rag_handler import process_rag_data
from app.services.text_normalizer import normalize_text
from app.services.media_processor import (
    process_media,
    check_image_library_availability,
    save_media_for_further_processing
)
from app.services.token_processor import calculate_tokens_and_stats
from app.services.payload_packager import (
    package_payload,
    validate_payload,
    summarize_payload,
    create_error_response
)
from app.services.llm_service import generate_response, check_model_availability
from app.services.output_saver import get_output_saver
from app.services.session_manager import get_session_manager, format_conversation_for_rag
from app.services.integration_layer import prepare_layer0_output, prepare_image_processing_output

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

# Mount static files (for web interface)
try:
    from pathlib import Path
    static_path = Path(__file__).parent / "static"
    static_path.mkdir(exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")
except Exception as e:
    logger.warning(f"Could not mount static files: {e}")


# Pydantic models for LLM endpoints
class GenerateRequest(BaseModel):
    """Request model for LLM generation."""
    prepared_input: PreparedInput
    max_new_tokens: int = 512
    temperature: float = 0.7
    top_p: float = 0.9
    do_sample: bool = True


class GenerateResponse(BaseModel):
    """Response model for LLM generation."""
    success: bool
    generated_text: str
    input_tokens: int
    output_tokens: int
    total_time_ms: float
    model: str = "gemma-2b"
    error: Optional[str] = None
    preparation_metadata: Optional[dict] = None


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
    
    # Check advanced image processing libraries
    from app.services.advanced_image_processor import check_libraries_available
    advanced_libs = check_libraries_available()
    
    all_libs = {
        **file_libs,
        "image": image_available,
        **advanced_libs
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
    retrieve_from_vector_db: bool = Form(False, description="Retrieve from vector database"),
    session_id: Optional[str] = Form(None, description="Session ID for conversation memory"),
    use_conversation_history: bool = Form(True, description="Include conversation history as context")
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
    
    # Handle session management
    session_manager = get_session_manager()
    
    # Create or get session
    if session_id is None:
        session_id = session_manager.create_session()
        logger.info(f"Created new session: {session_id[:8]}...")
    elif not session_manager.get_session(session_id):
        logger.warning(f"Session {session_id[:8]} not found, creating new one")
        session_id = session_manager.create_session()
    else:
        logger.info(f"Using existing session: {session_id[:8]}...")
    
    # Get conversation history if enabled (KEEP SEPARATE from RAG per INNOVATION 4)
    conversation_text = None
    if use_conversation_history:
        messages = session_manager.get_context(session_id, limit=5)
        if messages:
            history_text = format_conversation_for_rag(messages, max_messages=5)
            if history_text:
                conversation_text = history_text
                logger.info(f"[{session_id[:8]}] Retrieved {len(messages)} messages from conversation history (will be tagged [CONVERSATION])")
    
    # NOTE: Conversation context is NOT merged with external_data_list
    # It will be processed separately to avoid confusing conversation with RAG data
    
    try:
        # Step 1: Parse and validate
        step_start = time.time()
        
        # Validate request
        valid, error = validate_request(user_prompt)
        if not valid:
            raise HTTPException(status_code=400, detail=error)
        
        # Handle file upload
        temp_file_path = None
        temp_image_path = None
        if file and file.filename:
            # Save uploaded file
            filename = file.filename
            if not filename.strip():
                raise HTTPException(status_code=400, detail="Empty filename provided")
            
            # Validate file extension
            if not settings.is_allowed_extension(filename):
                raise HTTPException(
                    status_code=400, 
                    detail=f"File type not allowed. Allowed types: {', '.join(sorted(settings.ALLOWED_EXTENSIONS))}"
                )
            
            temp_file_path = str(settings.get_file_path(filename))
            
            with open(temp_file_path, "wb") as f:
                content = await file.read()
                f.write(content)
            
            # Validate file size
            if not settings.validate_file_size(len(content)):
                os.remove(temp_file_path)  # Cleanup
                raise HTTPException(
                    status_code=400, 
                    detail=f"File too large. Max size: {settings.MAX_FILE_SIZE_MB}MB"
                )
            
            logger.info(f"File uploaded: {filename} ({len(content)} bytes)")
            
            # Determine if it's an image or text file
            if settings.is_image_file(filename):
                temp_image_path = temp_file_path
                logger.info(f"Image file detected: {filename} - will process as media")
            else:
                file_path = temp_file_path
                logger.info(f"Text file detected: {filename} - will extract text")
        
        # Pass image_path if it's an image file
        parsed = parse_and_validate(
            user_prompt=user_prompt,
            file_path=file_path,
            image_path=temp_image_path,  # New: pass image if uploaded
            external_data=external_data_list
        )
        
        request_id = parsed["request_id"]
        step_times["parse_validate"] = (time.time() - step_start) * 1000
        
        # DETAILED LOG: Show parsed input
        logger.info(f"[{request_id}] ===== STEP 1: PARSED INPUT =====")
        logger.info(f"[{request_id}] Raw user text: {parsed['raw_user'][:100]}..." if len(parsed['raw_user']) > 100 else f"[{request_id}] Raw user text: {parsed['raw_user']}")
        logger.info(f"[{request_id}] External data items: {len(parsed['raw_external'])}")
        if parsed['raw_external']:
            for i, ext in enumerate(parsed['raw_external'][:3]):  # Show first 3
                logger.info(f"[{request_id}]   External[{i}]: {ext[:80]}..." if len(ext) > 80 else f"[{request_id}]   External[{i}]: {ext}")
        logger.info(f"[{request_id}] File provided: {parsed['raw_file'] or 'None'}")
        logger.info(f"[{request_id}] Image provided: {parsed.get('raw_image') or 'None'}")
        logger.info(f"[{request_id}] Validation: {parsed['validation']}")
        
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
                        
                        # DETAILED LOG: Show file extraction results
                        logger.info(f"[{request_id}] ===== STEP 2: FILE EXTRACTION =====")
                        logger.info(f"[{request_id}] File: {file_info.original_path}")
                        logger.info(f"[{request_id}] Type: {file_info.type}, Hash: {file_info.hash[:16]}...")
                        logger.info(f"[{request_id}] Extraction success: {file_info.extraction_success}")
                        logger.info(f"[{request_id}] Chunks created: {file_info.chunk_count}")
                        if file_chunks:
                            logger.info(f"[{request_id}] First chunk preview: {file_chunks[0].content[:100]}...")
                            logger.info(f"[{request_id}] Total extracted chars: {sum(len(c.content) for c in file_chunks)}")
                    except Exception as e:
                        logger.error(f"File extraction failed: {e}")
                        # Continue without file data
                else:
                    logger.warning(f"File validation failed: {error}")
            else:
                logger.info(f"[{request_id}] ===== STEP 2: FILE EXTRACTION =====")
                logger.info(f"[{request_id}] No file provided")
            
            step_times["file_extraction"] = (time.time() - step_start) * 1000
            
            # Step 3: Process RAG data and conversation context (SEPARATE per INNOVATION 4)
            step_start = time.time()
            external_chunks, hmacs, rag_enabled = process_rag_data(
                user_prompt=parsed["raw_user"],
                external_data=parsed["raw_external"],
                file_chunks=file_chunks,
                retrieve_from_db=retrieve_from_vector_db,
                conversation_text=conversation_text  # Separate from RAG!
            )
            step_times["rag_processing"] = (time.time() - step_start) * 1000
            req_logger.log_step("rag_processing", step_times["rag_processing"])
            
            # DETAILED LOG: Show RAG processing
            logger.info(f"[{request_id}] ===== STEP 3: CONTEXT PROCESSING (Conversation + RAG) =====")
            logger.info(f"[{request_id}] RAG enabled: {rag_enabled}")
            logger.info(f"[{request_id}] External chunks processed: {len(external_chunks)}")
            logger.info(f"[{request_id}] HMAC signatures generated: {len(hmacs)}")
            if external_chunks:
                for i, (chunk, hmac) in enumerate(list(zip(external_chunks, hmacs))[:3]):  # Show first 3
                    logger.info(f"[{request_id}]   Chunk[{i}]: {chunk[:80]}...")
                    logger.info(f"[{request_id}]   HMAC[{i}]: {hmac[:16]}...")
            logger.info(f"[{request_id}] Delimiter format: [EXTERNAL]content[/EXTERNAL]")
            
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
            
            # DETAILED LOG: Show normalization
            logger.info(f"[{request_id}] ===== STEP 4: TEXT NORMALIZATION =====")
            logger.info(f"[{request_id}] Original user text length: {len(parsed['raw_user'])}")
            logger.info(f"[{request_id}] Normalized user text length: {len(normalized_user)}")
            logger.info(f"[{request_id}] Normalized text: {normalized_user[:100]}..." if len(normalized_user) > 100 else f"[{request_id}] Normalized text: {normalized_user}")
            logger.info(f"[{request_id}] Emojis found: {len(user_emojis)}")
            if user_emojis:
                logger.info(f"[{request_id}] Emoji types: {user_emojis}")
                logger.info(f"[{request_id}] Emoji descriptions: {user_emoji_descs}")
            logger.info(f"[{request_id}] Emojis preserved in text: YES")
            
            # Step 5: Process media (images and/or emojis)
            step_start = time.time()
            
            # Process image if uploaded (new feature!)
            image_to_process = parsed.get("raw_image") if parsed.get("validation", {}).get("image_valid") else None
            
            image_dict, emoji_summary = process_media(
                image_path=image_to_process,
                emojis=user_emojis,
                emoji_descriptions=user_emoji_descs
            )
            
            if image_to_process:
                logger.info(f"[{request_id}] Image processed from upload: {image_to_process}")
            
            step_times["media_processing"] = (time.time() - step_start) * 1000
            
            # Save media for further layer processing if present
            if (image_dict and "error" not in image_dict) or user_emojis:
                media_paths = save_media_for_further_processing(
                    image_path=image_to_process,
                    image_metadata=image_dict if image_dict and "error" not in image_dict else None,
                    emoji_data=[{"char": e, "desc": d} for e, d in zip(user_emojis, user_emoji_descs)] if user_emojis else None,
                    request_id=request_id
                )
                if media_paths:
                    logger.info(f"[{request_id}] ✓ Media saved for further processing at: {media_paths['temp_dir']}")
            
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
            
            # DETAILED LOG: Show token stats
            logger.info(f"[{request_id}] ===== STEP 5: TOKEN & STATS CALCULATION =====")
            logger.info(f"[{request_id}] Total characters: {stats.char_total}")
            logger.info(f"[{request_id}] Estimated tokens: {stats.token_estimate}")
            logger.info(f"[{request_id}] User/External ratio: {stats.user_external_ratio:.2%}")
            logger.info(f"[{request_id}] File chunks: {stats.file_chunks_count}")
            logger.info(f"[{request_id}] Extracted file chars: {stats.extracted_total_chars}")
            
            # Step 6.5: Layer 0 Analysis (Unicode + Heuristics)
            step_start = time.time()
            attachment_texts = []
            if image_dict and "description" in image_dict and image_dict["description"]:
                attachment_texts.append(image_dict["description"])
            
            layer0_output = prepare_layer0_output(
                request_id=request_id,
                timestamp=datetime.utcnow().isoformat() + 'Z',
                user_text=normalized_user,
                external_texts=normalized_external,
                hmac_verified=len(hmacs) == len(normalized_external),
                emoji_count=emoji_summary.count,
                emoji_descriptions=user_emoji_descs,
                token_count=stats.token_estimate,
                char_total=stats.char_total,
                attachment_texts=attachment_texts,
                prep_time_ms=(time.time() - start_time) * 1000,
                store_raw_snapshot=True
            )
            step_times["layer0_analysis"] = (time.time() - step_start) * 1000
            
            logger.info(f"[{request_id}] ===== LAYER 0 ANALYSIS =====")
            logger.info(f"[{request_id}] Unicode obfuscation: {layer0_output.unicode_analysis.unicode_obfuscation_flag}")
            logger.info(f"[{request_id}] Zero-width chars: {layer0_output.unicode_analysis.zero_width_count}")
            logger.info(f"[{request_id}] Suspicion score: {layer0_output.suspicious_score:.2%}")
            if layer0_output.heuristic_flags.detected_patterns:
                logger.info(f"[{request_id}] Detected patterns: {', '.join(layer0_output.heuristic_flags.detected_patterns)}")
            
            # Step 7: Package payload
            step_start = time.time()
            total_time = (time.time() - start_time) * 1000
            
            prepared = package_payload(
                normalized_user=normalized_user,
                normalized_external=normalized_external,
                emoji_descriptions=user_emoji_descs,
                hmacs=hmacs,
                stats=stats,
                image_dict=image_dict if image_dict else {},
                emoji_summary=emoji_summary,
                request_id=request_id,
                session_id=session_id,
                rag_enabled=rag_enabled,
                has_media=bool(image_dict and "error" not in image_dict),
                has_file=bool(file_chunks),
                file_info=file_info,
                prep_time_ms=total_time,
                step_times=step_times,
                layer0_output=layer0_output
            )
            step_times["packaging"] = (time.time() - step_start) * 1000
            
            # DETAILED LOG: Show final payload
            logger.info(f"[{request_id}] ===== STEP 6: PAYLOAD PACKAGING =====")
            logger.info(f"[{request_id}] PreparedInput structure created:")
            logger.info(f"[{request_id}]   text_embed_stub:")
            logger.info(f"[{request_id}]     - normalized_user: {len(prepared.text_embed_stub.normalized_user)} chars")
            logger.info(f"[{request_id}]     - normalized_external: {len(prepared.text_embed_stub.normalized_external)} chunks")
            logger.info(f"[{request_id}]     - hmacs: {len(prepared.text_embed_stub.hmacs)} signatures")
            logger.info(f"[{request_id}]     - emoji_descriptions: {len(prepared.text_embed_stub.emoji_descriptions)}")
            logger.info(f"[{request_id}]   image_emoji_stub:")
            logger.info(f"[{request_id}]     - emoji_summary.count: {prepared.image_emoji_stub.emoji_summary.count}")
            logger.info(f"[{request_id}]   metadata:")
            logger.info(f"[{request_id}]     - request_id: {prepared.metadata.request_id}")
            logger.info(f"[{request_id}]     - rag_enabled: {prepared.metadata.rag_enabled}")
            logger.info(f"[{request_id}]     - has_file: {prepared.metadata.has_file}")
            logger.info(f"[{request_id}]     - prep_time_ms: {prepared.metadata.prep_time_ms:.2f}")
            
            # Validate payload
            valid_payload, payload_error = validate_payload(prepared)
            if not valid_payload:
                logger.error(f"Payload validation failed: {payload_error}")
                raise HTTPException(status_code=500, detail=f"Payload validation failed: {payload_error}")
            
            logger.info(f"[{request_id}] ✓ Payload validation: PASSED")
            
            # Save output to disk
            output_saver = get_output_saver()
            saved_path = output_saver.save_layer0_output(prepared)
            if saved_path:
                logger.info(f"[{request_id}] ✓ Output saved to: {saved_path}")
            
            # Save user message to session
            session_manager.add_message(session_id, "user", user_prompt)
            logger.info(f"[{session_id[:8]}] Saved user message to session")
            
            # Log summary
            logger.info(f"[{request_id}] ===== PREPARATION COMPLETE =====")
            logger.info(summarize_payload(prepared))
            logger.info(f"[{request_id}] → Ready to send to /api/v1/generate endpoint")
            
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
            
            # Save output to disk
            output_saver = get_output_saver()
            saved_path = output_saver.save_media_output(prepared)
            if saved_path:
                logger.info(f"[{request_id}] ✓ Output saved to: {saved_path}")
            
            # Save media for further layer processing (per architecture plan)
            if image_dict or user_emojis:
                media_paths = save_media_for_further_processing(
                    image_path=temp_image_path if image_dict and "error" not in image_dict else None,
                    image_metadata=image_dict if image_dict else None,
                    emoji_data=[{"char": e, "desc": d} for e, d in zip(user_emojis, user_emoji_descs)] if user_emojis else None,
                    request_id=request_id
                )
                if media_paths:
                    logger.info(f"[{request_id}] ✓ Media saved for further processing at: {media_paths['temp_dir']}")
            
            # Log summary
            logger.info(summarize_payload(prepared))
            
            # Cleanup temp file ONLY if we didn't save it for further processing
            # (if we saved it, it's been copied to temp_media)
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


@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the web interface."""
    try:
        from pathlib import Path
        html_path = Path(__file__).parent / "static" / "index.html"
        if html_path.exists():
            return html_path.read_text()
        else:
            return """
            <html>
                <body>
                    <h1>LLM-Protect Input Preparation API</h1>
                    <p>Version: {}</p>
                    <ul>
                        <li><a href="/docs">API Documentation</a></li>
                        <li><a href="/health">Health Check</a></li>
                    </ul>
                </body>
            </html>
            """.format(settings.API_VERSION)
    except Exception as e:
        logger.error(f"Error serving root: {e}")
        return HTMLResponse(f"<h1>Error: {e}</h1>", status_code=500)


@app.post(
    f"{settings.API_PREFIX}/generate",
    response_model=GenerateResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate LLM response from prepared input",
    description=(
        "Takes prepared input from /prepare-text endpoint and generates "
        "a response using Gemma 2B. This endpoint receives the HMAC-verified "
        "and processed input data and runs it through the LLM."
    )
)
async def generate_llm_response(request: GenerateRequest):
    """
    Generate LLM response from prepared input.
    
    This endpoint receives the output from /prepare-text and uses it to
    generate a response with the Gemma 2B model.
    """
    start_time = time.time()
    
    try:
        # Extract the prepared data
        prepared = request.prepared_input
        
        # Construct the prompt from prepared data
        # Combine user input with external data context
        prompt_parts = [prepared.text_embed_stub.normalized_user]
        
        if prepared.text_embed_stub.normalized_external:
            prompt_parts.append("\n\nContext:")
            for chunk in prepared.text_embed_stub.normalized_external:
                # Remove delimiters for the prompt
                clean_chunk = chunk.replace("[EXTERNAL]", "").replace("[/EXTERNAL]", "")
                prompt_parts.append(f"- {clean_chunk}")
        
        full_prompt = "\n".join(prompt_parts)
        
        logger.info(
            f"[{prepared.metadata.request_id}] ===== LLM GENERATION STARTED ====="
        )
        logger.info(
            f"[{prepared.metadata.request_id}] Prompt construction:"
        )
        logger.info(
            f"[{prepared.metadata.request_id}]   User text: {len(prepared.text_embed_stub.normalized_user)} chars"
        )
        logger.info(
            f"[{prepared.metadata.request_id}]   External chunks: {len(prepared.text_embed_stub.normalized_external)}"
        )
        logger.info(
            f"[{prepared.metadata.request_id}]   Full prompt length: {len(full_prompt)} chars"
        )
        logger.info(
            f"[{prepared.metadata.request_id}]   Estimated tokens: {prepared.text_embed_stub.stats.token_estimate}"
        )
        logger.info(
            f"[{prepared.metadata.request_id}] Full prompt preview:"
        )
        logger.info(f"[{prepared.metadata.request_id}] {full_prompt[:200]}..." if len(full_prompt) > 200 else f"[{prepared.metadata.request_id}] {full_prompt}")
        
        # Generate response
        result = generate_response(
            prompt=full_prompt,
            max_new_tokens=request.max_new_tokens,
            temperature=request.temperature,
            top_p=request.top_p,
            do_sample=request.do_sample
        )
        
        # Add preparation metadata
        result["preparation_metadata"] = {
            "request_id": prepared.metadata.request_id,
            "prep_time_ms": prepared.metadata.prep_time_ms,
            "input_tokens_estimated": prepared.text_embed_stub.stats.token_estimate,
            "rag_chunks": len(prepared.text_embed_stub.normalized_external),
            "hmac_signatures": len(prepared.text_embed_stub.hmacs),
        }
        
        total_time = (time.time() - start_time) * 1000
        
        # DETAILED LOG: Show generation results
        logger.info(f"[{prepared.metadata.request_id}] ===== LLM GENERATION COMPLETE =====")
        logger.info(f"[{prepared.metadata.request_id}] Success: {result.get('success', False)}")
        logger.info(f"[{prepared.metadata.request_id}] Input tokens (actual): {result.get('input_tokens', 0)}")
        logger.info(f"[{prepared.metadata.request_id}] Output tokens: {result.get('output_tokens', 0)}")
        logger.info(f"[{prepared.metadata.request_id}] Generation time: {result.get('total_time_ms', 0):.2f}ms")
        logger.info(f"[{prepared.metadata.request_id}] Total time (prep + gen): {total_time:.2f}ms")
        if result.get('success'):
            generated = result.get('generated_text', '')
            logger.info(f"[{prepared.metadata.request_id}] Generated text preview: {generated[:150]}..." if len(generated) > 150 else f"[{prepared.metadata.request_id}] Generated text: {generated}")
            
            # Save assistant response to session if session_id exists
            if prepared.metadata.session_id:
                session_manager = get_session_manager()
                session_manager.add_message(
                    prepared.metadata.session_id,
                    "assistant",
                    generated
                )
                logger.info(f"[{prepared.metadata.session_id[:8]}] Saved assistant response to session")
        else:
            logger.error(f"[{prepared.metadata.request_id}] Generation error: {result.get('error', 'Unknown')}")
        
        logger.info(f"[{prepared.metadata.request_id}] ===== PIPELINE COMPLETE =====")
        
        return GenerateResponse(**result)
        
    except Exception as e:
        logger.error(f"Error generating response: {e}", exc_info=True)
        return GenerateResponse(
            success=False,
            generated_text="",
            input_tokens=0,
            output_tokens=0,
            total_time_ms=(time.time() - start_time) * 1000,
            error=str(e)
        )


@app.get(f"{settings.API_PREFIX}/model-status")
async def model_status():
    """
    Check the status of the LLM model.
    
    Returns information about whether the model is loaded and available.
    """
    status_info = check_model_availability()
    return {
        "model": "gemma-2b",
        **status_info,
        "endpoint": f"{settings.API_PREFIX}/generate"
    }


@app.get(f"{settings.API_PREFIX}/output-stats")
async def output_statistics():
    """
    Get statistics about saved outputs.
    
    Returns counts and locations of saved Layer 0 and media outputs.
    """
    output_saver = get_output_saver()
    stats = output_saver.get_output_stats()
    
    # Add recent files info
    recent_layer0 = output_saver.get_recent_outputs("layer0", limit=5)
    recent_media = output_saver.get_recent_outputs("media", limit=5)
    
    stats["recent_layer0_files"] = [f.name for f in recent_layer0]
    stats["recent_media_files"] = [f.name for f in recent_media]
    
    return stats


@app.post(f"{settings.API_PREFIX}/sessions/create")
async def create_session():
    """
    Create a new conversation session.
    
    Returns:
        Session ID for use in subsequent requests
    """
    session_manager = get_session_manager()
    session_id = session_manager.create_session()
    
    return {
        "session_id": session_id,
        "message": "Session created successfully",
        "usage": "Include this session_id in your /prepare-text requests to enable conversation memory"
    }


@app.get(f"{settings.API_PREFIX}/sessions/{{session_id}}")
async def get_session(session_id: str):
    """
    Get information about a conversation session.
    
    Args:
        session_id: Session identifier
    
    Returns:
        Session details including message history
    """
    session_manager = get_session_manager()
    session = session_manager.get_session(session_id)
    
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    
    return session.to_dict()


@app.delete(f"{settings.API_PREFIX}/sessions/{{session_id}}")
async def delete_session(session_id: str):
    """
    Delete a conversation session.
    
    Args:
        session_id: Session identifier
    
    Returns:
        Confirmation message
    """
    session_manager = get_session_manager()
    success = session_manager.delete_session(session_id)
    
    if not success:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    
    return {
        "message": f"Session {session_id} deleted successfully"
    }


@app.post(f"{settings.API_PREFIX}/sessions/{{session_id}}/clear")
async def clear_session(session_id: str):
    """
    Clear all messages in a conversation session.
    
    Args:
        session_id: Session identifier
    
    Returns:
        Confirmation message
    """
    session_manager = get_session_manager()
    success = session_manager.clear_session(session_id)
    
    if not success:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    
    return {
        "message": f"Session {session_id} cleared successfully",
        "session_id": session_id
    }


@app.get(f"{settings.API_PREFIX}/sessions")
async def list_sessions():
    """
    List all active conversation sessions.
    
    Returns:
        List of session details
    """
    session_manager = get_session_manager()
    return {
        "sessions": session_manager.list_sessions(),
        "stats": session_manager.get_stats()
    }


@app.post(
    f"{settings.API_PREFIX}/prepare-layer0",
    response_model=Layer0Output,
    status_code=status.HTTP_200_OK,
    summary="Prepare input for Layer 0 (Fast Heuristics)",
    description=(
        "Advanced endpoint for Layer 0 processing. "
        "Includes Unicode obfuscation detection, zero-width character removal, "
        "fast heuristic pattern matching, and special character masking. "
        "Returns structured output optimized for Layer 0 fast processing."
    )
)
async def prepare_layer0(
    user_prompt: str = Form(..., description="User's input text"),
    external_data: Optional[str] = Form(None, description="JSON array of external data strings"),
    file: Optional[UploadFile] = File(None, description="Optional file upload"),
    retrieve_from_vector_db: bool = Form(False, description="Retrieve from vector database")
):
    """
    Prepare input with advanced Layer 0 analysis.
    
    Includes:
    - Zero-width and invisible character detection
    - Unicode obfuscation analysis
    - Fast heuristic pattern matching (base64, system delimiters, etc.)
    - Special character masking
    - Raw text snapshot storage
    """
    import json
    import uuid
    from datetime import datetime
    
    start_time = time.time()
    request_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat() + 'Z'
    
    # Parse external data
    external_data_list = []
    if external_data:
        try:
            external_data_list = json.loads(external_data)
        except json.JSONDecodeError:
            external_data_list = [external_data]
    
    # Handle file upload
    file_text = ""
    if file and file.filename:
        from pathlib import Path
        filename = file.filename
        
        if not settings.is_allowed_extension(filename):
            raise HTTPException(
                status_code=400,
                detail=f"File type not allowed. Allowed: {', '.join(sorted(settings.ALLOWED_EXTENSIONS))}"
            )
        
        temp_file_path = str(settings.get_file_path(filename))
        with open(temp_file_path, "wb") as f:
            content = await file.read()
            f.write(content)
        
        try:
            file_chunks, file_info = extract_file_text(temp_file_path)
            if file_chunks:
                file_text = ' '.join([chunk.content for chunk in file_chunks])
        except Exception as e:
            logger.error(f"File extraction failed: {e}")
    
    # Normalize and combine texts
    from app.services.text_normalizer import normalize_text
    normalized_user, user_emojis, user_emoji_descs = normalize_text(user_prompt)
    
    normalized_external = []
    for ext_data in external_data_list:
        norm, _, _ = normalize_text(ext_data)
        normalized_external.append(norm)
    
    if file_text:
        norm_file, _, _ = normalize_text(file_text)
        normalized_external.append(norm_file)
    
    # RAG processing
    from app.services.rag_handler import process_rag_data
    external_chunks, hmacs, rag_enabled = process_rag_data(
        user_prompt=user_prompt,
        external_data=external_data_list,
        file_chunks=None,
        retrieve_from_db=retrieve_from_vector_db,
        conversation_text=None
    )
    
    # Token calculation
    from app.services.token_processor import estimate_tokens
    token_count = estimate_tokens(normalized_user + ' '.join(normalized_external))
    char_total = len(normalized_user) + sum(len(ext) for ext in normalized_external)
    
    # Prepare Layer 0 output
    layer0_output = prepare_layer0_output(
        request_id=request_id,
        timestamp=timestamp,
        user_text=normalized_user,
        external_texts=normalized_external,
        hmac_verified=len(hmacs) > 0,
        emoji_count=len(user_emojis),
        emoji_descriptions=user_emoji_descs,
        token_count=token_count,
        char_total=char_total,
        attachment_texts=[],  # Would come from images
        prep_time_ms=(time.time() - start_time) * 1000,
        store_raw_snapshot=True
    )
    
    logger.info(
        f"[{request_id[:8]}] Layer 0 output prepared: "
        f"suspicious_score={layer0_output.suspicious_score:.2f}, "
        f"unicode_obfuscation={layer0_output.unicode_analysis.unicode_obfuscation_flag}"
    )
    
    return layer0_output


@app.post(
    f"{settings.API_PREFIX}/process-images",
    response_model=ImageProcessingOutput,
    status_code=status.HTTP_200_OK,
    summary="Process images with advanced analysis",
    description=(
        "Advanced image processing endpoint. "
        "Includes pHash calculation, EXIF extraction, OCR, steganography detection, "
        "and PDF image extraction. Returns comprehensive image analysis results."
    )
)
async def process_images_advanced(
    user_prompt: str = Form(..., description="User's input text"),
    images: Optional[List[UploadFile]] = File(None, description="Image files to process"),
    pdf_file: Optional[UploadFile] = File(None, description="PDF file (images will be extracted)"),
    run_ocr: bool = Form(False, description="Run OCR on images (resource intensive)"),
    ocr_confidence: float = Form(50.0, description="OCR confidence threshold")
):
    """
    Process images with comprehensive advanced analysis.
    
    Includes:
    - Perceptual hash (pHash) for near-duplicate detection
    - EXIF metadata extraction (including suspicious pattern detection)
    - OCR text extraction (optional)
    - Steganography detection (LSB analysis, entropy)
    - PDF embedded image extraction and processing
    """
    import uuid
    from datetime import datetime
    
    start_time = time.time()
    request_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat() + 'Z'
    
    image_paths = []
    pdf_path = None
    
    # Save uploaded images
    if images:
        for img_file in images:
            if img_file.filename:
                filename = img_file.filename
                
                if not settings.is_image_file(filename):
                    continue
                
                temp_path = str(settings.get_file_path(filename))
                with open(temp_path, "wb") as f:
                    content = await img_file.read()
                    f.write(content)
                
                image_paths.append(temp_path)
    
    # Save PDF if provided
    if pdf_file and pdf_file.filename:
        filename = pdf_file.filename
        temp_path = str(settings.get_file_path(filename))
        
        with open(temp_path, "wb") as f:
            content = await pdf_file.read()
            f.write(content)
        
        pdf_path = temp_path
    
    # Extract emojis from prompt
    from app.services.text_normalizer import extract_emojis, get_emoji_descriptions
    emojis = extract_emojis(user_prompt)
    emoji_descs = get_emoji_descriptions(emojis)
    
    emoji_summary = EmojiSummary(
        count=len(emojis),
        types=emojis,
        descriptions=emoji_descs
    )
    
    # Process images
    image_output = prepare_image_processing_output(
        request_id=request_id,
        timestamp=timestamp,
        image_paths=image_paths,
        pdf_path=pdf_path,
        emoji_summary=emoji_summary,
        run_ocr=run_ocr,
        ocr_confidence=ocr_confidence
    )
    
    logger.info(
        f"[{request_id[:8]}] Image processing output: "
        f"total={image_output.total_images}, "
        f"suspicious={image_output.suspicious_images_count}, "
        f"stego={image_output.steganography_detected}"
    )
    
    return image_output


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=True,
        log_level=settings.LOG_LEVEL.lower()
    )

