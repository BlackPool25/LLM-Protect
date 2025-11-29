#!/usr/bin/env python3
"""
Layer0 Security Microservice - FastAPI-based Input Validation Layer

Runs on port 3001 and processes Input-Prep JSON for security analysis.
Blocks malicious prompts, detects code, and forwards clean payloads to Layer 1.

Quick Test Commands:
  # Health check
  curl http://localhost:3001/test

  # Send sample input
  curl -X POST http://localhost:3001/layer0 -H "Content-Type: application/json" -d @input_example.json

  # Reload rules (requires ADMIN_TOKEN env var)
  curl -X POST http://localhost:3001/admin/reload-rules -H "Authorization: Bearer your_token"

Run with:
  cd layer0
  pip install -r requirements.txt && uvicorn server:app --port 3001
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import sqlite3
import unicodedata
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Optional

import httpx
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

# ============================================================================
# Configuration
# ============================================================================

# Get the directory where this script is located
BASE_DIR = Path(__file__).parent.resolve()

LAYER1_URL = os.getenv("LAYER1_URL", "http://localhost:3002/layer1")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "changeme")
STORE_RAW = os.getenv("STORE_RAW", "false").lower() == "true"
HMAC_SECRET = os.getenv("HMAC_SECRET", "layer0-secret-key").encode()
DB_PATH = Path(os.getenv("DB_PATH", str(BASE_DIR / "data" / "layer0_logs.db")))
RULES_DIR = Path(os.getenv("RULES_DIR", str(BASE_DIR / "rules")))

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("layer0")

# ============================================================================
# Precompiled Regex Patterns
# ============================================================================

# Sanitization patterns - markers to remove
SANITIZE_PATTERNS: list[re.Pattern] = [
    re.compile(r"\[EXTERNAL\]", re.IGNORECASE),
    re.compile(r"\[/EXTERNAL\]", re.IGNORECASE),
    re.compile(r"\[CONVERSATION\]", re.IGNORECASE),
    re.compile(r"\[/CONVERSATION\]", re.IGNORECASE),
    re.compile(r"\[Source:\s*[^\]]+\]", re.IGNORECASE),  # [Source: path, Chunk: n]
    re.compile(r"https?://[^\s\]]+"),  # URLs
]

# BLOCK patterns - immediate rejection
BLOCK_PATTERNS: dict[str, re.Pattern] = {
    "ignore_previous": re.compile(r"(?i)ignore\s+previous\s+instructions"),
    "disregard_prompts": re.compile(r"(?i)disregard\s+all\s+prior\s+prompts?"),
    "no_longer_ai": re.compile(r"(?i)you\s+are\s+no\s+longer\s+an\s+ai"),
    "jailbreak_keyword": re.compile(r"(?i)\bjailbreak(ed|ing)?\b"),
    "bypass_safety": re.compile(r"(?i)bypass\s+(the\s+)?(safety|security|content|filter|restriction|rule)s?"),
    "override_system": re.compile(r"(?i)override\s+(the\s+)?(system|safety|security)"),
    "act_as_system": re.compile(r"(?i)act\s+as\s+.+?system"),
}

# FLAG patterns - collect signatures without blocking
FLAG_PATTERNS: dict[str, re.Pattern] = {
    "triple_hash": re.compile(r"#{3,}"),
    "end_tag": re.compile(r"<\s*END\s*>", re.IGNORECASE),
    "fenced_code_block": re.compile(r"```[\w]*\n[\s\S]*?\n```|```{3,}[\s\S]*?```"),
    "double_fence": re.compile(r"```{2,}|===={2,}"),
    "zero_width_chars": re.compile(r"[\u200B\u200C\u200D\u2060]"),
    "format_controls": re.compile(r"[\u00AD\u061C\u180E\u200E\u200F\u202A-\u202E\u2066-\u2069\uFEFF]"),
}

# Code detection patterns by language
CODE_PATTERNS: dict[str, re.Pattern] = {
    "python": re.compile(r"\b(def\s+\w+\s*\(|class\s+\w+|import\s+\w+|from\s+\w+\s+import|print\s*\(|for\s+\w+\s+in\b)"),
    "c_cpp": re.compile(r"(#include\s*<[^>]+>|int\s+main\s*\(|printf\s*\(|void\s+\w+\s*\(|#define\s+\w+)"),
    "java": re.compile(r"\b(public\s+class\s+\w+|System\.out\.println|static\s+void\s+main|private\s+\w+\s+\w+)"),
    "javascript": re.compile(r"\b(console\.log\s*\(|function\s+\w*\s*\(|=>\s*\{?|const\s+\w+\s*=|let\s+\w+\s*=)"),
    "bash": re.compile(r"(#!/bin/(ba)?sh|\bsudo\s+\w|\bchmod\s+\d+|\becho\s+[\"']|\bexport\s+\w+=)"),
    "go": re.compile(r"\b(package\s+main|func\s+main\s*\(|import\s+\(|func\s+\w+\s*\()"),
}

# Heuristic patterns
HEURISTIC_PATTERNS: dict[str, re.Pattern] = {
    "semicolon_heavy": re.compile(r";[\s\n]"),
    "brace_heavy": re.compile(r"\{[^}]*\}"),
}

# ============================================================================
# Pydantic Models
# ============================================================================

class Layer0Response(BaseModel):
    """Response from Layer0 processing."""
    blocked: bool = False
    reason: Optional[str] = None
    request_id: str
    forwarded: bool = False
    layer1_response: Optional[dict[str, Any]] = None
    processing_summary: Optional[dict[str, Any]] = None


class Layer1Payload(BaseModel):
    """Payload to forward to Layer 1."""
    clean_user: str
    clean_external: str
    clean_text: str
    is_code: bool
    detected_language: Optional[str] = None
    confidence_code: float = 0.0
    code_snippets: list[str] = Field(default_factory=list)
    jailbreak_flag: bool = False
    severity: int = 0
    threat_signatures: list[str] = Field(default_factory=list)
    emoji_descriptions: list[str] = Field(default_factory=list)
    heuristic_flags: dict[str, Any] = Field(default_factory=dict)
    request_id: str


class CodeDetectionResult(BaseModel):
    """Result from code detection."""
    is_code: bool
    detected_language: Optional[str] = None
    confidence: float = 0.0
    code_snippets: list[str] = Field(default_factory=list)


# ============================================================================
# Database Setup
# ============================================================================

def init_db() -> None:
    """Initialize SQLite database for logging."""
    # Ensure data directory exists
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            blocked INTEGER NOT NULL DEFAULT 0,
            matched_rule_ids TEXT,
            detected_language TEXT,
            severity INTEGER DEFAULT 0,
            forwarded INTEGER NOT NULL DEFAULT 0,
            raw_text_hmac TEXT,
            raw_text TEXT
        )
    """)
    conn.commit()
    conn.close()
    logger.info(f"Database initialized at {DB_PATH}")


def log_event(
    request_id: str,
    blocked: bool,
    matched_rule_ids: list[str],
    detected_language: Optional[str],
    severity: int,
    forwarded: bool,
    raw_text: Optional[str] = None
) -> None:
    """Log processing event to database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        raw_text_hmac = None
        stored_raw_text = None
        
        if raw_text:
            raw_text_hmac = hmac.new(HMAC_SECRET, raw_text.encode(), hashlib.sha256).hexdigest()
            if STORE_RAW:
                stored_raw_text = raw_text
        
        cursor.execute("""
            INSERT INTO events (request_id, timestamp, blocked, matched_rule_ids, 
                              detected_language, severity, forwarded, raw_text_hmac, raw_text)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            request_id,
            datetime.now(timezone.utc).isoformat(),
            int(blocked),
            json.dumps(matched_rule_ids),
            detected_language,
            severity,
            int(forwarded),
            raw_text_hmac,
            stored_raw_text
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to log event: {e}")


# ============================================================================
# Dynamic Rules Loading
# ============================================================================

class RulesManager:
    """Manages dynamic rule loading from JSONL files."""
    
    def __init__(self) -> None:
        self.block_rules: dict[str, re.Pattern] = {}
        self.flag_rules: dict[str, re.Pattern] = {}
        self.loaded_at: Optional[datetime] = None
    
    def load_rules(self) -> int:
        """Load rules from JSONL files in rules directory."""
        self.block_rules = dict(BLOCK_PATTERNS)  # Start with built-in
        self.flag_rules = dict(FLAG_PATTERNS)    # Start with built-in
        
        loaded_count = 0
        
        if not RULES_DIR.exists():
            RULES_DIR.mkdir(parents=True, exist_ok=True)
            logger.warning(f"Created rules directory: {RULES_DIR}")
            return loaded_count
        
        for rule_file in RULES_DIR.glob("*.jsonl"):
            try:
                with open(rule_file, "r", encoding="utf-8") as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        try:
                            rule = json.loads(line)
                            rule_id = rule.get("id", f"{rule_file.stem}_{line_num}")
                            pattern = rule.get("pattern", "")
                            rule_type = rule.get("type", "flag")
                            flags = re.IGNORECASE if rule.get("ignore_case", True) else 0
                            
                            compiled = re.compile(pattern, flags)
                            
                            if rule_type == "block":
                                self.block_rules[rule_id] = compiled
                            else:
                                self.flag_rules[rule_id] = compiled
                            
                            loaded_count += 1
                        except (json.JSONDecodeError, re.error) as e:
                            logger.warning(f"Invalid rule in {rule_file}:{line_num}: {e}")
            except Exception as e:
                logger.error(f"Failed to load {rule_file}: {e}")
        
        self.loaded_at = datetime.now(timezone.utc)
        logger.info(f"Loaded {loaded_count} custom rules from {RULES_DIR}")
        return loaded_count


# Global rules manager
rules_manager = RulesManager()


# ============================================================================
# Text Processing Functions
# ============================================================================

def sanitize_text(text: str) -> str:
    """
    Remove markers, URLs, and normalize text.
    
    Strips: [EXTERNAL], [/EXTERNAL], [CONVERSATION], [/CONVERSATION],
            [Source: ...], URLs, and normalizes unicode.
    """
    if not text:
        return ""
    
    # Apply all sanitization patterns
    result = text
    for pattern in SANITIZE_PATTERNS:
        result = pattern.sub("", result)
    
    # Unicode NFKC normalization
    result = unicodedata.normalize("NFKC", result)
    
    # Remove zero-width characters
    result = re.sub(r"[\u200B\u200C\u200D\u2060\uFEFF]", "", result)
    
    # Normalize whitespace
    result = re.sub(r"\s+", " ", result).strip()
    
    return result


def extract_text_channels(payload: dict[str, Any]) -> tuple[str, str, str]:
    """
    Extract text channels from Input-Prep JSON.
    
    Returns:
        tuple: (clean_user, clean_external, fallback_merged)
    """
    prepared_input = payload.get("prepared_input", {})
    text_embed_stub = prepared_input.get("text_embed_stub", {})
    layer0_data = prepared_input.get("layer0", {})
    
    # Extract normalized_user (string)
    normalized_user = text_embed_stub.get("normalized_user", "")
    clean_user = sanitize_text(normalized_user) if normalized_user else ""
    
    # Extract normalized_external (list → joined string)
    normalized_external = text_embed_stub.get("normalized_external", [])
    if isinstance(normalized_external, list):
        external_joined = " ".join(normalized_external)
    else:
        external_joined = str(normalized_external)
    clean_external = sanitize_text(external_joined)
    
    # Fallback: layer0.normalized_text
    fallback_text = layer0_data.get("normalized_text", "")
    fallback_merged = sanitize_text(fallback_text) if fallback_text else ""
    
    # Use fallback only if both primary channels are empty
    if not clean_user and not clean_external and fallback_merged:
        clean_user = fallback_merged
    
    return clean_user, clean_external, fallback_merged


def extract_metadata(payload: dict[str, Any]) -> dict[str, Any]:
    """Extract metadata from Input-Prep JSON."""
    prepared_input = payload.get("prepared_input", {})
    text_embed_stub = prepared_input.get("text_embed_stub", {})
    layer0_data = prepared_input.get("layer0", {})
    metadata = prepared_input.get("metadata", {})
    
    return {
        "request_id": metadata.get("request_id", "unknown"),
        "emoji_descriptions": text_embed_stub.get("emoji_descriptions", []),
        "heuristic_flags": layer0_data.get("heuristic_flags", {}),
        "session_id": metadata.get("session_id"),
        "timestamp": metadata.get("timestamp"),
    }


# ============================================================================
# Pattern Matching Functions
# ============================================================================

def check_block_patterns(text: str) -> Optional[tuple[str, str]]:
    """
    Check text against BLOCK patterns.
    
    Returns:
        Optional tuple of (rule_id, matched_text) if blocked, else None.
    """
    all_block_rules = {**BLOCK_PATTERNS, **rules_manager.block_rules}
    
    for rule_id, pattern in all_block_rules.items():
        match = pattern.search(text)
        if match:
            return (rule_id, match.group(0))
    
    return None


def check_flag_patterns(text: str) -> list[str]:
    """
    Check text against FLAG patterns.
    
    Returns:
        List of matched rule IDs.
    """
    all_flag_rules = {**FLAG_PATTERNS, **rules_manager.flag_rules}
    matched = []
    
    for rule_id, pattern in all_flag_rules.items():
        if pattern.search(text):
            matched.append(f"flag:{rule_id}")
    
    return matched


def detect_code(text: str) -> CodeDetectionResult:
    """
    Detect code in text using regex patterns and heuristics.
    
    Analyzes fenced code blocks, inline code, and language-specific patterns.
    
    Returns:
        CodeDetectionResult with is_code, detected_language, confidence, and snippets.
    """
    if not text:
        return CodeDetectionResult(is_code=False)
    
    code_snippets: list[str] = []
    language_scores: dict[str, float] = {}
    fenced_boost = 0.0
    heur_score = 0.0
    
    # Extract fenced code blocks
    fenced_pattern = re.compile(r"```(\w*)\n?([\s\S]*?)```")
    for match in fenced_pattern.finditer(text):
        lang_hint = match.group(1).lower()
        code_content = match.group(2).strip()
        if code_content:
            code_snippets.append(code_content)
            fenced_boost = 0.4
            if lang_hint:
                language_scores[lang_hint] = language_scores.get(lang_hint, 0) + 0.3
    
    # Extract inline code
    inline_pattern = re.compile(r"`([^`]+)`")
    for match in inline_pattern.finditer(text):
        snippet = match.group(1).strip()
        if len(snippet) > 10:  # Only meaningful inline code
            code_snippets.append(snippet)
    
    # Score languages by pattern matches
    for lang, pattern in CODE_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            match_score = len(set(matches)) * 0.2
            language_scores[lang] = language_scores.get(lang, 0) + match_score
    
    # Apply heuristics
    semicolon_matches = HEURISTIC_PATTERNS["semicolon_heavy"].findall(text)
    brace_matches = HEURISTIC_PATTERNS["brace_heavy"].findall(text)
    
    if len(semicolon_matches) >= 3:
        heur_score += 0.1
    if len(brace_matches) >= 2:
        heur_score += 0.1
    
    # Determine best language
    detected_language = None
    max_score = 0.0
    for lang, score in language_scores.items():
        if score > max_score:
            max_score = score
            detected_language = lang
    
    # Calculate final confidence
    confidence = min(1.0, fenced_boost + max_score + heur_score)
    
    # Determine if code is present
    is_code = confidence >= 0.35 or len(code_snippets) > 0
    
    return CodeDetectionResult(
        is_code=is_code,
        detected_language=detected_language if is_code else None,
        confidence=round(confidence, 3),
        code_snippets=code_snippets[:10]  # Limit to 10 snippets
    )


def calculate_severity(
    threat_signatures: list[str],
    code_result: CodeDetectionResult,
    heuristic_flags: dict[str, Any]
) -> int:
    """
    Calculate severity level (0-2) based on findings.
    
    0: Clean / minimal concerns
    1: Low-medium risk (code detected, some flags)
    2: High risk (multiple suspicious patterns)
    """
    severity = 0
    
    # Code detection adds severity
    if code_result.is_code:
        severity = max(severity, 1)
    
    # Threat signatures
    sig_count = len(threat_signatures)
    if sig_count >= 3:
        severity = max(severity, 2)
    elif sig_count >= 1:
        severity = max(severity, 1)
    
    # Heuristic flags from input
    suspicious_score = heuristic_flags.get("suspicious_score", 0)
    if suspicious_score >= 0.5:
        severity = max(severity, 2)
    elif suspicious_score >= 0.3:
        severity = max(severity, 1)
    
    return severity


# ============================================================================
# FastAPI Application
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan context manager for startup/shutdown events."""
    # Startup
    init_db()
    rules_manager.load_rules()
    logger.info("Layer0 service started on port 3001")
    yield
    # Shutdown (if needed)
    logger.info("Layer0 service stopping")


app = FastAPI(
    title="Layer0 Security Service",
    description="Input validation and security screening microservice",
    version="1.0.0",
    lifespan=lifespan
)

security = HTTPBearer(auto_error=False)


# ============================================================================
# Endpoints
# ============================================================================

@app.get("/test")
async def health_check() -> dict[str, Any]:
    """Health check endpoint."""
    return {
        "status": "ok",
        "service": "layer0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rules_loaded": len(rules_manager.block_rules) + len(rules_manager.flag_rules),
        "rules_loaded_at": rules_manager.loaded_at.isoformat() if rules_manager.loaded_at else None
    }


@app.post("/layer0")
async def process_layer0(request: Request) -> dict[str, Any]:
    """
    Main Layer0 processing endpoint.
    
    Accepts Input-Prep JSON, validates, sanitizes, and forwards to Layer 1.
    """
    try:
        payload = await request.json()
    except Exception as e:
        logger.error(f"Invalid JSON payload: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    
    # Extract metadata
    meta = extract_metadata(payload)
    request_id = meta["request_id"]
    
    logger.info(f"Processing request: {request_id}")
    
    # Extract and sanitize text channels
    clean_user, clean_external, fallback_merged = extract_text_channels(payload)
    clean_text = f"{clean_user} {clean_external}".strip()
    
    # Store combined raw text for logging
    raw_text = clean_text if STORE_RAW else None
    
    # ========== BLOCK CHECK ==========
    # Check user channel
    block_result = check_block_patterns(clean_user)
    if not block_result:
        # Check external channel
        block_result = check_block_patterns(clean_external)
    
    if block_result:
        rule_id, matched_text = block_result
        logger.warning(f"BLOCKED request {request_id}: rule={rule_id}")
        
        log_event(
            request_id=request_id,
            blocked=True,
            matched_rule_ids=[f"block:{rule_id}"],
            detected_language=None,
            severity=2,
            forwarded=False,
            raw_text=raw_text
        )
        
        return {
            "blocked": True,
            "reason": f"Matched block pattern: {rule_id}",
            "request_id": request_id
        }
    
    # ========== FLAG CHECK ==========
    threat_signatures = []
    threat_signatures.extend(check_flag_patterns(clean_user))
    threat_signatures.extend(check_flag_patterns(clean_external))
    threat_signatures = list(set(threat_signatures))  # Deduplicate
    
    # ========== CODE DETECTION ==========
    code_result_user = detect_code(clean_user)
    code_result_external = detect_code(clean_external)
    
    # Combine code detection results
    is_code = code_result_user.is_code or code_result_external.is_code
    
    detected_language = code_result_user.detected_language or code_result_external.detected_language
    confidence_code = max(code_result_user.confidence, code_result_external.confidence)
    code_snippets = code_result_user.code_snippets + code_result_external.code_snippets
    
    # ========== SEVERITY CALCULATION ==========
    severity = calculate_severity(
        threat_signatures,
        CodeDetectionResult(is_code=is_code, detected_language=detected_language, confidence=confidence_code),
        meta["heuristic_flags"]
    )
    
    # ========== BUILD LAYER1 PAYLOAD ==========
    layer1_payload = Layer1Payload(
        clean_user=clean_user,
        clean_external=clean_external,
        clean_text=clean_text,
        is_code=is_code,
        detected_language=detected_language,
        confidence_code=confidence_code,
        code_snippets=code_snippets[:10],
        jailbreak_flag=False,
        severity=severity,
        threat_signatures=threat_signatures,
        emoji_descriptions=meta["emoji_descriptions"],
        heuristic_flags=meta["heuristic_flags"],
        request_id=request_id
    )
    
    # ========== FORWARD TO LAYER 1 ==========
    forwarded = False
    layer1_response = None
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                LAYER1_URL,
                json=layer1_payload.model_dump(),
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                layer1_response = response.json()
                forwarded = True
                logger.info(f"Forwarded request {request_id} to Layer 1")
            else:
                logger.warning(f"Layer 1 returned {response.status_code} for {request_id}")
                
    except httpx.ConnectError:
        logger.warning(f"Layer 1 unreachable for request {request_id}")
    except Exception as e:
        logger.error(f"Error forwarding to Layer 1: {e}")
    
    # ========== LOG EVENT ==========
    log_event(
        request_id=request_id,
        blocked=False,
        matched_rule_ids=threat_signatures,
        detected_language=detected_language,
        severity=severity,
        forwarded=forwarded,
        raw_text=raw_text
    )
    
    # ========== BUILD RESPONSE ==========
    processing_summary = {
        "is_code": is_code,
        "detected_language": detected_language,
        "confidence_code": confidence_code,
        "severity": severity,
        "threat_signatures_count": len(threat_signatures),
        "forwarded": forwarded
    }
    
    result = {
        "blocked": False,
        "request_id": request_id,
        "forwarded": forwarded,
        "processing_summary": processing_summary
    }
    
    if layer1_response:
        result["layer1_response"] = layer1_response
    elif not forwarded:
        result["warning"] = "Layer 1 unreachable - request logged but not forwarded"
    
    return result


@app.post("/admin/reload-rules")
async def reload_rules(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> dict[str, Any]:
    """
    Reload rules from rules directory (admin only).
    
    Requires Authorization: Bearer <ADMIN_TOKEN>
    """
    if not credentials or credentials.credentials != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid or missing admin token")
    
    count = rules_manager.load_rules()
    
    return {
        "status": "ok",
        "rules_reloaded": count,
        "loaded_at": rules_manager.loaded_at.isoformat() if rules_manager.loaded_at else None,
        "block_rules": len(rules_manager.block_rules),
        "flag_rules": len(rules_manager.flag_rules)
    }


# ============================================================================
# Error Handlers
# ============================================================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return {
        "error": "Internal server error",
        "detail": str(exc) if os.getenv("DEBUG") else "An error occurred",
        "status_code": 500
    }


# ============================================================================
# Main Entry Point
# ============================================================================

def test_local(input_path: str) -> None:
    """
    Test the Layer0 processing locally without starting the server.
    
    Usage:
        python server.py --test samples/input_example.json
        python server.py --test path/to/your/input.json
    """
    import asyncio
    from pprint import pprint
    
    # Initialize
    init_db()
    rules_manager.load_rules()
    
    # Load input file
    input_file = Path(input_path)
    if not input_file.exists():
        print(f"❌ File not found: {input_path}")
        return
    
    with open(input_file, "r", encoding="utf-8-sig") as f:
        payload = json.load(f)
    
    print(f"\n{'='*60}")
    print(f"🔍 Layer0 Local Test")
    print(f"{'='*60}")
    print(f"📄 Input: {input_path}")
    
    # Extract metadata
    meta = extract_metadata(payload)
    request_id = meta["request_id"]
    print(f"🆔 Request ID: {request_id}")
    
    # Extract and sanitize text channels
    clean_user, clean_external, fallback_merged = extract_text_channels(payload)
    clean_text = f"{clean_user} {clean_external}".strip()
    
    print(f"\n📝 Clean User ({len(clean_user)} chars):")
    print(f"   {clean_user[:200]}{'...' if len(clean_user) > 200 else ''}")
    
    print(f"\n📝 Clean External ({len(clean_external)} chars):")
    print(f"   {clean_external[:200]}{'...' if len(clean_external) > 200 else ''}")
    
    # Check BLOCK patterns
    print(f"\n{'='*60}")
    print("🛡️  Security Analysis")
    print(f"{'='*60}")
    
    block_result = check_block_patterns(clean_user)
    if not block_result:
        block_result = check_block_patterns(clean_external)
    
    if block_result:
        rule_id, matched_text = block_result
        print(f"\n🚫 BLOCKED!")
        print(f"   Rule: {rule_id}")
        print(f"   Match: {matched_text}")
        return
    
    print("✅ No block patterns matched")
    
    # Check FLAG patterns
    threat_signatures = []
    threat_signatures.extend(check_flag_patterns(clean_user))
    threat_signatures.extend(check_flag_patterns(clean_external))
    threat_signatures = list(set(threat_signatures))
    
    if threat_signatures:
        print(f"\n⚠️  Flag signatures detected ({len(threat_signatures)}):")
        for sig in threat_signatures:
            print(f"   - {sig}")
    else:
        print("✅ No flag patterns matched")
    
    # Code detection
    print(f"\n{'='*60}")
    print("💻 Code Detection")
    print(f"{'='*60}")
    
    code_result_user = detect_code(clean_user)
    code_result_external = detect_code(clean_external)
    
    is_code = code_result_user.is_code or code_result_external.is_code
    detected_language = code_result_user.detected_language or code_result_external.detected_language
    confidence_code = max(code_result_user.confidence, code_result_external.confidence)
    code_snippets = code_result_user.code_snippets + code_result_external.code_snippets
    
    print(f"   Is Code: {is_code}")
    print(f"   Language: {detected_language or 'N/A'}")
    print(f"   Confidence: {confidence_code:.2f}")
    print(f"   Snippets Found: {len(code_snippets)}")
    
    if code_snippets:
        print(f"\n   First snippet preview:")
        snippet = code_snippets[0][:100]
        print(f"   ```\n   {snippet}{'...' if len(code_snippets[0]) > 100 else ''}\n   ```")
    
    # Severity
    severity = calculate_severity(
        threat_signatures,
        CodeDetectionResult(is_code=is_code, detected_language=detected_language, confidence=confidence_code),
        meta["heuristic_flags"]
    )
    
    print(f"\n{'='*60}")
    print("📊 Summary")
    print(f"{'='*60}")
    print(f"   Severity: {severity} {'(Clean)' if severity == 0 else '(Low-Medium)' if severity == 1 else '(High)'}")
    print(f"   Threat Signatures: {len(threat_signatures)}")
    print(f"   Would Forward to Layer 1: Yes")
    
    # Show Layer1 payload
    layer1_payload = {
        "clean_user": clean_user[:100] + "..." if len(clean_user) > 100 else clean_user,
        "clean_external": clean_external[:100] + "..." if len(clean_external) > 100 else clean_external,
        "is_code": is_code,
        "detected_language": detected_language,
        "confidence_code": confidence_code,
        "severity": severity,
        "threat_signatures": threat_signatures,
        "request_id": request_id
    }
    
    print(f"\n📤 Layer1 Payload Preview:")
    pprint(layer1_payload, width=80, indent=3)
    print(f"\n{'='*60}")
    print("✅ Test complete!")
    print(f"{'='*60}\n")


def test_text(text: str):
    """Test Layer0 with a direct text input."""
    print(f"\n{'='*60}")
    print(f"🔍 Layer0 Local Test")
    print(f"{'='*60}")
    print(f"📝 Input Text ({len(text)} chars):")
    print(f"   {text[:200]}{'...' if len(text) > 200 else ''}")
    
    # Sanitize
    clean_text = sanitize_text(text)
    
    # Check BLOCK patterns
    print(f"\n{'='*60}")
    print("🛡️  Security Analysis")
    print(f"{'='*60}")
    
    blocked, block_rule, block_match = check_block_patterns(clean_text)
    if blocked:
        print(f"\n🚫 BLOCKED!")
        print(f"   Rule: {block_rule}")
        print(f"   Match: {block_match}")
        return
    
    # Check FLAG patterns
    signatures = check_flag_patterns(clean_text)
    if signatures:
        print(f"\n⚠️  FLAGGED!")
        print(f"   Signatures: {len(signatures)}")
        for sig in signatures:
            print(f"     - {sig['rule']}: {sig['match'][:50]}...")
    else:
        print("✅ No block patterns matched")
        print("✅ No flag patterns matched")
    
    # Code detection
    print(f"\n{'='*60}")
    print("💻 Code Detection")
    print(f"{'='*60}")
    
    is_code, language, confidence, snippets = detect_code(clean_text)
    print(f"   Is Code: {is_code}")
    print(f"   Language: {language or 'N/A'}")
    print(f"   Confidence: {confidence:.2f}")
    print(f"   Snippets Found: {len(snippets)}")
    
    # Severity
    severity = calculate_severity(signatures, is_code, confidence)
    
    print(f"\n{'='*60}")
    print("📊 Summary")
    print(f"{'='*60}")
    print(f"   Severity: {severity}")
    print(f"   Threat Signatures: {len(signatures)}")
    verdict = "FLAG" if signatures else "PASS"
    print(f"   Verdict: {verdict}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Layer0 Security Service")
    parser.add_argument("--test", type=str, help="Test locally with a JSON file (no server)")
    parser.add_argument("--text", type=str, help="Test with direct text input")
    parser.add_argument("--port", type=int, default=3001, help="Port to run server on")
    
    args = parser.parse_args()
    
    if args.text:
        test_text(args.text)
    elif args.test:
        test_local(args.test)
    else:
        import uvicorn
        uvicorn.run(app, host="0.0.0.0", port=args.port)
