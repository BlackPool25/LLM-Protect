Input-Prep Flowchart & Processing Plan

Local reference plan file: /mnt/data/FINAL_MODIFIED_PLAN.md

TL;DR

Yes: process images, PDFs, office docs and other files.

Images inside PDFs: extract all embedded images (and embedded metadata), then run the same image-processing pipeline (pHash, EXIF, caption, OCR, stego checks) on each extracted image. Treat OCR text & EXIF descriptions as additional text channels.

The rest of this document contains a step-by-step flowchart of the input-prep pipeline, what each component sees, the exact fields passed to Layer 0 (regex/heuristics) and image processor, and realistic time estimates for prototype vs production.

1) High-level flowchart (linear view)
User Input (text, files, attachments)
        ↓
[1] Gate & Ingest (FastAPI)
        ↓
[2] Provenance + HMAC checks
        ↓
[3] Canonicalization & Normalization
        ↓
[4] Fast Heuristics (pre-L0 quick checks)
        ↓
[5] Attachment Stubbing → Attachment Processing Queue
        ↓                                ↓
[6] Image/PDF/Doc Processor  ←------ Extracted images + Metadata
        ↓
[7] Create normalized payloads (channels, embeddings, tokens, flags)
        ↓
[8] Send minimal payload to Layer 0 (regex/heuristics)
        ↓
[9] Store rich metadata & pointers for Layer 1/2
2) Component-by-component: what each component sees and produces
[1] Gate & Ingest (FastAPI endpoint)

Sees: raw HTTP body, file bytes, headers, client metadata. Produces: request_id, uploader_id, size checks, file type whitelist flag, pointer(s) to stored blobs (local FS / object store). Outputs: minimal JSON for pipeline and stored raw blobs to disk/S3.

[2] Provenance + HMAC checks

Sees: channels (user/external), connector metadata. Produces: hmac_ok flags and source_trust_score used to decide whether external channel text is treated as untrusted.

[3] Canonicalization & Normalization

Sees: raw text snapshots, filenames, extracted PDF text. Actions:

Unicode normalization (NFKC) + diff

Remove/flag zero-width characters

Normalize whitespace, unify line endings

Keep raw snapshot in secure store Produces: normalized_text, raw_text_snapshot, unicode_diff and boolean unicode_obfuscation_flag.

[4] Fast Heuristics (pre-L0 quick checks)

Sees: normalized_text (first N bytes), filenames, and basic attachment metadata. Actions: run ultra-fast checks (regex for </system>, base64 long sequences, many repeated characters, long single-line payloads, suspicious control chars). Produces: heuristic_flags and an early block decision if obvious.

[5] Attachment Stubbing

Sees: uploaded files (images, PDFs, docs), file sizes. Actions: create attachment_stub entries with file hashes and thumbnails (or placeholders), spawn async jobs into image/pdf processing queue. Produces: attachments_meta[] with file_hash, mime_type, thumbnail_ptr.

[6] Image / PDF / Doc Processor (detailed)

This is the meat of the file-processing work. It MUST handle both raw images and images embedded inside PDFs/docs.

If input is a PDF or Office doc:

Extract page-level text (use pdfplumber or PyMuPDF / fitz).

Extract embedded images per page (save them as individual image blobs).

Extract embedded attachments (some PDFs contain files in object streams) and their metadata.

Extract XMP/metadata and any embedded XML/metadata strings.

For each image (raw upload or extracted):

Compute sha256 and pHash (perceptual hash).

Extract EXIF/XMP metadata and save exif_description and author tags.

Create a thumbnail (224×224 or 256×256), and a small compressed preview.

Run a light vision-caption model (tiny CLIP-based or lightweight mobilenet->text) to produce caption.

Optionally run OCR (Tesseract or cloud alternative) if heuristics indicate text present.

Compute vision_embedding (small CLIP or open CLIP) for similarity checks.

Run steganography heuristics: entropy profile, LSB analysis, and a simple payload extractor for common LSB formats. Produce stego_score and any extracted payload.

Outputs per-attachment: attachment_id, pHash, file_entropy, exif_meta, caption, ocr_text, vision_embedding_ptr, stego_score, extracted_payload.

[7] Compose normalized payloads

Sees: results from steps 3–6 and the original instruction field. Produces: final canonical structures (persisted JSON and pointers):

channels: user_text, external_texts[], exif_texts[], ocr_texts[] (each with hmac_ok and source_trust_score).

normalized_text (final truncated form to pass to L0), token_preview, embedding_fingerprint.

attachments_meta (detailed) kept in DB and small subset (exif description + caption) forwarded to Layer 0.

[8] Send minimal payload to Layer 0 (Regex/Heuristics)

What Layer 0 sees (minimal):

request_id

normalized_text (first 4k chars)

special_char_mask (a compact mask marking zero-width/homoglyph spots)

heuristic_flags

attachment_texts (exif_description + caption + small OCR)

emoji_seq and emoji_count

pHash or attachment_id pointers if needed

Layer 0 Actions: run regexes, separator detection, separator-within-attachment checks, reject immediately or pass to Layer 1.

[9] Storage & Logging

Persist the full request metadata, normalizations, attachments, embeddings pointers, and a masked copy for compliance. Emit monitoring events for any heuristic hits.

3) Special: images inside PDFs & office docs — recommended process

Always extract embedded images (use PyMuPDF / pdfium or pdfplumber + Pillow).

Treat each extracted image as a first-class attachment: compute pHash, excerpt EXIF, caption, OCR.

Send EXIF/Caption/OCR text upstream as plain text channels for Layer 0.

If PDF metadata (Title/Description/XMP) contains suspicious patterns (base64, HTML tags, long delimiters) flag and quarantine PDF.

If stego_score > threshold or extracted payload exists, quarantine and escalate for human review.

4) Minimal API/payload fields (reminder)

For Layer 0: only the smallest fields necessary: normalized_text (truncated), heuristic_flags, attachment_texts, emoji_seq, special_char_mask, request_id.

For persistence: keep full raw snapshots and vectors behind pointers.

5) Latency & resource estimates (realistic) — Prototype vs Production

These are realistic time/latency numbers based on typical open-source components on modest server hardware (8–16 CPU cores, single GPU optional). They assume CPU-bound FastAPI + small vision models run on CPU/GPU as noted.

Per-request latency (typical when running everything synchronously):

Gate & basic normalization (unicode / zero-width / token preview): 5–25 ms

Fast heuristics (regex checks): 1–5 ms

MiniLM embed fingerprint (all-MiniLM-L6-v2) on CPU: 5–30 ms (depending on batching)

Image thumbnail + pHash + EXIF read: 10–40 ms per image

Tiny caption model (CPU) or CLIP embed: 50–300 ms per image (GPU much faster)

OCR (Tesseract): 150–800 ms per page (selective)

Stego heuristics (entropy + LSB-lite): 30–200 ms per image

If you run image steps async (recommended): main path to Layer0 remains fast (under 50 ms) while attachments are processed in background (and their flags update results later).

Implementation time (engineering) — realistic delivery estimate (based on plan file)

These estimates assume 1–2 engineers (familiar with Python & ML infra), 40-hour weeks.

MVP (FastAPI + core normalization + Layer 0 minimal payload + basic attachment stubs)

Spec + Pydantic schemas: 0.5–1 day

FastAPI endpoint + basic normalization + regex heuristics: 1–2 days

Logging, request id, HMAC verification: 0.5–1 day

Basic attachment stubbing (store blobs, compute sha256, thumbnail): 1–2 days Total MVP: ~3–6 working days (single engineer) — deployable and safe for most traffic if image processing is async.

Essential image/pdf processing (production-ready)

PDF text & image extraction + EXIF capture: 1–3 days

pHash, thumbnail, and EXIF pipeline: 1–2 days

Tiny vision caption + CLIP embedding: 2–4 days (depends on model selection & GPU availability)

OCR selective integration + tuning: 2–5 days

Stego detectors + LSB heuristics + thresholding: 2–4 days

Integration testing, logging, dashboards, alerting & red-team data: 3–6 days Total for production-ready file processing: ~2–3 weeks (single engineer) or 1–2 weeks with 2 engineers.

Full hardened production (policy, monitoring, weekly red-team + adaptive thresholds)

A/B testing, threshold tuning, human escalation workflows, retraining or offline mutation coverage: 4–8 weeks.

6) Recommended rollout pattern

MVP first: get FastAPI endpoint, normalization, Layer 0 minimal payload, and attachment stubs. Keep heavy file processing async.

Add image pipeline: pHash, EXIF, caption — keep OCR/stego optional at first and gated by heuristics.

Enable PDF image extraction and send extracted image captions/EXIF to Layer 0.

Add stego & OCR after you have anchored thresholds and monitoring.

Daily/weekly red-team to generate obfuscations (TextAttack, custom emoji/zero-width fuzzer) and adapt rules.

7) Quick developer checklist (code imports & libs)

fastapi, uvicorn, pydantic

python-magic or filetype for mime checks

ftfy + unicodedata for normalization

transformers + sentence-transformers (for MiniLM)

Pillow, imagehash (pHash), piexif or exifread

pdfplumber / PyMuPDF(fitz) for PDF extraction

pytesseract for OCR (if needed)

numpy, scipy for stego heuristics

8) Notes & rationale

Do file processing: many attacks hide in metadata/embedded images and in PDFs. Not processing attachments increases risk dramatically.

Extract images from PDFs: attackers use PDFs as carriers (images, metadata, file attachments). Treat them as first-class citizen.

Keep Layer 0 minimal & fast: avoid sending full blobs—pass snapshots & pointers. Process heavy jobs async and update flags.

If you want, I can:

produce the exact FastAPI + Pydantic models (single-file) to implement the MVP endpoint, or

create a drop-in Python module that performs normalization, zero-width removal, emoji extraction, token preview and returns the exact JSON payload described.

Nice — here’s a focused, actionable checklist you can implement in your FastAPI input-prep endpoint + exactly what to send onward to **Layer 0 (regex/heuristics)** and **image-processing**. I’ll also call out the current high-risk attack types you should design for (with sources) and give a compact JSON payload example you can paste into your FastAPI handler.

---

# Quick summary of current high-risk attacks (design your prep for these)

* **Emoji / Unicode obfuscation (“emoji smuggling”, zero-width, homoglyphs)** — highly effective at evading content filters; build normalization & detection. ([arXiv][1])
* **Steganographic / image-embedded prompts** (hidden instructions in pixels or EXIF) — real, growing risk for multimodal inputs. ([arXiv][2])
* **Second-order prompt injection / multi-agent chaining** (one agent tricks another / calendar or doc fields exploited) — treat external/agent-sourced text as untrusted. ([TechRadar][3])
* **Poisoned external data (RAG/doc ingestion)** — treat external documents as separate channels and verify integrity. ([arXiv][4])

(For more context see the expanded plan file: `/mnt/data/FINAL_MODIFIED_PLAN.md`. )

---

# End-to-end **Input Preparation** checklist (order matters)

1. **Receive & gate**

   * Accept structured fields: `user_text`, `external_docs[]`, `attachments[]`, `instruction`, `client_meta` (see schema below).
   * Enforce maximum sizes, rate limits, file-type whitelists.

2. **Provenance & integrity**

   * If external data comes from connectors, attach `source_id`, timestamp, and HMAC signature; verify HMAC before trusting.
   * Generate and store per-request trace id (UUID).

3. **Basic canonicalization / normalization**

   * Normalize Unicode to **NFKC** (or NFKD as you prefer) to reduce homoglyph attacks. Keep original text snapshot. ([Medium][5])
   * Remove/record zero-width and invisible characters (e.g., U+200B, U+2060) and produce a masked version (`zero_width_removed`) plus detection flag.

4. **Token & length preview**

   * Tokenize with the same tokenizer as your LLM and attach `token_count`, `token_preview` (first N tokens). Reject or shard if too-long/unbounded content.

5. **Fast heuristics / pattern detection (pre-layer0)**

   * Detect base64/long-encoded blobs, long repeated punctuation, many delimiter-like characters, suspicious control characters, long single-line payloads. Produce `heuristic_flags`.

6. **Emoji & special-char handling**

   * Extract emoji sequences and map to text descriptions (short caption). Create `emoji_seq`, `emoji_desc_embed` fields. Flag odd emoji usage patterns. ([IJRASET][6])

7. **Embedding fingerprint (lightweight)**

   * Compute a compact embedding (all-MiniLM or similar) for the *normalized* text. Store `text_embedding_hash` (e.g., hashing float32 -> base64) and optionally a small `embedding_vector` for detection layers.

8. **RAG / external data separation**

   * Do **not** merge external docs directly into `user_text`. Store them as distinct channels `{user:, external:[], doc_meta:[]}` with HMACed channel signatures. Use delimiters later when composing final prompt. ([arXiv][4])

9. **Image/attachment stub processing** (see below for details)

   * For each image: compute file hash, perceptual hash (pHash), EXIF extraction, small caption via CPU-friendly vision model, stego-detection score, extract textual metadata (EXIF: Description, ImageDescription), and run LSB/LSB-like stego heuristics.

10. **Produce normalized “sentinel” forms for downstream layers**

    * `normalized_text` (NFKC + zero-width removed)
    * `raw_text_snapshot` (original)
    * `token_preview` and `token_count`
    * `embedding_id` / `embedding_vector`
    * `heuristic_flags` (fast booleans)
    * `attachments_meta[]` (image hash, pHash, exif, stego_score, caption)
    * `channels` (user vs external vs system) with HMACs

11. **Logging & alerting**

    * Log everything (including snapshots) to off-system secure log with request id. If `heuristic_flags` or `stego_score` exceed thresholds, emit an alert to monitoring dashboard.

12. **Return minimal payload to Layer 0** (see next section) and store rich metadata for Layer 1/2/3.

---

# What to send *to Layer 0* (fast regex/heuristics; CPU millisecond budget)

Layer 0 must be minimal and fast — only the fields needed to evaluate regex/heuristics quickly:

* `request_id` (UUID)
* `normalized_text` (short-capped, e.g., first 4k chars)
* `raw_text_snapshot` (optional small snapshot or pointer to stored blob)
* `token_count`
* `special_char_mask` (string of same length with `.`/`Z` denoting zero-width/homoglyphs etc.)
* `heuristic_flags` (precomputed simple booleans: has_long_base64, contains_system_delimiters, many_repeated_chars, contains_xml_tags, contains_html_comments)
* `attachment_texts` (EXIF/ALT text + image captions extracted; small strings)
* `emoji_seq` and `emoji_count`
* `channel_tags` (`user` / `external`) and HMAC verification result
* `embed_fingerprint_hash` (very small hash) — optional, if you want Layer 0 to consult a small allow/deny list

**Layer 0 action expectations**: run regexes, separator detection, detect known templates like `ignore previous instructions`, suspicious delimiters like `</system>`, very long encoded strings, unicode-tag characters. If blocked, return a short reason code and surface to user.

(These practices align with OWASP guidance on prompt injection risk classification). ([OWASP Gen AI Security Project][7])

---

# What to send to **image processing** (and what to compute there)

For every image/file attachment, **send the raw bytes** (or a pointer) and these required fields/calls from input-prep:

**From Input Prep -> Image Processing**

* `request_id`, `attachment_id`, `file_hash` (sha256), `mime_type`, `file_size`
* `thumbnail` (small downsampled image, e.g., 224×224)
* `client_meta` (uploader-provided filename + source_id)
* `channel` (user vs external)

**What image processing must return (and what you should store/send onward)**

1. `pHash` (perceptual hash) for near-duplicate detection
2. `file_entropy` and `suspicious_entropy_ratio` (highly uniform images might be stego carriers)
3. `exif_meta` (camera fields, Description, Artist, Software) — **extract EXIF Description and treat as text input for layers** (EXIF Description is a common attack vector). ([Medium][8])
4. `embedded_text_from_exif` (string)
5. `caption` (small free-text caption from a tiny vision model)
6. `vision_embedding` (CLIP-like) — optional small vector for semantic checks
7. `ocr_text` (if image likely to contain text; run CPU OCR selectively)
8. `stego_score` (LSB or other stego detectors — return confidence and any extracted payload text if found)
9. `suspect_flags`: e.g. `exif_description_present`, `exif_to_user_text_similarity_high`, `stego_confidence`, `extracted_payload_length`
10. `suspicious_metadata` boolean (if EXIF description contains “system override” patterns, long HTML, base64, etc.)

**Important**: send `exif_meta.Description` and `caption` to Layer 0 as plain text for immediate heuristics; if stego_score > threshold, escalate to human review.

(Research shows EXIF / metadata is a practical attack vector and steganography in images is an active research threat). ([arXiv][2])

---

# FastAPI JSON payload (suggested schema you can implement in 1 endpoint)

```json
{
  "request_id": "uuid",
  "instruction": "...",
  "user_text": "...",
  "normalized_text": "...",
  "token_count": 123,
  "token_preview": ["Tok1","Tok2", "..."],
  "heuristic_flags": {
    "has_base64": false,
    "has_system_delimiter": true,
    "zero_width_found": true,
    "many_repeated_chars": false
  },
  "emoji_seq": ["🔥","📁"],
  "embedding_fingerprint": "embhash-base64",
  "channels": {
    "user": {"hmac_ok": true},
    "external": [{"source_id":"url","hmac_ok":false}]
  },
  "attachments": [
    {
      "id":"img-1",
      "file_hash":"sha256..",
      "mime":"image/png",
      "size":12345,
      "thumbnail_ptr":"s3://.../thumb.jpg"
    }
  ],
  "provenance": {"uploader_id":"...", "ts":"..."}
}
```

* **Send only the minimal `normalized_text`, `heuristic_flags`, `attachment_texts`, and channel HMAC status to Layer 0.**
* Keep the full text + embeddings stored server-side and pass pointers to downstream layers to avoid duplication.

---

# Practical processing knobs & detection thresholds (recommendations)

* Unicode normalization: **NFKC**, record diff. If many changes or many zero-width removed → raise `unicode_obfuscation` flag. ([Medium][5])
* Emoji / zero-width smell: if emoji count > 10% of chars or repeating invisible chars → `emoji_smuggling_flag`. ([arXiv][1])
* Stego detector: use pHash + LSB heuristic; if `stego_score > 0.6` then quarantine and escalate to human. ([arXiv][2])
* Token preview: if prompt-length grows unbounded after RAG concatenation → cut and require user confirmation.

---

# Monitoring, red-team, and adaptive updates

* Save representative "near misses" for offline retraining & threshold tuning. Use TextAttack or AdvBench to generate obfuscations offline. ([Medium][8])
* Weekly UMAP/embedding viz of recent traffic to spot clusters (attacks often cluster).
* Maintain a whitelist/blacklist of `pHash` and `exif` signatures discovered in attacks.

---

# Minimal implementation priority (what to build first)

1. Structured API fields + HMAC verification for channels. (Block >95% indirect attacks.)
2. Unicode normalization + zero-width detector + token preview. (Very quick, very effective.)
3. Fast regex list (Layer 0 inputs) for common templates (`ignore previous instructions`, `<system>`, long base64). ([OWASP Gen AI Security Project][7])
4. Lightweight `all-MiniLM-L6-v2` embedding fingerprint + an IsolationForest offline detection. (Cheap CPU inference.)
5. Image pre-stub: EXIF extraction + pHash + caption; only run OCR/stego detectors if heuristics indicate.

---

If you want, I can:

* produce the exact FastAPI POST schema + Pydantic model for the payload above, **or**
* give you a ready-to-drop-in Python function that implements steps 2–6 (normalization, zero-width removal, token preview, emoji extraction, embedding fingerprint) and returns the JSON payload shown.

Also: here’s the local plan file I reviewed earlier (useful for full context):
`/mnt/data/FINAL_MODIFIED_PLAN.md` — that file contains the modified roadmap and recommendations. 

Which next step do you want? (FastAPI Pydantic model or the Python helper function to run in your input-prep service?)

[1]: https://arxiv.org/html/2504.11168v1?utm_source=chatgpt.com "Bypassing Prompt Injection and Jailbreak Detection in LLM ..."
[2]: https://arxiv.org/html/2507.22304v1?utm_source=chatgpt.com "Invisible Injections: Exploiting Vision-Language Models ..."
[3]: https://www.techradar.com/pro/security/second-order-prompt-injection-can-turn-ai-into-a-malicious-insider?utm_source=chatgpt.com "Second-order prompt injection can turn AI into a malicious insider"
[4]: https://arxiv.org/html/2507.13169v1?utm_source=chatgpt.com "Prompt Injection 2.0: Hybrid AI Threats"
[5]: https://medium.com/%40instatunnel/unicode-normalization-attacks-when-admin-admin-32477c36db7f?utm_source=chatgpt.com "Unicode Normalization Attacks: When “admin” ≠ “admin” 🔤"
[6]: https://www.ijraset.com/research-paper/emoji-and-unicode-based-data-masking-attacks-on-ai-systems?utm_source=chatgpt.com "A Survey on Emoji and Unicode-Based Data Masking ..."
[7]: https://genai.owasp.org/llmrisk/llm01-prompt-injection/?utm_source=chatgpt.com "LLM01:2025 Prompt Injection - OWASP Gen AI Security Project"
[8]: https://fdzdev.medium.com/20-prompt-injection-techniques-every-red-teamer-should-test-b22359bfd57d?utm_source=chatgpt.com "20 Prompt Injection Techniques Every Red Teamer Should Test"
