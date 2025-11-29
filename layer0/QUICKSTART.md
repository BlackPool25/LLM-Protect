# Layer0 - Quick Start Guide

## TL;DR

```bash
# 1. Install
cd layer0
pip install -r requirements.txt

# 2. Run
python server.py --port 3001

# 3. Test
curl http://localhost:3001/test
```

---

## Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/test` | GET | Health check |
| `/layer0` | POST | Main processing (receives Input Prep JSON) |

---

## Test Locally (No Server)

```bash
# Test with JSON file
python server.py --test path/to/input.json

# Test with text
python server.py --text "Your message here"
```

---

## Integration

**Input Prep sends to:** `POST http://localhost:3001/layer0`

**Layer0 forwards to:** `http://localhost:3002/layer1`

---

## Response Examples

### ✅ Clean (Passed)
```json
{"blocked": false, "forwarded": true}
```

### 🚫 Attack (Blocked)
```json
{"blocked": true, "reason": "Matched block pattern: ignore_previous"}
```

---

## That's it! 🚀
