# Hugging Face Setup for Gemma-2B

Gemma-2B is a **gated model** that requires Hugging Face authentication.

## Quick Setup (3 steps)

### 1. Create a Hugging Face Account

Go to https://huggingface.co/join and create a free account.

### 2. Request Access to Gemma-2B

Visit: https://huggingface.co/google/gemma-2b

Click **"Request access"** button. Access is usually granted instantly.

### 3. Get Your Access Token

**Option A: Login via CLI (Recommended)**

```bash
# Install huggingface-cli if not already installed
pip install huggingface-hub

# Login (will save token automatically)
huggingface-cli login
```

Enter your token when prompted. Get it from: https://huggingface.co/settings/tokens

**Option B: Set Environment Variable**

```bash
# Get your token from: https://huggingface.co/settings/tokens
# Create a token with "Read" permission

# Add to your .env file
echo "HF_TOKEN=hf_your_token_here" >> .env
```

## Verify Setup

```bash
# Test if authentication works
python -c "from transformers import AutoTokenizer; print('✓ Authentication successful' if AutoTokenizer.from_pretrained('google/gemma-2b') else '✗ Failed')"
```

## Alternative: Use Ungated Models

If you want to skip authentication, use these alternatives:

### TinyLlama (1.1B - Fast, No Auth Required)

```python
# In app/services/llm_service.py, change:
model_name = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
```

### Phi-2 (2.7B - Microsoft, No Auth)

```python
model_name = "microsoft/phi-2"
```

### GPT-2 (1.5B - Classic, No Auth)

```python
model_name = "gpt2-large"
```

## Change Model in Code

Edit `app/services/llm_service.py`:

```python
def load_model(model_name: str = "YOUR_MODEL_HERE"):
```

## Troubleshooting

### "You are trying to access a gated repo"

**Solution**: Follow steps 1-3 above to authenticate

### "Invalid token"

**Solution**: 
1. Go to https://huggingface.co/settings/tokens
2. Create a new token with "Read" permission
3. Run `huggingface-cli login` and paste the token

### "Token not found"

**Solution**: Make sure HF_TOKEN is in your `.env` file:
```bash
grep HF_TOKEN .env
```

If not there, add it:
```bash
echo "HF_TOKEN=hf_your_token_here" >> .env
```

### Model takes too long to load

**First time**: Model downloads (can be 5-10GB, takes time)
**Subsequent loads**: Should be fast (5-10 seconds)

Models are cached in: `~/.cache/huggingface/hub/`

## Using TinyLlama (Quick Alternative)

For immediate testing without auth:

```bash
# Update the model in code
sed -i 's/google\/gemma-2b/TinyLlama\/TinyLlama-1.1B-Chat-v1.0/g' app/services/llm_service.py

# Restart server
uvicorn app.main:app --reload
```

TinyLlama:
- ✅ No authentication required
- ✅ Smaller (1.1B vs 2B parameters)
- ✅ Faster inference
- ✅ Good for testing
- ⚠️ Slightly lower quality responses

## Summary

**Quick fix for Gemma-2B:**
```bash
# 1. Login to Hugging Face
huggingface-cli login

# 2. Restart your server
# Server will automatically pick up authentication
```

**Or use TinyLlama (no auth needed):**
```bash
# Change model name in app/services/llm_service.py
# Line ~26: model_name: str = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
```

