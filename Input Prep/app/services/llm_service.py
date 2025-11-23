"""
LLM service for generating responses using Gemma 2B.

Integrates with Hugging Face transformers to run the LLM locally.
"""

from typing import Optional, Dict, Any
import torch
from app.utils.logger import get_logger
from app.config import settings

logger = get_logger(__name__)

# Try to import transformers
try:
    from transformers import AutoTokenizer, AutoModelForCausalLM
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    logger.warning("transformers not available. LLM inference will be disabled.")

# Global model and tokenizer (loaded once)
_model = None
_tokenizer = None
_model_loaded = False


def load_model(model_name: str = "google/gemma-2b", use_auth_token: bool = True):
    """
    Load the Gemma 2B model and tokenizer.
    
    Args:
        model_name: Hugging Face model identifier
        use_auth_token: Whether to use HF authentication token
    
    Returns:
        Tuple of (tokenizer, model)
    """
    global _model, _tokenizer, _model_loaded
    
    if _model_loaded:
        return _tokenizer, _model
    
    if not TRANSFORMERS_AVAILABLE:
        raise ImportError("transformers library not installed. Install with: pip install transformers")
    
    try:
        logger.info(f"Loading model: {model_name}")
        
        # Get HF token from environment or use default authentication
        import os
        hf_token = os.getenv("HF_TOKEN") or os.getenv("HUGGING_FACE_HUB_TOKEN")
        
        # Load tokenizer
        _tokenizer = AutoTokenizer.from_pretrained(
            model_name,
            token=hf_token if use_auth_token else None
        )
        
        # Load model with appropriate device (CPU/GPU)
        device = "cuda" if torch.cuda.is_available() else "cpu"
        logger.info(f"Using device: {device}")
        
        _model = AutoModelForCausalLM.from_pretrained(
            model_name,
            torch_dtype=torch.float16 if device == "cuda" else torch.float32,
            device_map="auto" if device == "cuda" else None,
            low_cpu_mem_usage=True,
            token=hf_token if use_auth_token else None
        )
        
        if device == "cpu":
            _model = _model.to(device)
        
        _model_loaded = True
        logger.info("Model loaded successfully")
        
        return _tokenizer, _model
        
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        raise


def generate_response(
    prompt: str,
    max_new_tokens: int = 512,
    temperature: float = 0.7,
    top_p: float = 0.9,
    do_sample: bool = True
) -> Dict[str, Any]:
    """
    Generate a response using the LLM.
    
    Args:
        prompt: The input prompt (already prepared)
        max_new_tokens: Maximum number of tokens to generate
        temperature: Sampling temperature (higher = more creative)
        top_p: Nucleus sampling parameter
        do_sample: Whether to use sampling (False = greedy decoding)
    
    Returns:
        Dictionary with generated text and metadata
    """
    if not TRANSFORMERS_AVAILABLE:
        return {
            "success": False,
            "error": "Transformers library not available",
            "generated_text": "",
            "input_tokens": 0,
            "output_tokens": 0,
            "total_time_ms": 0
        }
    
    import time
    start_time = time.time()
    
    try:
        # Load model if not already loaded
        tokenizer, model = load_model()
        
        # Tokenize input
        inputs = tokenizer(prompt, return_tensors="pt")
        input_tokens = inputs["input_ids"].shape[1]
        
        # Move to appropriate device
        device = next(model.parameters()).device
        inputs = {k: v.to(device) for k, v in inputs.items()}
        
        logger.info(f"Generating response (input_tokens={input_tokens}, max_new={max_new_tokens})")
        
        # Generate
        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                temperature=temperature,
                top_p=top_p,
                do_sample=do_sample,
                pad_token_id=tokenizer.eos_token_id
            )
        
        # Decode output
        generated_text = tokenizer.decode(outputs[0], skip_special_tokens=True)
        
        # Remove the input prompt from the output
        if generated_text.startswith(prompt):
            generated_text = generated_text[len(prompt):].strip()
        
        output_tokens = outputs[0].shape[0] - input_tokens
        total_time = (time.time() - start_time) * 1000
        
        logger.info(f"Generation complete: {output_tokens} tokens in {total_time:.2f}ms")
        
        return {
            "success": True,
            "generated_text": generated_text,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_time_ms": total_time,
            "model": "gemma-2b"
        }
        
    except Exception as e:
        total_time = (time.time() - start_time) * 1000
        logger.error(f"Generation failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "generated_text": "",
            "input_tokens": 0,
            "output_tokens": 0,
            "total_time_ms": total_time
        }


def check_model_availability() -> Dict[str, Any]:
    """
    Check if the model is available and can be loaded.
    
    Returns:
        Dictionary with availability status
    """
    if not TRANSFORMERS_AVAILABLE:
        return {
            "available": False,
            "reason": "transformers library not installed"
        }
    
    try:
        if _model_loaded:
            return {
                "available": True,
                "loaded": True,
                "device": str(next(_model.parameters()).device)
            }
        else:
            # Check if model files exist
            return {
                "available": True,
                "loaded": False,
                "message": "Model not loaded yet (will load on first request)"
            }
    except Exception as e:
        return {
            "available": False,
            "reason": str(e)
        }

