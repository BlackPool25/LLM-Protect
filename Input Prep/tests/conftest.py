"""Pytest configuration and shared fixtures."""

import pytest
import json
from pathlib import Path

from src.core.token_inserter import TokenInserter
from src.core.preference_aligner import PreferenceAligner
from src.core.multimodal import MultimodalExtractor
from src.config import settings


@pytest.fixture(scope="session", autouse=True)
def initialize_api_components():
    """Initialize global API components before any tests."""
    import src.gateway.api as api_module
    
    # Initialize components
    api_module.token_inserter = TokenInserter(
        defensive_tokens=settings.defensive_tokens,
        position=settings.token_position
    )
    
    api_module.preference_aligner = PreferenceAligner(
        model_path=settings.model_path,
        lora_adapter_path=settings.lora_adapter_path,
        risk_threshold=settings.risk_threshold
    )
    
    api_module.multimodal_extractor = MultimodalExtractor()
    
    yield
    
    # Cleanup (optional)
    api_module.token_inserter = None
    api_module.preference_aligner = None
    api_module.multimodal_extractor = None


@pytest.fixture(scope="session")
def owasp_samples():
    """Load OWASP test samples."""
    fixtures_path = Path(__file__).parent / "fixtures" / "owasp_samples.json"
    with open(fixtures_path) as f:
        return json.load(f)


@pytest.fixture
def benign_prompts(owasp_samples):
    """Get benign prompts from samples."""
    return [s for s in owasp_samples if s["expected_risk"] == "low"]


@pytest.fixture
def malicious_prompts(owasp_samples):
    """Get malicious prompts from samples."""
    return [s for s in owasp_samples if s["expected_risk"] == "high"]


@pytest.fixture
def medium_risk_prompts(owasp_samples):
    """Get medium risk prompts from samples."""
    return [s for s in owasp_samples if s["expected_risk"] == "medium"]

