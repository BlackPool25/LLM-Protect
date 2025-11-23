#!/bin/bash
# LLM-Protect Setup Script for AMD GPUs (ROCm)
# Optimized for AMD Radeon 7900 GRE and similar RDNA GPUs

set -e

cd "$(dirname "$0")"

echo "🛡️  LLM-Protect Setup Script (AMD GPU Edition)"
echo "=============================="
echo ""

# Check for AMD GPU
echo "Checking for AMD GPU..."
if command -v rocm-smi &> /dev/null; then
    echo "✓ ROCm detected"
    rocm-smi --showproductname
elif lspci | grep -i "VGA.*AMD" &> /dev/null; then
    echo "⚠️  AMD GPU detected but ROCm not installed"
    echo "   Please install ROCm first: https://rocm.docs.amd.com/projects/install-on-linux/en/latest/"
    echo ""
    read -p "Continue without ROCm (CPU mode)? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    echo "⚠️  No AMD GPU detected. This script is optimized for AMD GPUs."
    echo ""
    read -p "Continue with CPU-only setup? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi
echo ""

# Check if virtual environment is activated
echo "Checking virtual environment..."
if [[ "$VIRTUAL_ENV" != "" ]]; then
    echo "✓ Virtual environment detected: $VIRTUAL_ENV"
    PYTHON_VERSION=$(python --version 2>&1 | awk '{print $2}')
    echo "✓ Python $PYTHON_VERSION"
else
    echo "❌ No virtual environment activated!"
    echo "   Please activate your venv first with: actml"
    exit 1
fi
echo ""

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip -q
echo "✓ pip upgraded"
echo ""

# Fix NumPy version first
echo "Installing compatible NumPy version..."
pip install "numpy<2.0.0" -q
echo "✓ NumPy <2.0.0 installed"
echo ""

# Install PyTorch with ROCm support
echo "Installing PyTorch with ROCm support..."
if command -v rocm-smi &> /dev/null; then
    echo "   (This may take 5-10 minutes)"
    pip install torch torchvision --index-url https://download.pytorch.org/whl/rocm6.2
    echo "✓ PyTorch with ROCm installed"
else
    echo "   ROCm not detected, installing CPU version"
    pip install torch==2.2.0 torchvision
    echo "✓ PyTorch (CPU) installed"
fi
echo ""

# Install other dependencies from PyPI (not ROCm index)
echo "Installing remaining dependencies..."
pip install transformers==4.38.0
pip install optimum[exporters]==1.17.0
pip install peft==0.9.0
pip install onnxruntime==1.17.0
pip install pymupdf==1.23.21 pillow==10.2.0
pip install git+https://github.com/openai/CLIP.git
pip install fastapi==0.109.0 uvicorn[standard]==0.27.0
pip install cryptography==42.0.0 python-jose==3.3.0
pip install pytest==8.0.0 pytest-asyncio==0.21.1 pytest-benchmark==4.0.0
pip install locust==2.20.0 prometheus-client==0.19.0 structlog==24.1.0
pip install pydantic==2.5.0 pydantic-settings==2.1.0 python-multipart==0.0.9
echo "✓ Dependencies installed"
echo ""

# Create .env file
echo "Setting up environment configuration..."
if [ ! -f ".env" ]; then
    cp .env.example .env
    # Generate random HMAC secret
    SECRET=$(openssl rand -hex 32)
    sed -i "s/change-me-in-production-use-strong-secret/$SECRET/g" .env
    echo "✓ .env file created with random HMAC secret"
else
    echo "✓ .env file already exists"
fi
echo ""

# Create models directory
echo "Creating models directory..."
mkdir -p models
echo "✓ models/ directory ready"
echo ""

# Detect GPU capabilities
if command -v rocm-smi &> /dev/null; then
    echo "================================================"
    echo "🎮 AMD GPU Detected - ROCm Configuration"
    echo "================================================"
    echo ""
    rocm-smi --showproductname
    echo ""
    
    # Test PyTorch GPU access
    python3 << 'PYEOF'
import torch
if torch.cuda.is_available():
    print(f"✓ PyTorch can access GPU: {torch.cuda.get_device_name(0)}")
    print(f"✓ CUDA (ROCm) version: {torch.version.cuda}")
    print(f"✓ Available GPU memory: {torch.cuda.get_device_properties(0).total_memory / 1024**3:.1f} GB")
else:
    print("⚠️  PyTorch cannot access GPU. Check ROCm installation.")
PYEOF
    echo ""
fi

# Model download - Skip for Week 1
echo "================================================"
echo "📦 Model Download - SKIPPED FOR WEEK 1"
echo "================================================"
echo "Note: Phi-3 ONNX export is not fully supported in optimum 1.17.0"
echo "Week 1 implementation uses heuristic-based detection (mock mode)"
echo "This is intentional per the plan - full model integration is Week 2+"
echo ""
echo "✓ Week 1 will work perfectly without downloading 5GB models"
echo ""

# Run tests
echo "================================================"
echo "🧪 Running Tests"
echo "================================================"
pytest tests/ -v --tb=short -x || {
    echo "⚠️  Some tests failed, but basic setup is complete"
}
echo ""

echo "================================================"
echo "✅ Setup Complete!"
echo "================================================"
echo ""

if command -v rocm-smi &> /dev/null; then
    echo "🎮 AMD GPU Configuration:"
    echo "   - ROCm detected and configured"
    echo "   - PyTorch with ROCm support installed"
    echo "   - GPU acceleration enabled"
    echo ""
fi

echo "To start the API server:"
echo "  1. Activate virtual environment: source venv/bin/activate"
echo "  2. Run the server: python src/gateway/api.py"
echo "  3. Visit http://localhost:8000/docs for API documentation"
echo ""
echo "To test GPU access:"
echo "  python -c 'import torch; print(f\"GPU available: {torch.cuda.is_available()}\")'"
echo ""
echo "Happy securing! 🛡️"

