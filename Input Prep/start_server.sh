#!/bin/bash
# Start LLM-Protect server with AMD GPU support

cd "/home/lightdesk/Projects/LLM-Protect/Input Prep"
source ../venv/bin/activate

# AMD GPU settings for RX 7900 GRE (RDNA3)
export HSA_OVERRIDE_GFX_VERSION=11.0.0
export HIP_VISIBLE_DEVICES=0
export AMD_SERIALIZE_KERNEL=3  # For debugging HIP errors

# Optional: Enable more detailed error messages
# export TORCH_SHOW_CPP_STACKTRACES=1

echo "Starting LLM-Protect server with AMD GPU support..."
python -c "import torch; print(f'GPU: {torch.cuda.get_device_name(0) if torch.cuda.is_available() else \"CPU\"}')"
python -c "import torch; print(f'ROCm version: {torch.version.hip if hasattr(torch.version, \"hip\") else \"N/A\"}')"
echo ""

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

