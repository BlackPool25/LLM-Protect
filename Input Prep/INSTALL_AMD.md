# Installation Guide for AMD GPUs (ROCm)

## Your Hardware: AMD Radeon RX 7900 GRE

Your GPU is supported by ROCm 5.7+ and PyTorch with ROCm backend.

## Step-by-Step Installation

### 1. Install ROCm (if not already installed)

**Your GPU (RX 7900 GRE) requires ROCm 6.0 or later**

For Ubuntu/Debian:

```bash
# Download latest AMDGPU installer (6.4.4 or later)
wget https://repo.radeonopensoftware.com/amdgpu-install/latest/ubuntu/jammy/amdgpu-install_latest_all.deb
sudo dpkg -i amdgpu-install_latest_all.deb
sudo apt update

# Install ROCm (this will install the latest version)
sudo amdgpu-install --usecase=rocm

# Add user to render and video groups
sudo usermod -a -G render,video $LOGNAME

# Reboot (required)
sudo reboot
```

**Alternative - Specific Version (6.1 recommended for PyTorch stability):**
```bash
sudo amdgpu-install --usecase=rocm --rocmrelease=6.1
```

### 2. Verify ROCm Installation

After reboot:

```bash
# Check if GPU is detected
rocm-smi

# Should show your RX 7900 GRE
```

### 3. Create Virtual Environment

```bash
cd /home/lightdesk/Projects/LLM-Protect

# Create venv
python3 -m venv venv

# Activate
source venv/bin/activate
```

### 4. Install PyTorch with ROCm Support

**Important**: Install PyTorch BEFORE other requirements!

**Recommended for RX 7900 GRE - ROCm 6.1 (best stability):**
```bash
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/rocm6.1
```

**Alternative versions:**
```bash
# Latest (ROCm 6.2) - may have cutting-edge features
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/rocm6.2

# Minimum (ROCm 6.0) - first version with 7900 GRE support
# pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/rocm6.0
```

### 5. Install Other Requirements

```bash
pip install -r requirements.txt
```

### 6. Verify GPU is Available in PyTorch

```bash
python3 -c "import torch; print(f'CUDA available: {torch.cuda.is_available()}'); print(f'Device: {torch.cuda.get_device_name(0) if torch.cuda.is_available() else \"CPU\"}')"
```

**Expected output**:
```
CUDA available: True
Device: AMD Radeon RX 7900 GRE
```

**Note**: PyTorch uses the "CUDA" API name even for AMD GPUs with ROCm. This is normal!

## Performance Expectations

With your RX 7900 GRE:

- **Gemma 2B**: ~100-200 tokens/second
- **Memory Usage**: ~6GB VRAM for FP16
- **First Load**: 30-60 seconds (model download + loading)
- **Subsequent Loads**: 5-10 seconds

## Troubleshooting

### "RuntimeError: No HIP GPUs are available"

**Solution**: 
```bash
# Check ROCm installation
rocm-smi

# Verify user groups
groups | grep -E "render|video"

# If not in groups, add and reboot
sudo usermod -a -G render,video $LOGNAME
sudo reboot
```

### "Unsupported GPU architecture"

**Solution**: Update to ROCm 6.1 or later (7900 GRE needs 6.0+)
```bash
# Install ROCm 6.1 (recommended)
sudo amdgpu-install --usecase=rocm --rocmrelease=6.1

# Or latest
sudo amdgpu-install --usecase=rocm --rocmrelease=latest
```

### PyTorch doesn't detect GPU

**Solution**: Reinstall PyTorch with correct ROCm version (match your installed ROCm)
```bash
pip uninstall torch torchvision torchaudio

# For ROCm 6.1 (recommended)
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/rocm6.1

# Or for ROCm 6.2
# pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/rocm6.2
```

### Out of Memory Errors

**Solutions**:
1. Use FP16 (already default in code)
2. Reduce batch size
3. Use smaller model (Gemma 2B IT variant)
4. Monitor VRAM: `watch -n 1 rocm-smi`

## Performance Optimization

### Enable TF32 (for better performance)

Edit `app/services/llm_service.py`:

```python
# Add after imports
torch.backends.cuda.matmul.allow_tf32 = True
torch.backends.cudnn.allow_tf32 = True
```

### Monitor GPU Usage

```bash
# Real-time monitoring
watch -n 1 rocm-smi

# Or use radeontop
sudo apt install radeontop
radeontop
```

## Environment Variables

Add to your `.env` file:

```bash
# Force ROCm to use GPU 0
HIP_VISIBLE_DEVICES=0

# Optimize for RDNA3 architecture
HSA_OVERRIDE_GFX_VERSION=11.0.0

# Enable debug info (optional)
# HIP_LAUNCH_BLOCKING=1
```

## Alternative: CPU-Only Installation

If you encounter issues with ROCm, you can fall back to CPU:

```bash
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu
```

**Note**: CPU inference will be much slower (10-20 tokens/second).

## Testing the Installation

Run this test script:

```python
import torch

print("=" * 60)
print("PyTorch GPU Test")
print("=" * 60)

print(f"PyTorch version: {torch.__version__}")
print(f"CUDA available: {torch.cuda.is_available()}")

if torch.cuda.is_available():
    print(f"CUDA version: {torch.version.cuda}")
    print(f"Device count: {torch.cuda.device_count()}")
    print(f"Current device: {torch.cuda.current_device()}")
    print(f"Device name: {torch.cuda.get_device_name(0)}")
    print(f"Device capability: {torch.cuda.get_device_capability(0)}")
    
    # Memory info
    print(f"\nMemory allocated: {torch.cuda.memory_allocated(0) / 1024**3:.2f} GB")
    print(f"Memory reserved: {torch.cuda.memory_reserved(0) / 1024**3:.2f} GB")
    
    # Test tensor operations
    print("\nTesting tensor operations...")
    x = torch.randn(1000, 1000).cuda()
    y = torch.randn(1000, 1000).cuda()
    z = torch.matmul(x, y)
    print("✓ GPU tensor operations working!")
else:
    print("\n⚠ GPU not available - will use CPU")

print("=" * 60)
```

Save as `test_gpu.py` and run:
```bash
python test_gpu.py
```

## Starting the Server

Once installed:

```bash
# Activate venv
source venv/bin/activate

# Start server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The first request will take longer as the model loads into GPU memory.

## Recommended ROCm Version

For your RX 7900 GRE (RDNA3 Navi 31 XL):
- **ROCm 6.1** (recommended for PyTorch stability)
- **ROCm 6.4.4** (latest as of Sept 2025, has newest features)
- **ROCm 6.0** (minimum - first to support 7900 GRE)
- **Avoid ROCm < 6.0** (no support for 7900 GRE)

## Need Help?

1. Check ROCm compatibility: https://rocm.docs.amd.com/
2. PyTorch ROCm builds: https://pytorch.org/get-started/locally/
3. AMD GPU community: https://community.amd.com/

## Summary

```bash
# Quick install script for AMD RX 7900 GRE
# (ROCm 6.0+ required, 6.1 recommended)

# Install PyTorch with ROCm 6.1
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/rocm6.1

# Install other dependencies
pip install -r requirements.txt

# Test GPU
python -c "import torch; print(f'GPU: {torch.cuda.get_device_name(0) if torch.cuda.is_available() else \"Not available\"}')"
```

**Key Points for RX 7900 GRE:**
- ✅ Supported since ROCm 6.0 (Feb 2024)
- ✅ Best stability with ROCm 6.1 + PyTorch
- ✅ Excellent for Gemma 2B (16GB VRAM, RDNA3)
- ✅ Expected: 100-200 tokens/second

Your RX 7900 GRE is excellent for running Gemma 2B! 🚀

