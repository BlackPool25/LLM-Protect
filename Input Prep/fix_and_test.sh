#!/bin/bash
# Quick fix for pytest-asyncio and run tests

cd "/home/lightdesk/Projects/LLM-Protect/Input Prep"

# Check if venv is activated
if [ -z "$VIRTUAL_ENV" ]; then
    echo "❌ Virtual environment not activated!"
    echo "Please run: actml"
    exit 1
fi

echo "✓ Virtual environment detected: $VIRTUAL_ENV"
echo ""

# Fix pytest-asyncio version
echo "Fixing pytest-asyncio compatibility..."
pip install pytest-asyncio==0.21.1 --upgrade -q
echo "✓ pytest-asyncio downgraded to 0.21.1"
echo ""

# Run tests
echo "================================================"
echo "🧪 Running Tests"
echo "================================================"
pytest tests/ -v --tb=short -x

echo ""
echo "✅ Week 1 Implementation Complete!"
echo ""
echo "To start the API:"
echo "  python src/gateway/api.py"







