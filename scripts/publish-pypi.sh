#!/usr/bin/env bash
set -e

echo "================================================================"
echo "📦 SwishOS agentic-redteam PyPI Release & Upload Script"
echo "================================================================"

# 1. Clean previous build artifacts
echo "\n[1/4] Cleaning build artifacts..."
rm -rf dist/ build/ *.egg-info

# 2. Build Python wheel and tarball
echo "\n[2/4] Building wheel and source distribution..."
python3 -m build

# 3. Check distribution metadata
echo "\n[3/4] Validating metadata with twine check..."
twine check dist/*

# 4. Upload to PyPI
echo "\n[4/4] Uploading to PyPI (twine upload)..."
echo "Note: Ensure your PYPI_API_TOKEN is set or provide PyPI credentials at the prompt."
twine upload dist/*

echo "\n✅ Release successfully uploaded to PyPI!"
echo "Users can now run: pip install agentic-redteam"
