#!/usr/bin/env bash
set -euo pipefail

# Bootstrap development environment (Linux / macOS)
python -c 'import sys; assert sys.version_info >= (3,10), "Python >= 3.10 required"'
python -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "Setup complete. Activate with: source .venv/bin/activate"
