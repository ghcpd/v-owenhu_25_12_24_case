#!/usr/bin/env bash
set -euo pipefail

python -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Run a quick dependency audit and IaC scan (optional but recommended)
if command -v pip-audit >/dev/null 2>&1; then
  pip-audit || true
fi
if command -v checkov >/dev/null 2>&1; then
  checkov -d . || true
fi

echo "Setup complete. Activate with: source .venv/bin/activate"
