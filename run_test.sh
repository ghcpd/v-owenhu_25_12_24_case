#!/bin/bash
set -e
echo "Running security audit tests..."
if [ -d "venv" ]; then
    source venv/bin/activate
fi
python auto_test.py
