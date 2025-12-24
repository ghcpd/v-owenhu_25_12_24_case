#!/bin/bash

# Linux/macOS setup script
set -e

echo "Setting up Python security audit environment..."

# Create virtual environment
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "Virtual environment created"
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

# Create logs directory
mkdir -p logs

echo "Setup complete. Run './run_test.sh' to execute tests."
