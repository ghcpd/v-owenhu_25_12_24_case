#!/bin/bash

# Bootstrap script for Linux/macOS

# Install Python if not present (assuming apt or brew)
if ! command -v python3 &> /dev/null; then
    echo "Installing Python3..."
    if command -v apt &> /dev/null; then
        sudo apt update && sudo apt install -y python3 python3-pip
    elif command -v brew &> /dev/null; then
        brew install python3
    else
        echo "Please install Python3 manually."
        exit 1
    fi
fi

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

echo "Setup complete."