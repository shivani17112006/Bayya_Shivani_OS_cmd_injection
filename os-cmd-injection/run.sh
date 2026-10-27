#!/usr/bin/env bash
# One-command setup + run for macOS/Linux.
# Usage: ./run.sh   (you may need: chmod +x run.sh)

set -e

if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

echo "Activating virtual environment..."
source venv/bin/activate

echo "Installing dependencies..."
pip install -r requirements.txt -q

echo "Starting app at http://127.0.0.1:5000 ..."
python app.py
