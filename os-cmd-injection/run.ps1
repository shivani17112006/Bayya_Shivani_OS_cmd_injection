# One-command setup + run for Windows PowerShell.
# Usage: .\run.ps1

if (-not (Test-Path "venv")) {
    Write-Host "Creating virtual environment..."
    python -m venv venv
}

Write-Host "Activating virtual environment..."
.\venv\Scripts\Activate.ps1

Write-Host "Installing dependencies..."
pip install -r requirements.txt -q

Write-Host "Starting app at http://127.0.0.1:5000 ..."
python app.py
