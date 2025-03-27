#!/bin/bash

# Set project directory to the location of the script
PROJECT_DIR=$(dirname "$0")
cd "$PROJECT_DIR" || { echo "ERROR: Could not change to project directory $PROJECT_DIR"; read -p "Press Enter to continue..."; exit 1; }

# Step 1: Stop any running Uvicorn processes
echo "Stopping any running Uvicorn processes..."
pkill -f uvicorn
echo "Done."

# Step 2: Clear __pycache__ directories
echo "Clearing __pycache__ directories..."
find . -type d -name "__pycache__" -exec rm -r {} +
echo "Done."

# Step 3: Activate venv (create if not exists)
echo "Activating virtual environment..."
if [ ! -d "venv" ]; then
    echo "ERROR: venv directory not found. Creating one..."
    python3 -m venv venv
fi
source venv/bin/activate || { echo "ERROR: Failed to activate virtual environment"; read -p "Press Enter to continue..."; exit 1; }
echo "Done."

# Step 4: Install dependencies
echo "Installing dependencies..."
python -m pip install --upgrade pip
python -m pip install -r requirements.txt || { echo "ERROR: Failed to install dependencies"; read -p "Press Enter to continue..."; exit 1; }
echo "Done."

# Step 5: Run Uvicorn with no cache
echo "Starting Uvicorn with cleared cache..."
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
echo "If you see 'Application startup complete', Uvicorn is running."

read -p "Press Enter to continue..."