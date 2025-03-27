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

# Step 3: Delete existing venv
echo "Deleting existing virtual environment..."
rm -rf venv
echo "Cleared venv directory."

# Step 4: Recreate venv
echo "Creating new virtual environment..."
python3 -m venv venv || { echo "ERROR: Failed to create virtual environment"; read -p "Press Enter to continue..."; exit 1; }
echo "Done."

# Step 5: Activate venv and install dependencies
echo "Activating venv and installing dependencies..."
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt || { echo "ERROR: Failed to install dependencies"; read -p "Press Enter to continue..."; exit 1; }
echo "Done."

# Step 6: Reload .env by running Uvicorn
echo "Starting Uvicorn to reload .env..."
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
echo "If you see 'Application startup complete', the env is reloaded."

read -p "Press Enter to continue..."