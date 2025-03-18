@echo off
setlocal EnableDelayedExpansion

:: Set project directory to the location of the batch file
set PROJECT_DIR=%~dp0
cd /d %PROJECT_DIR% || (
    echo ERROR: Could not change to project directory %PROJECT_DIR%
    pause
    exit /b 1
)

:: Step 1: Stop any running Uvicorn processes
echo Stopping any running Python processes...
taskkill /IM python.exe /F 2>nul
echo Done.

:: Step 2: Clear __pycache__ directories
echo Clearing __pycache__ directories...
for /r %%d in (__pycache__) do (
    if exist "%%d" (
        rmdir /s /q "%%d"
        echo Cleared: %%d
    )
)
echo Done.

:: Step 3: Delete existing venv
echo Deleting existing virtual environment...
if exist venv (
    rmdir /s /q venv
    echo Cleared venv directory.
) else (
    echo No venv directory found, skipping.
)

:: Step 4: Recreate venv
echo Creating new virtual environment...
python -m venv venv || (
    echo ERROR: Failed to create virtual environment
    pause
    exit /b 1
)
echo Done.

:: Step 5: Activate venv and install dependencies
echo Activating venv and installing dependencies...
call venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt || (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)
echo Done.

:: Step 6: Reload .env by running Uvicorn
echo Starting Uvicorn to reload .env...
python -m uvicorn agents-service.agents_service:app --host 0.0.0.0 --port 8000 --reload
echo If you see "Application startup complete", the env is reloaded.

pause