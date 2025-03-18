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

:: Step 3: Activate venv (assumes venv exists)
echo Activating virtual environment...
if not exist venv (
    echo ERROR: venv directory not found. Creating one...
    python -m venv venv
)
call venv\Scripts\activate || (
    echo ERROR: Failed to activate virtual environment
    pause
    exit /b 1
)
echo Done.

:: Step 4: Install dependencies
echo Installing dependencies...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt || (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)
echo Done.

:: Step 5: Run Uvicorn with no cache
echo Starting Uvicorn with cleared cache...
python -m uvicorn agents-service.agents_service:app --host 0.0.0.0 --port 8000 --reload
echo If you see "Application startup complete", Uvicorn is running.

pause