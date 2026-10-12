@echo off
echo Starting Vigil Native Setup...

:: Check if backend folder exists
if not exist "backend" (
    echo [ERROR] 'backend' folder not found! Are you in the root project folder?
    pause
    exit /b
)

cd backend
echo Navigating to backend...

:: Ensure dependencies
pip install -r requirements.txt

:: Launch the native runner
echo Launching Vigil...
python run_native.py

pause