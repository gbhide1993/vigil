@echo off
echo [Vigil] Checking for existing instance...
FOR /F "tokens=5" %%P IN ('netstat -ano ^| findstr ":7422 " ^| findstr "LISTENING"') DO (
    echo [Vigil] Stopping existing process %%P...
    TaskKill /PID %%P /F >nul 2>&1
)
timeout /t 3 /nobreak >nul

echo [Vigil] Starting backend...
cd /d "%~dp0backend" && python run_native.py
