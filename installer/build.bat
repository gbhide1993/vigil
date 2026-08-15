@echo off
echo Building Vigil installer...

echo Step 0: Cleaning build folders...
rmdir /S /Q build\tray 2>nul
rmdir /S /Q build\backend 2>nul
rmdir /S /Q build\frontend 2>nul
mkdir build\tray
mkdir build\backend
mkdir build\frontend

echo Step 1: Building backend exe...
cd ..\backend
call .venv\Scripts\pyinstaller.exe vlaw-backend.spec --clean
if errorlevel 1 goto error

echo Step 2: Building tray exe...
cd ..\tray
call npm run build
if errorlevel 1 goto error

echo Step 2b: Building frontend...
cd ..\frontend
call npm run build
if errorlevel 1 goto error

del /F /Q ..\tray\dist\win-unpacked\V-LAW.exe 2>nul
echo Removed legacy V-LAW.exe

echo Step 3: Copying artifacts to installer/build...
cd ..\installer
xcopy /E /Y /I ..\tray\dist\win-unpacked\* build\tray\
xcopy /Y ..\backend\dist\vlaw-backend.exe build\backend\vigil-backend.exe
xcopy /E /Y /I ..\tray\assets\* build\assets\
xcopy /E /Y /I ..\frontend\dist\* build\frontend\

echo Step 4: Compiling installer...
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" vigil-setup.iss
if errorlevel 1 goto error

echo Step 5: Generating manifest.json...
for /f "delims=" %%V in ('node -e "console.log(require('../tray/package.json').version)"') do set APP_VERSION=%%V

for /f "tokens=1-3 delims=/ " %%a in ('powershell -NoProfile -Command "Get-Date -Format yyyy-MM-dd"') do set RELEASE_DATE=%%a

for /f "skip=1 tokens=1" %%H in ('certutil -hashfile output\Vigil-Setup.exe SHA256 ^| findstr /v "hash"') do (
    if not defined FILE_SHA256 set FILE_SHA256=%%H
)

for %%F in (output\Vigil-Setup.exe) do set FILE_BYTES=%%~zF
set /a FILE_MB=%FILE_BYTES% / 1048576

(
echo {
echo   "version": "%APP_VERSION%",
echo   "released": "%RELEASE_DATE%",
echo   "win_x64": {
echo     "url": "https://download.getvvault.com/Vigil-Setup.exe",
echo     "sha256": "%FILE_SHA256%",
echo     "size_mb": %FILE_MB%
echo   }
echo }
) > output\manifest.json

echo Done. Installer at installer\output\Vigil-Setup.exe
echo Manifest at installer\output\manifest.json
goto end

:error
echo BUILD FAILED
exit /b 1

:end
