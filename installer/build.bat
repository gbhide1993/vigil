@echo off
setlocal
cd /d "%~dp0"
echo Building Vigil installer...

echo Step 0: Checking that the installer, tray and backend versions agree...
node check-version.js
if errorlevel 1 goto error
for /f "delims=" %%V in ('node check-version.js --print') do set APP_VERSION=%%V

echo Step 0b: Cleaning build folders...
for %%D in (tray backend frontend assets policy) do (
    if exist build\%%D rmdir /S /Q build\%%D
)
mkdir build\tray
mkdir build\backend
mkdir build\frontend
mkdir build\assets

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
if errorlevel 1 goto error
copy /Y ..\backend\dist\vlaw-backend.exe build\backend\vigil-backend.exe
if errorlevel 1 goto error
xcopy /E /Y /I ..\tray\assets\* build\assets\
if errorlevel 1 goto error
xcopy /E /Y /I ..\frontend\dist\* build\frontend\
if errorlevel 1 goto error

echo Step 4: Compiling installer...
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" vigil-setup.iss
if errorlevel 1 goto error

echo Step 5: Writing SHA256 of the installer...
powershell -NoProfile -Command "$f='output\Vigil-Setup-%APP_VERSION%.exe'; $h=(Get-FileHash $f -Algorithm SHA256).Hash; Set-Content -Path ($f + '.sha256') -Value ($h + '  ' + (Split-Path $f -Leaf)) -Encoding ASCII; Write-Host $h"
if errorlevel 1 goto error

echo Step 6: Writing manifest.json next to the installer (a build output only, nothing is uploaded)...
node manifest.js write "output\Vigil-Setup-%APP_VERSION%.exe" %APP_VERSION% output\manifest.json
if errorlevel 1 goto error

echo Step 7: Checking the manifest against the installer and the version...
node manifest.js check output\manifest.json "output\Vigil-Setup-%APP_VERSION%.exe" %APP_VERSION%
if errorlevel 1 goto error

echo Done. Installer at installer\output\Vigil-Setup-%APP_VERSION%.exe
echo SHA256 at installer\output\Vigil-Setup-%APP_VERSION%.exe.sha256
echo Manifest at installer\output\manifest.json
goto end

:error
echo BUILD FAILED
exit /b 1

:end
