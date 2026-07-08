@echo off
echo Building V-LAW installer...

echo Step 1: Building backend exe...
cd ..\backend
call .venv\Scripts\pyinstaller.exe vlaw-backend.spec --clean
if errorlevel 1 goto error

echo Step 2: Building tray exe...
cd ..\tray
call npm run build
if errorlevel 1 goto error

echo Step 3: Copying artifacts to installer/build...
cd ..\installer
xcopy /E /Y /I ..\tray\dist\win-unpacked\* build\tray\
xcopy /Y ..\backend\dist\vlaw-backend.exe build\backend\
xcopy /E /Y /I ..\tray\assets\* build\assets\

echo Step 4: Compiling installer...
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" vlaw-setup.iss
if errorlevel 1 goto error

echo Done. Installer at installer\output\VLaw-Setup.exe
goto end

:error
echo BUILD FAILED
exit /b 1

:end
