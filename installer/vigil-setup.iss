; Vigil Installer
; Inno Setup 6.x
;
; The version below must equal tray/package.json and VERSION in backend/main.py;
; build.bat runs check-version.js and stops if they differ.

#define AppName "Vigil"
#define AppVersion "0.9.0"
#define AppPublisher "Vvault Technologies"
#define AppURL "https://getvvault.com/vigil"
#define AppExeName "Vigil.exe"
#define BackendExeName "vigil-backend.exe"
#define BackendPort "7422"
; Name of the per-user Run value. It is the one Electron's setLoginItemSettings used to write
; (electron.app.<name>), so an upgrade replaces the old entry instead of adding a second one.
#define AutostartValue "electron.app.Vigil"

[Setup]
AppId={{8F4A2B1C-3D9E-4F7A-B2C5-1E6D8A3F9B4C}
AppName={#AppName}
AppVersion={#AppVersion}
VersionInfoVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=output
OutputBaseFilename=Vigil-Setup-{#AppVersion}
SetupIconFile=build\assets\app_icon.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
; Setup stops Vigil itself, by executable path, in PrepareToInstall below.
CloseApplications=no
RestartApplications=no
UninstallDisplayIcon={app}\tray\{#AppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "autostart"; Description: "Start Vigil when I sign in"; GroupDescription: "Startup:"
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
; Tray app (Electron)
Source: "build\tray\*"; DestDir: "{app}\tray"; Flags: ignoreversion recursesubdirs createallsubdirs

; Backend exe
Source: "build\backend\{#BackendExeName}"; DestDir: "{app}\backend"; Flags: ignoreversion

; Frontend (React app, served by backend)
Source: "build\frontend\*"; DestDir: "{app}\frontend"; Flags: ignoreversion recursesubdirs createallsubdirs

; Stops Vigil by executable path. One copy is unpacked for the installer, one is installed
; for the uninstaller.
Source: "stop-vigil.ps1"; Flags: dontcopy
Source: "stop-vigil.ps1"; DestDir: "{app}\tools"; Flags: ignoreversion

[InstallDelete]
; Old hashed frontend files (index-*.js, index-*.css) would otherwise pile up across upgrades.
Type: filesandordirs; Name: "{app}\frontend\assets"
; Earlier versions installed a default policy file here that the backend never read.
Type: filesandordirs; Name: "{app}\policy"

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\tray\{#AppExeName}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{commondesktop}\{#AppName}"; Filename: "{app}\tray\{#AppExeName}"; Tasks: desktopicon

[Registry]
; Lets every client (VS Code extension, JetBrains plugin, CLI) find Vigil
; via one registry key instead of hardcoded paths.
Root: HKA; Subkey: "Software\Vigil"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey

; Earlier versions also started Vigil from a machine-wide entry. Remove it so the per-user
; entry written below (when the task is chosen) is the only autostart entry.
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueName: "Vigil"; Flags: deletevalue

[Run]
; Launch Vigil after install
Filename: "{app}\tray\{#AppExeName}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent

[Code]
const
  RunKey = 'Software\Microsoft\Windows\CurrentVersion\Run';

var
  StopScript: String;

function PowerShellExe: String;
begin
  Result := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
end;

// Runs stop-vigil.ps1 (unpacked for the installer, installed for the uninstaller).
function RunStopScript(const Script, Arguments: String): Integer;
var
  ResultCode: Integer;
begin
  if not Exec(PowerShellExe,
      '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + Script + '" ' + Arguments,
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    ResultCode := -1;
  Result := ResultCode;
end;

// Per-user autostart. Setup runs elevated, and when the person installing is a standard user who
// typed an administrator's password, "HKCU" and %LOCALAPPDATA% belong to that administrator, not to
// the person who will use Vigil. So the per-user steps run as the account that started Setup
// (ExecAsOriginalUser), which is the account that signs in to use Vigil.
procedure SetUserAutostart(Enable: Boolean);
var
  ResultCode: Integer;
  Command: String;
begin
  if Enable then
    Command := 'add "HKCU\' + RunKey + '" /v {#AutostartValue} /t REG_SZ /d "\"' + ExpandConstant('{app}\tray\{#AppExeName}') + '\"" /f'
  else
    Command := 'delete "HKCU\' + RunKey + '" /v {#AutostartValue} /f';
  if not ExecAsOriginalUser(ExpandConstant('{sys}\reg.exe'), Command, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Log('Could not change the per-user autostart entry');
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  // Left behind by earlier installers (they wrote the port check result to %TEMP%).
  DeleteFile(AddBackslash(GetEnv('TEMP')) + 'vigil-port-check.txt');
end;

// Runs after the wizard, with the final install folder known and before any file is replaced.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
  Owner: AnsiString;
  OwnerFile: String;
begin
  Result := '';
  ExtractTemporaryFile('stop-vigil.ps1');
  StopScript := ExpandConstant('{tmp}\stop-vigil.ps1');

  // 1. Stop Vigil: every process whose executable is under {app} (matched by path, not by name).
  Code := RunStopScript(StopScript, '-AppDir "' + ExpandConstant('{app}') + '" -TimeoutSeconds 15');
  if Code <> 0 then
  begin
    Result := 'Setup could not stop the running Vigil within 15 seconds.' + #13#10 +
              'Quit Vigil from its tray icon (right-click, Quit Vigil) and run Setup again.';
    Exit;
  end;

  // 2. Port {#BackendPort} must be free, or owned by Vigil under {app} (already stopped above).
  OwnerFile := ExpandConstant('{tmp}\port-owner.txt');
  Code := RunStopScript(StopScript, '-AppDir "' + ExpandConstant('{app}') + '" -CheckPort {#BackendPort} -OutFile "' + OwnerFile + '"');
  if Code = 2 then
  begin
    Owner := '';
    LoadStringFromFile(OwnerFile, Owner);
    Result := 'Port {#BackendPort} is in use by another program' +
              ' (' + Trim(String(Owner)) + ').' + #13#10 +
              'Vigil needs port {#BackendPort}. Close that program and run Setup again.';
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    SetUserAutostart(WizardIsTaskSelected('autostart'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
  Question: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    // Files are still in place here. Stop Vigil by path, then remove this user's autostart entry.
    RunStopScript(ExpandConstant('{app}\tools\stop-vigil.ps1'), '-AppDir "' + ExpandConstant('{app}') + '" -TimeoutSeconds 15');
    SetUserAutostart(False);
  end;

  if CurUninstallStep = usPostUninstall then
  begin
    Question :=
      'Vigil has been removed. Do you also want to delete everything Vigil stored on this PC?' + #13#10 + #13#10 +
      'Yes: deletes the whole folder %LOCALAPPDATA%\V-LAW (the evidence database, policy, license, logs and rotated logs, and backups, ' +
      'and the keys folder that holds the evidence anchor records) ' +
      'and Vigil''s settings folder under %APPDATA%. A new install then starts a fresh evidence series. This cannot be undone.' + #13#10 + #13#10 +
      'No: keeps all of it, the keys folder included. Reinstalling Vigil later picks it up again.';
    if MsgBox(Question, mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
    begin
      // As the original user, so %LOCALAPPDATA% and %APPDATA% are that user's, not the elevated account's.
      // The evidence anchor counter and install id live in %LOCALAPPDATA%\V-LAW\keys (backend VLAW_KEY_DIR,
      // the folder next to "data"). It is deleted here together with the database, on purpose: a database
      // without its key folder is a clean start, a key folder without its database is reported as a
      // restarted series. The keys folder is named explicitly so this stays true if the folder delete is
      // ever narrowed.
      ExecAsOriginalUser(ExpandConstant('{cmd}'),
        '/C rmdir /S /Q "%LOCALAPPDATA%\V-LAW\keys" & rmdir /S /Q "%LOCALAPPDATA%\V-LAW" & rmdir /S /Q "%APPDATA%\vigil-tray" & rmdir /S /Q "%APPDATA%\vlaw-tray"',
        '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    end
    else
      MsgBox('Your Vigil data was kept:' + #13#10 +
             '  %LOCALAPPDATA%\V-LAW (including its keys folder)' + #13#10 +
             '  %APPDATA%\vigil-tray' + #13#10 +
             'Delete those folders yourself if you no longer need them.', mbInformation, MB_OK);
  end;
end;
