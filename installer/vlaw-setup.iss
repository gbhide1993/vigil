; V-LAW Installer
; Inno Setup 6.x

#define AppName "V-LAW"
#define AppVersion "0.2.0-beta"
#define AppPublisher "Vvault Technologies"
#define AppURL "https://getvvault.com"
#define AppExeName "V-LAW.exe"
#define BackendExeName "vlaw-backend.exe"

[Setup]
AppId={{8F4A2B1C-3D9E-4F7A-B2C5-1E6D8A3F9B4C}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=output
OutputBaseFilename=VLaw-Setup
SetupIconFile=build\assets\app_icon.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes
RestartApplications=no
UninstallDisplayIcon={app}\tray\{#AppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
; Tray app (Electron)
Source: "build\tray\*"; DestDir: "{app}\tray"; Flags: ignoreversion recursesubdirs createallsubdirs

; Backend exe
Source: "build\backend\{#BackendExeName}"; DestDir: "{app}\backend"; Flags: ignoreversion

; Frontend (React app, served by backend)
Source: "build\frontend\*"; DestDir: "{app}\frontend"; Flags: ignoreversion recursesubdirs createallsubdirs

; Default policy
Source: "build\policy\vlaw-policy.json"; DestDir: "{app}\policy"; Flags: ignoreversion onlyifdoesntexist

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\tray\{#AppExeName}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{commondesktop}\{#AppName}"; Filename: "{app}\tray\{#AppExeName}"; Tasks: desktopicon

[Registry]
; Auto-launch on Windows startup. HKA resolves to HKLM when running
; elevated (our case, since PrivilegesRequired=admin) and HKCU otherwise,
; so the entry always lands in the correct hive for the install context.
Root: HKA; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "VLAW"; ValueData: """{app}\tray\{#AppExeName}"""; Flags: uninsdeletevalue

; Lets every client (VS Code extension, JetBrains plugin, CLI) find Vigil
; via one registry key instead of hardcoded paths.
Root: HKCU; Subkey: "Software\Vigil"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey

[Run]
; Launch V-LAW after install
Filename: "{app}\tray\{#AppExeName}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Kill both processes before uninstall
Filename: "taskkill"; Parameters: "/F /IM {#AppExeName}"; Flags: runhidden waituntilterminated; RunOnceId: "KillTray"
Filename: "taskkill"; Parameters: "/F /IM {#BackendExeName}"; Flags: runhidden waituntilterminated; RunOnceId: "KillBackend"

[UninstallDelete]
; Clean up user data directories (log, db) — ask first
Type: filesandordirs; Name: "{app}\data"
Type: filesandordirs; Name: "{app}\logs"

[Code]
// Port conflict check before install
function CheckPort7422Free: Boolean;
var
  ResultCode: Integer;
begin
  Exec('cmd.exe', '/C netstat -ano | findstr ":7422 " > "%TEMP%\vlaw-port-check.txt"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := (ResultCode <> 0);  // findstr returns 0 if found, 1 if not
  if not Result then
    MsgBox('Port 7422 is already in use on this machine.' + #13#10 +
           'Please close any other application using port 7422 and try again.' + #13#10 +
           'If V-LAW is already installed and running, uninstall it first.',
           mbError, MB_OK);
end;

function InitializeSetup(): Boolean;
begin
  Result := CheckPort7422Free();
end;
