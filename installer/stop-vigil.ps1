# Used by the Vigil installer and uninstaller.
#
# Stop mode (default): ends every process whose executable lives under -AppDir, matched by
# the executable's full path and never by image name, so another program that happens to be
# called Vigil.exe or vigil-backend.exe elsewhere is left alone. Order: ask the tray windows
# to close, then end the tray processes (so the tray cannot restart the backend), then the
# backend, then wait up to -TimeoutSeconds for all of them to be gone.
#   exit 0  nothing under AppDir is running (any more)
#   exit 1  something under AppDir is still running after the timeout
#
# Port mode (-CheckPort N): looks at who listens on TCP port N.
#   exit 0  the port is free, or its owner is under AppDir
#   exit 2  another program owns it; "name (path)" is written to -OutFile when given

param(
    [Parameter(Mandatory = $true)][string]$AppDir,
    [int]$TimeoutSeconds = 15,
    [int]$CheckPort = 0,
    [string]$OutFile = ''
)

$ErrorActionPreference = 'SilentlyContinue'
$root = [System.IO.Path]::GetFullPath($AppDir).TrimEnd('\') + '\'

function Test-UnderApp([string]$path) {
    return $path -and $path.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-AppProcesses {
    Get-CimInstance Win32_Process | Where-Object { Test-UnderApp $_.ExecutablePath }
}

if ($CheckPort -gt 0) {
    $owner = Get-NetTCPConnection -LocalPort $CheckPort -State Listen | Select-Object -First 1
    if (-not $owner) { exit 0 }
    $proc = Get-Process -Id $owner.OwningProcess
    $path = $proc.Path
    if (Test-UnderApp $path) { exit 0 }
    if ($OutFile) {
        $name = if ($proc) { $proc.ProcessName } else { 'unknown' }
        $where = if ($path) { $path } else { 'path not readable' }
        Set-Content -Path $OutFile -Value "$name ($where)" -Encoding ASCII
    }
    exit 2
}

$all = @(Get-AppProcesses)
if ($all.Count -eq 0) { exit 0 }

# 1. Ask politely: close any tray window.
foreach ($p in $all) { (Get-Process -Id $p.ProcessId).CloseMainWindow() | Out-Null }
Start-Sleep -Seconds 2

# 2. Tray first, so it cannot respawn the backend, then everything else under AppDir.
$trayRoot = $root + 'tray\'
foreach ($p in @(Get-AppProcesses | Where-Object { $_.ExecutablePath.StartsWith($trayRoot, [System.StringComparison]::OrdinalIgnoreCase) })) {
    Stop-Process -Id $p.ProcessId -Force
}
Start-Sleep -Milliseconds 500
foreach ($p in @(Get-AppProcesses)) { Stop-Process -Id $p.ProcessId -Force }

# 3. Wait for them to be gone.
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
while ((Get-Date) -lt $deadline) {
    if (@(Get-AppProcesses).Count -eq 0) { exit 0 }
    Start-Sleep -Milliseconds 300
}
exit $(if (@(Get-AppProcesses).Count -eq 0) { 0 } else { 1 })
