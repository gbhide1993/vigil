"""Checks of the installer script and its helpers. The Inno Setup logic itself cannot be run
here without running the installer, so most of this is static: the script says what it must
say, and the helper scripts (version check, stop-by-path) are exercised for real."""

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "installer"
ISS = (INSTALLER / "vigil-setup.iss").read_text(encoding="utf-8")
BAT = (INSTALLER / "build.bat").read_text(encoding="utf-8")
STOP = INSTALLER / "stop-vigil.ps1"


def _section(name: str) -> str:
    match = re.search(rf"^\[{name}\]\s*$(.*?)(?=^\[|\Z)", ISS, re.S | re.M)
    return match.group(1) if match else ""


def _powershell(*args, timeout=120):
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(STOP), *map(str, args)],
        capture_output=True, text=True, timeout=timeout,
    )


# ------------------------------------------------------------------ versions

def _version_tree(tmp_path, iss="0.9.0", tray="0.9.0", backend="0.9.0"):
    (tmp_path / "installer").mkdir()
    (tmp_path / "tray").mkdir()
    (tmp_path / "backend").mkdir()
    (tmp_path / "installer" / "vigil-setup.iss").write_text(f'#define AppName "Vigil"\n#define AppVersion "{iss}"\n', encoding="utf-8")
    (tmp_path / "tray" / "package.json").write_text(json.dumps({"version": tray}), encoding="utf-8")
    (tmp_path / "backend" / "main.py").write_text(f'import os\nVERSION = "{backend}"\n', encoding="utf-8")
    return tmp_path


def _check(root, *extra):
    return subprocess.run(["node", str(INSTALLER / "check-version.js"), str(root), *extra], capture_output=True, text=True, timeout=30)


def test_the_three_versions_agree_in_the_repository():
    result = subprocess.run(["node", str(INSTALLER / "check-version.js"), "--print"], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "0.9.1"


def test_version_check_passes_and_prints_the_agreed_version(tmp_path):
    root = _version_tree(tmp_path)
    ok = _check(root, "--print")
    assert ok.returncode == 0 and ok.stdout.strip() == "0.9.0"


@pytest.mark.parametrize("which", ["iss", "tray", "backend"])
def test_version_check_fails_with_a_clear_message_when_any_one_differs(tmp_path, which):
    root = _version_tree(tmp_path, **{which: "0.2.10"})
    result = _check(root)
    assert result.returncode == 1
    assert "BUILD FAILED" in result.stderr and "differs between the installer, the tray and the backend" in result.stderr
    assert "0.2.10" in result.stderr and "0.9.0" in result.stderr


def test_build_bat_stops_on_a_version_mismatch_and_names_the_output_by_version():
    assert BAT.index("check-version.js") < BAT.index("pyinstaller.exe"), "checked before anything is built"
    assert "if errorlevel 1 goto error" in BAT.split("check-version.js", 1)[1].split("\n", 2)[1]
    assert "Vigil-Setup-%APP_VERSION%.exe" in BAT
    assert re.search(r'^OutputBaseFilename=Vigil-Setup-\{#AppVersion\}$', ISS, re.M)


def test_backend_and_tray_report_the_same_version_as_the_installer():
    backend = re.search(r'^VERSION = "([^"]+)"', (ROOT / "backend" / "main.py").read_text(encoding="utf-8"), re.M).group(1)
    tray = json.loads((ROOT / "tray" / "package.json").read_text(encoding="utf-8"))["version"]
    installer = re.search(r'^#define AppVersion "([^"]+)"', ISS, re.M).group(1)
    assert backend == tray == installer == "0.9.1"
    tray_main = (ROOT / "tray" / "main.js").read_text(encoding="utf-8")
    assert "const APP_VERSION = app.getVersion()" in tray_main and "label: `Vigil v${APP_VERSION}`" in tray_main
    assert "0.2.0-beta" not in tray_main


# ------------------------------------------------------------------ the script's content

def test_autostart_is_one_optional_per_user_entry():
    assert "Name: \"autostart\"; Description: \"Start Vigil when I sign in\"" in _section("Tasks")
    task_line = next(line for line in _section("Tasks").splitlines() if "autostart" in line)
    assert "unchecked" not in task_line, "checked by default"
    registry = _section("Registry")
    # no machine-wide or HKA autostart entry is written; the only HKLM Run line deletes the old one
    run_lines = [line for line in registry.splitlines() if "CurrentVersion\\Run" in line and not line.strip().startswith(";")]
    assert len(run_lines) == 1 and "HKLM" in run_lines[0] and "deletevalue" in run_lines[0]
    assert "ValueData" not in run_lines[0]
    assert 'AutostartValue "electron.app.Vigil"' in ISS
    assert "SetUserAutostart(WizardIsTaskSelected('autostart'))" in ISS
    assert "SetUserAutostart(False)" in ISS, "the uninstaller removes the per-user entry"
    code = _section("Code")
    assert "ExecAsOriginalUser(ExpandConstant('{sys}\\reg.exe')" in code, "per-user changes run as the account that started Setup"
    tray = (ROOT / "tray" / "main.js").read_text(encoding="utf-8")
    assert "setLoginItemSettings({ openAtLogin: true" not in tray, "the tray must not re-create the entry on every start"


def test_upgrade_stops_vigil_by_path_and_no_longer_says_uninstall_first():
    assert "uninstall it first" not in ISS.lower()
    code = _section("Code")
    assert "function PrepareToInstall" in code and "-TimeoutSeconds 15" in code
    assert "is in use by another program" in code and "Port {#BackendPort}" in code
    assert "CloseApplications=no" in ISS
    assert "vigil-port-check.txt" in code and "DeleteFile" in code
    delete = _section("InstallDelete")
    assert 'Name: "{app}\\frontend\\assets"' in delete
    assert "taskkill" not in ISS.lower() and "/IM" not in ISS and "UninstallRun" not in ISS


def test_uninstall_prompt_and_what_each_answer_removes():
    code = _section("Code")
    assert "MB_DEFBUTTON2" in code, "No is the default"
    for text in ("%LOCALAPPDATA%\\V-LAW", "evidence database, policy, license, logs and rotated logs", "%APPDATA%", "Yes:", "No:"):
        assert text in code
    assert "\\logs" not in code.replace("rotated logs", ""), "the dead logs sub-folder delete is gone"
    assert "rmdir /S /Q \"%LOCALAPPDATA%\\V-LAW\"" in code and "vigil-tray" in code
    assert "Your Vigil data was kept" in code


def test_no_policy_file_is_shipped_and_build_bat_cleans_assets_and_policy():
    assert "policy" not in _section("Files").lower().replace("stop-vigil", "")
    assert not (INSTALLER / "build" / "policy").exists()
    assert "for %%D in (tray backend frontend assets policy)" in BAT
    assert "manifest.js write" in BAT and "manifest.js check" in BAT, "the manifest the extension reads is a build output"
    assert ".sha256" in BAT and "Get-FileHash" in BAT
    backend_main = (ROOT / "backend" / "main.py").read_text(encoding="utf-8")
    assert "DEFAULT_POLICY" in backend_main, "the backend writes its own default policy, so a shipped copy was dead"


def test_no_hard_coded_developer_paths():
    for name, text in (("iss", ISS), ("bat", BAT), ("stop", STOP.read_text(encoding="utf-8"))):
        assert "gbhid" not in text and "C:\\Users" not in text, name


# --------------------------------------------------------- stop-vigil.ps1, run for real

def _copy_runner(folder: Path) -> Path:
    """A copy of cmd.exe named Vigil.exe that just waits, started from `folder`."""
    folder.mkdir(parents=True)
    exe = folder / "Vigil.exe"
    shutil.copy(Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe", exe)
    return exe


def _alive(proc) -> bool:
    return proc.poll() is None


def test_stop_script_matches_by_path_not_by_image_name(tmp_path):
    inside = _copy_runner(tmp_path / "app" / "tray")
    backend_dir = tmp_path / "app" / "backend"
    backend_dir.mkdir(parents=True)
    backend = backend_dir / "vigil-backend.exe"
    shutil.copy(Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe", backend)
    outside = _copy_runner(tmp_path / "elsewhere" / "tray")      # same image name, different folder
    wait = ["/c", "ping -n 25 127.0.0.1 > nul"]
    procs = [subprocess.Popen([str(p), *wait], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for p in (inside, backend, outside)]
    try:
        time.sleep(1)
        assert all(_alive(p) for p in procs)
        result = _powershell("-AppDir", tmp_path / "app", "-TimeoutSeconds", 15)
        assert result.returncode == 0, result.stdout + result.stderr
        assert not _alive(procs[0]) and not _alive(procs[1]), "everything under the install folder is stopped"
        assert _alive(procs[2]), "a Vigil.exe elsewhere is left alone"
    finally:
        import psutil

        for p in procs:
            try:
                for child in psutil.Process(p.pid).children(recursive=True):
                    child.kill()
            except psutil.NoSuchProcess:
                pass
            if _alive(p):
                p.kill()
            p.wait(timeout=20)


def test_stop_script_with_nothing_running_returns_zero_quickly(tmp_path):
    started = time.time()
    result = _powershell("-AppDir", tmp_path / "nothing-here", "-TimeoutSeconds", 15)
    assert result.returncode == 0 and time.time() - started < 30


def _listener():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    return sock, sock.getsockname()[1]


def test_port_check_reports_another_program_but_not_one_under_the_app_folder(tmp_path):
    sock, port = _listener()
    try:
        out = tmp_path / "owner.txt"
        other = _powershell("-AppDir", tmp_path / "app", "-CheckPort", port, "-OutFile", out)
        assert other.returncode == 2, other.stdout + other.stderr
        assert "python" in out.read_text(encoding="ascii").lower()
        under = _powershell("-AppDir", Path(sys.executable).parent, "-CheckPort", port)
        assert under.returncode == 0, "an owner under the app folder is not 'another program'"
    finally:
        sock.close()
    free = _powershell("-AppDir", tmp_path / "app", "-CheckPort", port)
    assert free.returncode == 0


def test_uninstall_yes_deletes_the_evidence_key_folder_and_no_keeps_it():
    """The evidence anchor counter lives in %LOCALAPPDATA%\\V-LAW\\keys. Yes removes it with the database (a
    fresh install then starts a clean series); No keeps it and says so. Static check only: the Pascal code
    has not been run (see the manual checks in the report)."""
    code = _section("Code")
    yes_branch = code[code.index("if MsgBox(Question"):code.index("else\n      MsgBox('Your Vigil data was kept")]
    assert 'rmdir /S /Q "%LOCALAPPDATA%\\V-LAW\\keys"' in yes_branch
    assert 'rmdir /S /Q "%LOCALAPPDATA%\\V-LAW"' in yes_branch
    assert "MB_YESNO or MB_DEFBUTTON2" in code, "No stays the default"
    assert "the keys folder that holds the evidence anchor records" in code
    assert "including its keys folder" in code[code.index("Your Vigil data was kept"):]
    # the backend's key folder really is that folder: next to the data folder, inside V-LAW
    main_py = (ROOT / "backend" / "main.py").read_text(encoding="utf-8")
    assert 'os.path.join(os.path.dirname(os.path.abspath(os.environ["VLAW_DATA_DIR"])), "keys")' in main_py
    assert 'os.environ.setdefault("VLAW_DATA_DIR", os.path.join(BASE_DIR, "data"))' in main_py
