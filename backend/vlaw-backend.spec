# vlaw-backend.spec
from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

hiddenimports = []
hiddenimports += collect_submodules('uvicorn')
hiddenimports += collect_submodules('fastapi')
hiddenimports += collect_submodules('aiosqlite')
hiddenimports += collect_submodules('watchdog')
hiddenimports += collect_submodules('psutil')
hiddenimports += collect_submodules('apscheduler')
hiddenimports += collect_submodules('multipart')
hiddenimports += [
    'uvicorn.logging',
    'uvicorn.loops',
    'uvicorn.loops.auto',
    'uvicorn.protocols',
    'uvicorn.protocols.http',
    'uvicorn.protocols.http.auto',
    'uvicorn.lifespan',
    'uvicorn.lifespan.on',
    'aiosqlite',
    'sqlite3',
    'watchdog.observers',
    'watchdog.observers.polling',
    'psutil._pswindows',
]

# Data files to bundle (read-only assets). The default policy JSON is
# generated at first run from DEFAULT_POLICY in main.py, so no policy/
# template needs to be bundled.
datas = [
    ('db/schema.sql', 'db'),
]

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter', 'matplotlib', 'numpy', 'pandas',
        'PIL', 'cv2', 'torch', 'tensorflow',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='vlaw-backend',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,          # UPX can cause false positives in Windows Defender
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,       # Keep True for now — shows log output
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
    version=None,
)
