# vlaw-backend.spec
import os

import reportlab
from PyInstaller.utils.hooks import collect_submodules

reportlab_path = os.path.dirname(reportlab.__file__)

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
    'fastapi.staticfiles',
    'fastapi.responses',
    'aiofiles',
]
hiddenimports += collect_submodules('reportlab')
hiddenimports += [
    'reportlab',
    'reportlab.pdfgen',
    'reportlab.pdfgen.canvas',
    'reportlab.lib',
    'reportlab.lib.pagesizes',
    'reportlab.lib.units',
    'reportlab.lib.colors',
    'reportlab.lib.styles',
    'reportlab.pdfbase',
    'reportlab.pdfbase.pdfmetrics',
    'reportlab.pdfbase.ttfonts',
    'reportlab.pdfbase._fontdata',
    'reportlab.pdfbase._fontdata_enc_winansi',
    'reportlab.pdfbase._fontdata_enc_macroman',
    'reportlab.pdfbase._fontdata_enc_standard',
    'reportlab.pdfbase._fontdata_enc_symbol',
    'reportlab.pdfbase._fontdata_enc_zapfdingbats',
    'reportlab.pdfbase._fontdata_enc_pdfdoc',
    'reportlab.pdfbase._fontdata_enc_macexpert',
]

# Data files to bundle (read-only assets). The default policy JSON is
# generated at first run from DEFAULT_POLICY in main.py, so no policy/
# template needs to be bundled. reportlab's own package directory is
# bundled too — PyInstaller's static import analysis misses it because
# export.py imports it lazily inside the function body, and reportlab
# itself needs its font-metrics/encoding data files present on disk at
# runtime, not just importable.
datas = [
    ('db/schema.sql', 'db'),
    (reportlab_path, 'reportlab'),
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
        # PIL was previously excluded to shrink the bundle, but
        # reportlab.lib.utils imports it unconditionally at module load
        # (from PIL import Image) even though this app never generates
        # images in its PDFs — excluding it broke PDF export entirely.
        'tkinter', 'matplotlib', 'numpy', 'pandas',
        'cv2', 'torch', 'tensorflow',
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
