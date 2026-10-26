# -*- mode: python ; coding: utf-8 -*-
# igSeal 제작기 (사장님 도구). onefile, GUI. 뷰어 스텁 exe 를 데이터로 내장.
import os
from PyInstaller.utils.hooks import collect_all

ROOT = os.path.abspath(os.path.join(os.getcwd(), '..'))
SRC = os.path.join(ROOT, 'src')
STUB = os.path.join(ROOT, 'build', 'dist', 'igSeal-Viewer.exe')
if not os.path.isfile(STUB):
    raise SystemExit('뷰어 스텁이 없습니다. viewer.spec 를 먼저 빌드하세요: ' + STUB)

datas = [(STUB, '.')]   # _MEIPASS/igSeal-Viewer.exe 로 들어감
binaries, hidden = [], []
for pkg in ['cryptography']:
    try:
        d, b, h = collect_all(pkg)
        datas += d; binaries += b; hidden += h
    except Exception as e:
        print('skip', pkg, e)

a = Analysis(
    [os.path.join(SRC, 'igseal_packager.py')],
    pathex=[SRC],
    binaries=binaries,
    datas=datas,
    hiddenimports=hidden + ['igseal_core', 'tkinter', 'tkinter.ttk', 'tkinter.filedialog'],
    excludes=['matplotlib', 'PyQt5', 'PyQt6', 'PySide2', 'PySide6', 'PIL', 'numpy', 'pytest'],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name='igSeal-Packager',
    console=False,
    disable_windowed_traceback=False,
    upx=False,
)
