# -*- mode: python ; coding: utf-8 -*-
# igSeal 뷰어 스텁 (거래처가 받는 봉인 exe의 베이스). onefile, GUI(console=False).
import os
from PyInstaller.utils.hooks import collect_all

ROOT = os.path.abspath(os.path.join(os.getcwd(), '..'))
SRC = os.path.join(ROOT, 'src')

datas, binaries, hidden = [], [], []
for pkg in ['PIL', 'fitz', 'pymupdf', 'cryptography']:
    try:
        d, b, h = collect_all(pkg)
        datas += d; binaries += b; hidden += h
    except Exception as e:
        print('skip', pkg, e)

a = Analysis(
    [os.path.join(SRC, 'igseal_viewer.py')],
    pathex=[SRC],
    binaries=binaries,
    datas=datas,
    hiddenimports=hidden + ['igseal_core', 'PIL._tkinter_finder', 'tkinter', 'tkinter.ttk'],
    excludes=['matplotlib', 'PyQt5', 'PyQt6', 'PySide2', 'PySide6', 'numpy.f2py', 'pytest'],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name='igSeal-Viewer',
    console=False,
    disable_windowed_traceback=False,
    upx=False,
)
