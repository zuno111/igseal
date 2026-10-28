# -*- mode: python ; coding: utf-8 -*-
# igSeal 제작기 (사장님 도구). onefile, GUI. .igs 전용 파일을 출력.
import os
from PyInstaller.utils.hooks import collect_all

ROOT = os.path.abspath(os.path.join(os.getcwd(), '..'))
SRC = os.path.join(ROOT, 'src')

datas = []
# 뷰어 스텁이 있으면 내장(레거시 exe 봉인 모드용). 없어도 .igs 모드는 정상 동작.
STUB = os.path.join(ROOT, 'build', 'dist', 'igSeal-Viewer.exe')
if os.path.isfile(STUB):
    datas.append((STUB, '.'))
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
