# -*- mode: python ; coding: utf-8 -*-


import os

# 获取项目根目录（weebot 的父目录）
# spec 文件位于 weebot 目录，所以父目录是项目根目录
try:
    # PyInstaller 5.0+ 使用 SPECPATH
    spec_dir = os.path.dirname(os.path.abspath(SPECPATH))
except NameError:
    # 旧版本或直接运行，使用当前目录
    spec_dir = os.path.dirname(os.path.abspath(__file__))

root_dir = os.path.dirname(spec_dir)  # weebot 的父目录

# 使用新的脚本路径
script_paths = []
new_script = os.path.join(root_dir, 'dist', 'agent', 'wx391027', 'index.js')

if os.path.exists(new_script):
    script_paths.append((new_script, 'dist/agent/wx391027/'))
else:
    # 如果脚本不存在，打印警告但继续（构建时会报错）
    print(f"警告: 未找到脚本文件: {new_script}")
    print("请先运行: npm run build")

a = Analysis(
    ['WeeBot.py'],
    pathex=[],
    binaries=[],
    datas=script_paths,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='WeeBot',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
