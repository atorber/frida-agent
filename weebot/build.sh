#!/bin/bash
# WeeBot 构建脚本
# 用于编译 Frida 脚本并打包 Python 应用为可执行文件

set -e

echo "========================================"
echo "WeeBot 构建脚本"
echo "========================================"
echo ""

# 检查 Node.js 是否安装
if ! command -v node &> /dev/null; then
    echo "[错误] 未找到 Node.js，请先安装 Node.js"
    exit 1
fi

# 检查 Python 是否安装
if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    echo "[错误] 未找到 Python，请先安装 Python"
    exit 1
fi

# 检查 PyInstaller 是否安装
if ! python3 -c "import PyInstaller" 2>/dev/null && ! python -c "import PyInstaller" 2>/dev/null; then
    echo "[信息] 正在安装 PyInstaller..."
    pip3 install pyinstaller || pip install pyinstaller
fi

echo "[步骤 1/4] 编译 Frida 脚本..."
cd ..
npm run build
cd weebot

echo ""
echo "[步骤 2/4] 检查并同步脚本文件..."
if [ -f "../dist/agent/wx391027/index.js" ]; then
    echo "[成功] 找到脚本文件: ../dist/agent/wx391027/index.js"
    mkdir -p agent/wx391027
    cp -f "../dist/agent/wx391027/index.js" "agent/wx391027/index.js"
    echo "[成功] 已同步到 weebot/agent/wx391027/index.js"
else
    echo "[错误] 未找到脚本文件: ../dist/agent/wx391027/index.js"
    echo "请先运行: npm run build"
    exit 1
fi

echo ""
echo "[步骤 3/4] 使用 PyInstaller 打包..."
python3 -m PyInstaller WeeBot.spec || python -m PyInstaller WeeBot.spec

echo ""
echo "[步骤 4/4] 完成"
echo "========================================"
echo "构建完成！"
echo "========================================"
echo "可执行文件位置: dist/WeeBot.exe (Windows) 或 dist/WeeBot (Linux/Mac)"
echo ""
