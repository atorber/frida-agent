@echo off
REM WeeBot 构建脚本
REM 用于编译 Frida 脚本并打包 Python 应用为可执行文件

echo ========================================
echo WeeBot 构建脚本
echo ========================================
echo.

REM 检查 Node.js 是否安装
where node >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [错误] 未找到 Node.js，请先安装 Node.js
    pause
    exit /b 1
)

REM 检查 Python 是否安装
where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [错误] 未找到 Python，请先安装 Python
    pause
    exit /b 1
)

REM 检查 PyInstaller 是否安装
python -c "import PyInstaller" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [信息] 正在安装 PyInstaller...
    pip install pyinstaller
)

echo [步骤 1/3] 编译 Frida 脚本...
cd ..
call npm run build
if %ERRORLEVEL% NEQ 0 (
    echo [错误] Frida 脚本编译失败
    pause
    exit /b 1
)
cd weebot

echo.
echo [步骤 2/3] 检查脚本文件...
if exist "..\dist\agent\wx391027\index.js" (
    echo [成功] 找到脚本文件: ..\dist\agent\wx391027\index.js
) else (
    echo [错误] 未找到脚本文件: ..\dist\agent\wx391027\index.js
    echo 请先运行: npm run build
    pause
    exit /b 1
)

echo.
echo [步骤 3/3] 使用 PyInstaller 打包...
pyinstaller WeeBot.spec
if %ERRORLEVEL% NEQ 0 (
    echo [错误] PyInstaller 打包失败
    pause
    exit /b 1
)

echo.
echo ========================================
echo 构建完成！
echo ========================================
echo 可执行文件位置: dist\WeeBot.exe
echo.
pause
