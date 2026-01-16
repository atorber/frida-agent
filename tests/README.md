# 测试脚本目录

本目录包含用于测试 Frida Agent 功能的测试脚本。

## 文件说明

### 回调测试服务器

- `test_callback_server.py` - Python 版本的回调测试服务器（推荐）
- `test_callback_server.js` - Node.js 版本的回调测试服务器
- `test_callback_server.ps1` - PowerShell 版本的回调测试服务器（Windows）
- `README_CALLBACK_TEST.md` - 回调测试服务器使用说明

### API 测试

- `test_api.py` - API 接口测试脚本

## 使用方法

### 回调测试服务器

详细使用方法请参考 [README_CALLBACK_TEST.md](./README_CALLBACK_TEST.md)

快速开始：

```bash
# Python 版本
python tests/test_callback_server.py

# Node.js 版本
node tests/test_callback_server.js

# PowerShell 版本（Windows）
.\tests\test_callback_server.ps1
```

### API 测试

```bash
python tests/test_api.py
```
