# WeeBot Python

## 快速开始

### 环境安装及检查

1. 微信版本 3.9.10.27
2. Python版本 3.7+

### 安装依赖

```shell
pip install frida
pip install frida-tools
```

### 启动

```shell
python main.py
```

## 接口说明

### 获取登录用户信息

### 获取联系人列表

### 发送消息

```bash
pyinstaller --onefile --add-data "xp-3.9.10.27.js;." maiWeeBotn.py

pyinstaller --onefile --windowed --add-data "xp-3.9.10.27.js;." WeeBot.py

pyinstaller --onefile --windowed --noconsole --add-data "xp-3.9.10.27.js;." WeeBot.py

```
