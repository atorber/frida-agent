"""WeeBot - 微信机器人 GUI 客户端.

使用 subprocess 调用 frida CLI 来加载脚本，避免脚本格式解析问题。
"""
from datetime import datetime
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

import tkinter as tk
from tkinter import messagebox, scrolledtext

# Agent HTTP API 地址
API_BASE_URL = "http://127.0.0.1:19088"

# 全局变量
log_queue = queue.Queue()  # 线程安全的日志队列
frida_process = None  # frida 子进程
frida_thread = None  # 读取 frida 输出的线程
stop_monitoring = False  # 停止监控标志
custom_script_path = None  # 用户自定义的脚本路径


def log(message):
    """日志记录函数."""
    log_queue.put(message)


def check_log_queue():
    """检查队列中的日志消息，并更新GUI."""
    try:
        while True:
            message = log_queue.get_nowait()
            update_gui(message)
    except queue.Empty:
        pass
    root.after(100, check_log_queue)


def update_gui(message):
    """更新GUI日志显示."""
    debug_text.config(state=tk.NORMAL)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    debug_text.insert(tk.END, f"[{timestamp}] {message}\n")
    debug_text.config(state=tk.DISABLED)
    debug_text.yview(tk.END)


def resource_path(relative_path):
    """获取资源的绝对路径（支持 PyInstaller 打包）."""
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


def find_script_path():
    """查找 Frida 脚本文件路径.

    查找顺序：
    1. 用户自定义路径（如果设置了）
    2. 环境变量 FRIDA_SCRIPT_PATH（如果设置了）
    3. 默认搜索路径（PyInstaller 打包路径、开发环境路径等）
    """
    # 1. 优先使用用户自定义路径
    if custom_script_path:
        abs_path = os.path.abspath(custom_script_path)
        if os.path.exists(abs_path):
            return abs_path
        log(f"警告: 自定义脚本路径不存在: {abs_path}")

    # 2. 检查环境变量
    env_path = os.environ.get('FRIDA_SCRIPT_PATH')
    if env_path:
        abs_path = os.path.abspath(env_path)
        if os.path.exists(abs_path):
            return abs_path
        log(f"警告: 环境变量 FRIDA_SCRIPT_PATH 指定的路径不存在: {abs_path}")

    # 3. 默认搜索路径
    # 获取当前程序运行目录
    if getattr(sys, 'frozen', False):
        # PyInstaller 打包后的可执行文件
        current_dir = os.path.dirname(sys.executable)
    else:
        # 开发环境，使用脚本所在目录
        current_dir = os.path.dirname(os.path.abspath(__file__))

    script_paths = [
        # 当前程序运行文件夹下的 agent/wx391027/index.js（优先）
        os.path.join(current_dir, "agent", "wx391027", "index.js"),
        # PyInstaller 打包后的路径（兼容旧版本）
        resource_path("dist/agent/wx391027/index.js"),
        # 开发环境路径（兼容旧版本）
        os.path.join(
            os.path.dirname(__file__),
            "..", "dist", "agent", "wx391027", "index.js"
        ),
        # 项目根目录路径（兼容旧版本）
        os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "dist", "agent", "wx391027", "index.js"
        ),
    ]

    for path in script_paths:
        abs_path = os.path.abspath(path)
        if os.path.exists(abs_path):
            return abs_path

    return None


def check_frida_installed():
    """检查 frida CLI 是否已安装."""
    frida_cmd = shutil.which('frida')
    if not frida_cmd:
        return False, None
    return True, frida_cmd


def check_wechat_running():
    """检查 WeChat.exe 是否正在运行."""
    try:
        result = subprocess.run(
            ['tasklist', '/FI', 'IMAGENAME eq WeChat.exe'],
            capture_output=True,
            text=True,
            timeout=5
        )
        return 'WeChat.exe' in result.stdout
    except Exception:
        return False


def api_request(method, path, data=None, query=None):
    """调用 Agent HTTP API."""
    try:
        url = f"{API_BASE_URL}{path}"
        if query:
            url += "?" + urllib.parse.urlencode(query)

        req = urllib.request.Request(url)
        req.add_header('Content-Type', 'application/json')

        if method == 'POST' and data:
            data_bytes = json.dumps(data).encode('utf-8')
            req.add_header('Content-Length', str(len(data_bytes)))
            response = urllib.request.urlopen(req, data_bytes, timeout=10)
        else:
            response = urllib.request.urlopen(req, timeout=10)

        result = json.loads(response.read().decode('utf-8'))
        return result
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8')
        try:
            error_data = json.loads(error_body)
            return error_data
        except Exception:
            msg = f'HTTP {e.code}: {e.reason}'
            return {'code': 0, 'msg': msg, 'data': None}
    except Exception as e:
        return {'code': 0, 'msg': str(e), 'data': None}


def read_frida_output(process):
    """在单独线程中读取 frida 进程的输出."""
    global stop_monitoring
    try:
        # 使用二进制模式读取，然后手动解码为 UTF-8
        for line_bytes in iter(process.stdout.readline, b''):
            if stop_monitoring:
                break
            if line_bytes:
                try:
                    # 尝试 UTF-8 解码
                    line = line_bytes.decode('utf-8', errors='replace')
                except Exception:
                    # 如果 UTF-8 失败，尝试使用系统默认编码
                    try:
                        default_enc = sys.getdefaultencoding()
                        line = line_bytes.decode(default_enc, errors='replace')
                    except Exception:
                        # 最后尝试 latin-1（不会失败）
                        line = line_bytes.decode('latin-1', errors='replace')

                # 移除换行符并记录日志
                line = line.rstrip('\n\r')
                if line:
                    log(f"[Frida] {line}")
    except Exception as e:
        if not stop_monitoring:
            log(f"读取 Frida 输出异常: {str(e)}")
    finally:
        if process.stdout:
            process.stdout.close()


def monitor_api_health():
    """监控 API 健康状态（在后台线程中运行）."""
    global stop_monitoring
    max_attempts = 30  # 最多尝试 30 次（30 秒）
    attempt = 0

    while not stop_monitoring and attempt < max_attempts:
        time.sleep(1)
        attempt += 1

        try:
            result = api_request('GET', '/api/health')
            if result.get('code') == 1:
                log("✓ API 服务已就绪")
                # 刷新推送配置显示
                root.after(0, refresh_push_config)
                return True
        except Exception:
            # API 还未启动，继续等待
            pass

    if attempt >= max_attempts:
        log("⚠ API 服务启动超时，请检查日志")
    return False


def start_script():
    """启动 Frida 脚本（使用 frida CLI）."""
    global frida_process, frida_thread, stop_monitoring

    try:
        # 1. 检查 frida CLI 是否安装
        frida_installed, frida_cmd = check_frida_installed()
        if not frida_installed:
            error_msg = (
                "未找到 frida CLI 工具。\n\n"
                "请安装 frida-tools:\n"
                "  pip install frida-tools\n\n"
                "或者确保 frida 命令在系统 PATH 中。"
            )
            messagebox.showerror("错误", error_msg)
            log(error_msg)
            return

        log(f"找到 frida CLI: {frida_cmd}")

        # 2. 检查 WeChat 是否运行
        if not check_wechat_running():
            error_msg = (
                "未找到 WeChat.exe 进程。\n\n"
                "请先启动微信，然后再点击'启动'按钮。"
            )
            messagebox.showerror("错误", error_msg)
            log(error_msg)
            return

        log("检测到 WeChat.exe 进程")

        # 3. 查找脚本文件
        script_path = find_script_path()
        if not script_path:
            # 获取当前程序运行目录用于提示
            if getattr(sys, 'frozen', False):
                current_dir = os.path.dirname(sys.executable)
            else:
                current_dir = os.path.dirname(os.path.abspath(__file__))
            default_path = os.path.join(
                current_dir, "agent", "wx391027", "index.js"
            )
            error_msg = (
                "未找到 Frida 脚本文件。\n\n"
                f"请确保脚本文件存在于以下位置之一：\n"
                f"1. {default_path}\n"
                f"2. 或通过 GUI 设置自定义路径\n"
                f"3. 或设置环境变量 FRIDA_SCRIPT_PATH\n\n"
                "如果使用默认路径，请先运行: npm run build"
            )
            messagebox.showerror("错误", error_msg)
            log(error_msg)
            return

        log(f"找到脚本文件: {script_path}")

        # 4. 启动 frida 进程
        log("正在启动 frida 进程...")
        stop_monitoring = False

        frida_process = subprocess.Popen(
            ['frida', '-l', script_path, 'WeChat.exe'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1  # 行缓冲模式
        )

        # 5. 启动线程读取输出
        frida_thread = threading.Thread(
            target=read_frida_output,
            args=(frida_process,),
            daemon=True
        )
        frida_thread.start()

        log("Frida 进程已启动，等待 Agent 初始化...")

        # 6. 在后台线程中监控 API 健康状态
        health_thread = threading.Thread(
            target=monitor_api_health,
            daemon=True
        )
        health_thread.start()

        # 7. 更新 UI 状态
        start_button.config(state=tk.DISABLED)
        stop_button.config(state=tk.NORMAL)
        push_config_frame.pack(pady=5)  # 显示推送配置界面

    except FileNotFoundError:
        error_msg = (
            "未找到 frida 命令。\n\n"
            "请确保已安装 frida-tools:\n"
            "  pip install frida-tools"
        )
        messagebox.showerror("错误", error_msg)
        log(error_msg)
    except Exception as e:
        error_msg = f"启动失败: {str(e)}"
        messagebox.showerror("错误", error_msg)
        log(error_msg)
        log(f"详细错误: {traceback.format_exc()}")


def stop_script():
    """停止 Frida 脚本."""
    global frida_process, frida_thread, stop_monitoring

    try:
        stop_monitoring = True

        if frida_process:
            log("正在停止 frida 进程...")
            frida_process.terminate()

            # 等待进程结束（最多 5 秒）
            try:
                frida_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # 如果 5 秒内未结束，强制终止
                log("进程未响应，强制终止...")
                frida_process.kill()
                frida_process.wait()

            frida_process = None
            log("Frida 进程已停止")

        if frida_thread:
            frida_thread.join(timeout=2)
            frida_thread = None

        # 更新 UI 状态
        start_button.config(state=tk.NORMAL)
        stop_button.config(state=tk.DISABLED)
        push_config_frame.pack_forget()  # 隐藏推送配置界面

    except Exception as e:
        log(f"停止失败: {str(e)}")
        messagebox.showerror("错误", f"停止失败: {str(e)}")


def get_push_config():
    """获取当前推送配置."""
    try:
        result = api_request('GET', '/api/push/config')
        if result.get('code') == 1:
            config = result.get('data', {})
            return config
        else:
            msg = result.get('msg', '未知错误')
            log(f"获取推送配置失败: {msg}")
            return None
    except Exception as e:
        log(f"获取推送配置异常: {str(e)}")
        return None


def set_push_config():
    """设置推送配置."""
    try:
        enabled = push_enabled_var.get()
        callback_url = callback_url_entry.get().strip()

        if enabled and not callback_url:
            messagebox.showerror("错误", "开启推送时必须提供回调地址")
            return

        if callback_url and not (
            callback_url.startswith('http://') or
            callback_url.startswith('https://')
        ):
            messagebox.showerror(
                "错误",
                "回调地址格式不正确，"
                "应为 http:// 或 https:// 开头的完整 URL"
            )
            return

        data = {
            'enabled': enabled,
            'callbackUrl': callback_url if enabled else ''
        }

        log(f"设置推送配置: enabled={enabled}, "
            f"callbackUrl={callback_url}")
        result = api_request('POST', '/api/push/config', data=data)

        if result.get('code') == 1:
            config = result.get('data', {})
            config_str = json.dumps(config, ensure_ascii=False)
            log(f"推送配置设置成功: {config_str}")
            status = '开启' if enabled else '关闭'
            messagebox.showinfo("成功", f"推送配置已{status}")
        else:
            error_msg = result.get('msg', '未知错误')
            log(f"设置推送配置失败: {error_msg}")
            messagebox.showerror("失败", f"设置推送配置失败: {error_msg}")
    except Exception as e:
        log(f"设置推送配置异常: {str(e)}")
        messagebox.showerror("异常", f"设置推送配置时发生异常: {str(e)}")


def refresh_push_config():
    """刷新推送配置显示."""
    config = get_push_config()
    if config:
        push_enabled_var.set(config.get('enabled', False))
        callback_url_entry.delete(0, tk.END)
        callback_url_entry.insert(0, config.get('callbackUrl', ''))


def browse_script_path():
    """浏览并选择脚本文件."""
    global custom_script_path
    from tkinter import filedialog

    file_path = filedialog.askopenfilename(
        title="选择 Frida 脚本文件",
        filetypes=[
            ("JavaScript files", "*.js"),
            ("All files", "*.*")
        ],
        initialdir=os.path.dirname(__file__) if __file__ else "."
    )

    if file_path:
        abs_path = os.path.abspath(file_path)
        if os.path.exists(abs_path):
            custom_script_path = abs_path
            if 'script_path_entry' in globals():
                script_path_entry.delete(0, tk.END)
                script_path_entry.insert(0, abs_path)
            log(f"已设置自定义脚本路径: {abs_path}")
            messagebox.showinfo("成功", f"脚本路径已设置:\n{abs_path}")
        else:
            messagebox.showerror("错误", f"文件不存在:\n{abs_path}")


def clear_script_path():
    """清除自定义脚本路径，使用默认搜索."""
    global custom_script_path
    custom_script_path = None
    if 'script_path_entry' in globals():
        script_path_entry.delete(0, tk.END)
        script_path_entry.insert(0, "(使用默认搜索路径)")
    log("已清除自定义脚本路径，将使用默认搜索路径")
    messagebox.showinfo("成功", "已清除自定义脚本路径")


def apply_script_path():
    """应用脚本路径设置."""
    global custom_script_path
    if 'script_path_entry' not in globals():
        return
    path = script_path_entry.get().strip()

    if not path or path == "(使用默认搜索路径)":
        clear_script_path()
        return

    abs_path = os.path.abspath(path)
    if os.path.exists(abs_path):
        custom_script_path = abs_path
        log(f"已应用脚本路径: {abs_path}")
        messagebox.showinfo("成功", f"脚本路径已应用:\n{abs_path}")
    else:
        messagebox.showerror("错误", f"文件不存在:\n{abs_path}")


# 创建主窗口
root = tk.Tk()
root.title("WeeBot - 微信机器人")

# 启动检查队列的循环
root.after(0, check_log_queue)

# 创建主框架
main_frame = tk.Frame(root)
main_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

# 创建控制按钮框架
control_frame = tk.Frame(main_frame)
control_frame.pack(pady=5)

# 创建启动 Frida 脚本的按钮
start_button = tk.Button(
    control_frame, text="启动", command=start_script, width=10
)
start_button.pack(side=tk.LEFT, padx=5)

# 创建停止 Frida 脚本的按钮
stop_button = tk.Button(
    control_frame,
    text="停止",
    command=stop_script,
    width=10,
    state=tk.DISABLED
)
stop_button.pack(side=tk.LEFT, padx=5)

# 创建脚本路径配置框架
script_path_frame = tk.LabelFrame(
    main_frame, text="Frida 脚本路径配置", padx=10, pady=10
)
script_path_frame.pack(pady=5, fill=tk.X, padx=10)

# 脚本路径输入框
script_path_input_frame = tk.Frame(script_path_frame)
script_path_input_frame.pack(fill=tk.X, pady=5)

tk.Label(script_path_input_frame, text="脚本路径:").pack(
    side=tk.LEFT, padx=5
)
script_path_entry = tk.Entry(script_path_input_frame, width=60)
script_path_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
script_path_entry.insert(0, "(使用默认搜索路径)")

# 脚本路径按钮
script_path_button_frame = tk.Frame(script_path_frame)
script_path_button_frame.pack(pady=5)

browse_button = tk.Button(
    script_path_button_frame,
    text="浏览...",
    command=browse_script_path,
    width=12
)
browse_button.pack(side=tk.LEFT, padx=5)

apply_button = tk.Button(
    script_path_button_frame,
    text="应用",
    command=apply_script_path,
    width=12
)
apply_button.pack(side=tk.LEFT, padx=5)

clear_button = tk.Button(
    script_path_button_frame,
    text="清除（使用默认）",
    command=clear_script_path,
    width=15
)
clear_button.pack(side=tk.LEFT, padx=5)

# 提示信息
script_path_hint = tk.Label(
    script_path_frame,
    text="提示: 留空将使用默认搜索路径，或设置环境变量 FRIDA_SCRIPT_PATH",
    fg="gray",
    font=("TkDefaultFont", 8)
)
script_path_hint.pack(pady=2)

# 创建推送配置框架（初始隐藏）
push_config_frame = tk.LabelFrame(
    main_frame, text="消息推送配置", padx=10, pady=10
)
# 不立即 pack，等启动后再显示

# 推送开关
push_enabled_var = tk.BooleanVar()
push_enabled_checkbox = tk.Checkbutton(
    push_config_frame,
    text="启用消息推送",
    variable=push_enabled_var
)
push_enabled_checkbox.pack(anchor=tk.W, pady=2)

# 回调地址输入
callback_url_frame = tk.Frame(push_config_frame)
callback_url_frame.pack(fill=tk.X, pady=5)

tk.Label(callback_url_frame, text="回调地址:").pack(
    side=tk.LEFT, padx=5
)
callback_url_entry = tk.Entry(callback_url_frame, width=50)
callback_url_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
callback_url_entry.insert(0, "http://127.0.0.1:8888")  # 默认值

# 推送配置按钮
push_button_frame = tk.Frame(push_config_frame)
push_button_frame.pack(pady=5)

set_push_button = tk.Button(
    push_button_frame,
    text="设置推送配置",
    command=set_push_config,
    width=15
)
set_push_button.pack(side=tk.LEFT, padx=5)

refresh_push_button = tk.Button(
    push_button_frame,
    text="刷新配置",
    command=refresh_push_config,
    width=15
)
refresh_push_button.pack(side=tk.LEFT, padx=5)

# 创建用于显示调试输出的滚动文本框
debug_frame = tk.LabelFrame(main_frame, text="日志输出")
debug_frame.pack(pady=10, fill=tk.BOTH, expand=True)

debug_text = scrolledtext.ScrolledText(
    debug_frame, state=tk.DISABLED, width=80, height=20
)
debug_text.pack(pady=5, padx=5, fill=tk.BOTH, expand=True)


def on_closing():
    """关闭程序时的清理操作."""
    if messagebox.askokcancel("退出", "确定退出?"):
        stop_script()
        root.quit()
        root.destroy()


root.protocol("WM_DELETE_WINDOW", on_closing)

# 启动日志
log("WeeBot 已启动")
log("请点击'启动'按钮开始附加到微信进程")
log(f"Agent API 地址: {API_BASE_URL}")

# 打印默认脚本路径
if getattr(sys, 'frozen', False):
    current_dir = os.path.dirname(sys.executable)
else:
    current_dir = os.path.dirname(os.path.abspath(__file__))
default_script_path = os.path.join(
    current_dir, "agent", "wx391027", "index.js"
)
log(f"默认脚本路径: {default_script_path}")
if os.path.exists(default_script_path):
    log("✓ 默认脚本文件存在")
else:
    log("⚠ 默认脚本文件不存在，可通过 GUI 设置自定义路径")

# 启动Tkinter主循环
root.mainloop()
