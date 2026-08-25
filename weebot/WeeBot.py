"""WeeBot - 微信机器人 GUI 客户端.

使用 subprocess 调用 frida CLI 来加载脚本，避免脚本格式解析问题。
"""
from datetime import datetime
import json
import os
import queue
import shutil
import signal
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
# Apps Server 消息 Hook（与 server/README 对齐）
DEFAULT_CALLBACK_URL = "http://127.0.0.1:19089/apps/hook"
# 日志窗口最多保留行数，避免长时间运行内存膨胀
MAX_LOG_LINES = 2000
# Windows ACCESS_VIOLATION
WIN_STATUS_ACCESS_VIOLATION = 0xC0000005

# 全局变量
log_queue = queue.Queue()  # 线程安全的日志队列
frida_process = None  # frida/node 子进程
frida_thread = None  # 读取输出的线程
watch_thread = None  # 监控进程退出的线程
frida_stdin = None  # 保持 stdin 打开，避免 frida REPL 因 EOF 退出
stop_monitoring = False  # 停止监控标志
custom_script_path = None  # 用户自定义的脚本路径
launch_mode = None  # 'node' | 'frida' | 'reuse'
_ui_reset_lock = threading.Lock()


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
    root.after(150, check_log_queue)


def update_gui(message):
    """更新GUI日志显示（限长）."""
    debug_text.config(state=tk.NORMAL)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    debug_text.insert(tk.END, f"[{timestamp}] {message}\n")
    # 超出上限时删掉头部落后行
    try:
        end_index = debug_text.index('end-1c')
        line_count = int(float(end_index.split('.')[0]))
        if line_count > MAX_LOG_LINES:
            debug_text.delete('1.0', f'{line_count - MAX_LOG_LINES}.0')
    except Exception:
        pass
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
    1. 用户自定义路径 / 环境变量 FRIDA_SCRIPT_PATH
    2. 开发态：优先仓库 dist/agent/wx391027/index.js（最新编译产物）
    3. 打包态：exe 旁路 agent/、以及 PyInstaller 内嵌 dist/
    4. weebot/agent/ 捆绑副本（兼容旧分发）
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

    weebot_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(weebot_dir)
    frozen = getattr(sys, 'frozen', False)

    if frozen:
        exe_dir = os.path.dirname(sys.executable)
        script_paths = [
            # 打包后：exe 同目录旁路脚本（便于热更新）
            os.path.join(exe_dir, "agent", "wx391027", "index.js"),
            # PyInstaller 内嵌
            resource_path("dist/agent/wx391027/index.js"),
            resource_path("agent/wx391027/index.js"),
        ]
    else:
        # 开发态：优先最新 dist，避免误用 weebot/agent 过期副本
        script_paths = [
            os.path.join(repo_root, "dist", "agent", "wx391027", "index.js"),
            os.path.join(weebot_dir, "..", "dist", "agent", "wx391027", "index.js"),
            os.path.join(weebot_dir, "agent", "wx391027", "index.js"),
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


def find_node_cmd():
    """查找 node 可执行文件."""
    return shutil.which('node')


def find_start_js():
    """查找仓库内带优雅退出的 start.js（优先于裸 frida -l）."""
    weebot_dir = os.path.dirname(os.path.abspath(__file__))
    abs_path = os.path.abspath(
        os.path.join(weebot_dir, "..", "agent", "wx391027", "tools", "start.js")
    )
    if os.path.exists(abs_path):
        return abs_path
    return None


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


def agent_already_ready():
    """Agent HTTP 是否已在监听（避免重复注入导致崩溃）."""
    result = api_request('GET', '/api/health')
    return isinstance(result, dict) and result.get('code') == 1


def format_exit_code(code):
    """把 Windows 退出码解释成人话."""
    if code is None:
        return "unknown"
    u = code & 0xFFFFFFFF
    if u == WIN_STATUS_ACCESS_VIOLATION:
        return (
            f"{code} (0xC0000005 ACCESS_VIOLATION)\n"
            "常见原因：\n"
            "1) 微信进程里已有残留 Frida Agent，重复注入冲突 —— 请完全退出微信后重开再启动\n"
            "2) 未以管理员运行 WeeBot / 终端\n"
            "3) 杀软拦截注入\n"
            "4) 微信未完全登录到主界面就注入\n"
            "建议：优先使用仓库 `npm run start:wx391027`（Node start.js）"
        )
    if u == 0xC000013A:
        return f"{code} (Ctrl+C / 控制台关闭)"
    if code == 0:
        return "0 (正常退出)"
    return f"{code} (0x{u:08X})"


def api_request(method, path, data=None, query=None):
    """调用 Agent HTTP API（显式 method，正确关闭连接）."""
    try:
        url = f"{API_BASE_URL}{path}"
        if query:
            url += "?" + urllib.parse.urlencode(query)

        body = None
        headers = {'Content-Type': 'application/json'}
        if data is not None:
            body = json.dumps(data).encode('utf-8')
            headers['Content-Length'] = str(len(body))

        req = urllib.request.Request(
            url,
            data=body,
            headers=headers,
            method=method.upper(),
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            raw = response.read().decode('utf-8')
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8')
        try:
            return json.loads(error_body)
        except Exception:
            msg = f'HTTP {e.code}: {e.reason}'
            return {'code': 0, 'msg': msg, 'data': None}
    except Exception as e:
        return {'code': 0, 'msg': str(e), 'data': None}


def read_frida_output(process):
    """在单独线程中读取 frida 进程的输出."""
    global stop_monitoring
    try:
        for line_bytes in iter(process.stdout.readline, b''):
            if stop_monitoring:
                break
            if line_bytes:
                try:
                    line = line_bytes.decode('utf-8', errors='replace')
                except Exception:
                    try:
                        default_enc = sys.getdefaultencoding()
                        line = line_bytes.decode(default_enc, errors='replace')
                    except Exception:
                        line = line_bytes.decode('latin-1', errors='replace')

                line = line.rstrip('\n\r')
                if line:
                    log(f"[Frida] {line}")
    except Exception as e:
        if not stop_monitoring:
            log(f"读取 Frida 输出异常: {str(e)}")
    finally:
        if process.stdout:
            process.stdout.close()


def reset_ui_after_exit(reason="Frida 进程已退出"):
    """进程异常/正常退出后复位 UI（须在主线程调用）."""
    global frida_process, frida_thread, watch_thread, frida_stdin, stop_monitoring, launch_mode
    with _ui_reset_lock:
        stop_monitoring = True
        if frida_stdin is not None:
            try:
                frida_stdin.close()
            except Exception:
                pass
        frida_stdin = None
        frida_process = None
        frida_thread = None
        watch_thread = None
        launch_mode = None
        try:
            start_button.config(state=tk.NORMAL)
            stop_button.config(state=tk.DISABLED)
            push_config_frame.pack_forget()
        except Exception:
            pass
        log(reason)


def watch_frida_process(process):
    """后台等待 frida 子进程结束，自动复位 UI."""
    global stop_monitoring
    try:
        code = process.wait()
        if not stop_monitoring:
            detail = format_exit_code(code)
            root.after(
                0,
                lambda: reset_ui_after_exit(
                    f"⚠ 注入进程已退出: {detail}\n请按提示处理后重新点击「启动」"
                ),
            )
    except Exception as e:
        if not stop_monitoring:
            root.after(
                0,
                lambda: reset_ui_after_exit(f"⚠ 监控注入进程异常: {e}"),
            )


def monitor_api_health():
    """监控 API 健康状态（在后台线程中运行）."""
    global stop_monitoring
    max_attempts = 45
    attempt = 0

    while not stop_monitoring and attempt < max_attempts:
        time.sleep(1)
        attempt += 1

        try:
            result = api_request('GET', '/api/health')
            if result.get('code') == 1:
                log("✓ API 服务已就绪")
                root.after(0, refresh_push_config)
                return True
        except Exception:
            pass

    if attempt >= max_attempts and not stop_monitoring:
        log("⚠ API 服务启动超时，请检查日志；可点「停止」后完全退出微信再重试")
    return False


def mark_ui_running():
    """标记为已运行并显示推送配置."""
    start_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)
    push_config_frame.pack(pady=5)


def start_script():
    """启动 Agent：优先复用已就绪 → Node start.js → frida CLI."""
    global frida_process, frida_thread, watch_thread, frida_stdin, stop_monitoring, launch_mode

    try:
        if not check_wechat_running():
            error_msg = (
                "未找到 WeChat.exe 进程。\n\n"
                "请先启动微信并登录到主界面，然后再点击「启动」。"
            )
            messagebox.showerror("错误", error_msg)
            log(error_msg)
            return

        log("检测到 WeChat.exe 进程")

        # 已有 Agent 在跑：不要重复注入（重复注入极易 ACCESS_VIOLATION）
        if agent_already_ready():
            launch_mode = 'reuse'
            stop_monitoring = False
            log("✓ 检测到 Agent API 已在 19088 就绪，跳过重复注入")
            mark_ui_running()
            root.after(0, refresh_push_config)
            return

        script_path = find_script_path()
        if not script_path:
            weebot_dir = os.path.dirname(os.path.abspath(__file__))
            repo_dist = os.path.abspath(
                os.path.join(weebot_dir, "..", "dist", "agent", "wx391027", "index.js")
            )
            error_msg = (
                "未找到 Frida 脚本文件。\n\n"
                f"请确保脚本文件存在于：\n"
                f"1. {repo_dist}（推荐，开发态优先）\n"
                f"2. 或通过 GUI 设置自定义路径\n"
                f"3. 或设置环境变量 FRIDA_SCRIPT_PATH\n\n"
                "请先运行: npm run build"
            )
            messagebox.showerror("错误", error_msg)
            log(error_msg)
            return

        log(f"找到脚本文件: {script_path}")

        node_cmd = find_node_cmd()
        start_js = find_start_js()
        frida_installed, frida_cmd = check_frida_installed()

        stop_monitoring = False
        creationflags = 0
        if os.name == 'nt':
            # 便于之后发 CTRL_BREAK 做优雅停止
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

        # 优先 Node start.js（与 npm run start:wx391027 一致，更稳）
        if node_cmd and start_js:
            launch_mode = 'node'
            log(f"使用 Node 启动器: {start_js}")
            env = os.environ.copy()
            # start.js 内脚本路径固定指向 dist；确保与 find 到的一致时可提示
            frida_process = subprocess.Popen(
                [node_cmd, start_js],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
                env=env,
                cwd=os.path.dirname(start_js),
                creationflags=creationflags,
            )
            frida_stdin = frida_process.stdin
        elif frida_installed:
            launch_mode = 'frida'
            log(f"使用 frida CLI: {frida_cmd}")
            log("提示: 推荐安装 Node 后用仓库 start.js，稳定性更好")
            # -n 按进程名附加；保持 stdin 打开，避免 REPL 因管道 EOF 退出
            frida_process = subprocess.Popen(
                [frida_cmd, '-l', script_path, '-n', 'WeChat.exe'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
                creationflags=creationflags,
            )
            frida_stdin = frida_process.stdin
        else:
            error_msg = (
                "未找到可用的启动方式。\n\n"
                "请安装其一：\n"
                "1) Node.js（推荐，配合 agent/wx391027/tools/start.js）\n"
                "2) pip install frida-tools\n"
            )
            messagebox.showerror("错误", error_msg)
            log(error_msg)
            return

        frida_thread = threading.Thread(
            target=read_frida_output,
            args=(frida_process,),
            daemon=True
        )
        frida_thread.start()

        watch_thread = threading.Thread(
            target=watch_frida_process,
            args=(frida_process,),
            daemon=True
        )
        watch_thread.start()

        log(f"注入进程已启动 (mode={launch_mode})，等待 Agent 初始化...")

        health_thread = threading.Thread(
            target=monitor_api_health,
            daemon=True
        )
        health_thread.start()

        mark_ui_running()

    except FileNotFoundError:
        error_msg = (
            "未找到 frida/node 命令。\n\n"
            "请安装 frida-tools 或 Node.js。"
        )
        messagebox.showerror("错误", error_msg)
        log(error_msg)
    except Exception as e:
        error_msg = f"启动失败: {str(e)}"
        messagebox.showerror("错误", error_msg)
        log(error_msg)
        log(f"详细错误: {traceback.format_exc()}")
        reset_ui_after_exit("启动失败，已复位")


def stop_script():
    """停止注入进程."""
    global frida_process, frida_thread, watch_thread, frida_stdin, stop_monitoring, launch_mode

    try:
        stop_monitoring = True
        proc = frida_process
        mode = launch_mode

        if mode == 'reuse':
            log("当前为复用已有 Agent，停止仅断开 WeeBot 关联（不卸载微信内 Agent）")
            launch_mode = None
            start_button.config(state=tk.NORMAL)
            stop_button.config(state=tk.DISABLED)
            push_config_frame.pack_forget()
            return

        if proc:
            log("正在停止注入进程...")
            # Node start.js：尽量发 CTRL_BREAK / SIGINT 触发优雅关 HTTP
            if mode == 'node' and os.name == 'nt':
                try:
                    proc.send_signal(signal.CTRL_BREAK_EVENT)
                except Exception:
                    pass
            elif mode == 'node':
                try:
                    proc.send_signal(signal.SIGINT)
                except Exception:
                    pass

            if frida_stdin is not None:
                try:
                    frida_stdin.close()
                except Exception:
                    pass
                frida_stdin = None

            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                log("进程未响应，强制终止...")
                proc.kill()
                proc.wait()
            except Exception as e:
                log(f"终止进程时: {e}")
                try:
                    proc.kill()
                except Exception:
                    pass
            frida_process = None
            log("注入进程已停止（若微信内仍占用 19088，请完全退出微信再开）")

        if frida_thread:
            frida_thread.join(timeout=2)
            frida_thread = None
        watch_thread = None
        launch_mode = None

        start_button.config(state=tk.NORMAL)
        stop_button.config(state=tk.DISABLED)
        push_config_frame.pack_forget()

    except Exception as e:
        log(f"停止失败: {str(e)}")
        messagebox.showerror("错误", f"停止失败: {str(e)}")
        reset_ui_after_exit("停止异常，已复位")

def get_push_config():
    """获取当前推送配置."""
    try:
        result = api_request('GET', '/api/push/config')
        if result.get('code') == 1:
            return result.get('data', {})
        msg = result.get('msg', '未知错误')
        log(f"获取推送配置失败: {msg}")
        return None
    except Exception as e:
        log(f"获取推送配置异常: {str(e)}")
        return None


def set_push_config():
    """设置推送配置（后台线程，避免卡 UI）."""
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
            "回调地址格式不正确，应为 http:// 或 https:// 开头的完整 URL"
        )
        return

    data = {
        'enabled': enabled,
        'callbackUrl': callback_url if enabled else ''
    }

    def worker():
        log(f"设置推送配置: enabled={enabled}, callbackUrl={callback_url}")
        result = api_request('POST', '/api/push/config', data=data)

        def done():
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

        root.after(0, done)

    threading.Thread(target=worker, daemon=True).start()


def refresh_push_config():
    """刷新推送配置显示（后台拉取）."""
    def worker():
        config = get_push_config()

        def apply():
            if not config:
                return
            push_enabled_var.set(config.get('enabled', False))
            callback_url_entry.delete(0, tk.END)
            url = config.get('callbackUrl') or DEFAULT_CALLBACK_URL
            callback_url_entry.insert(0, url)

        root.after(0, apply)

    threading.Thread(target=worker, daemon=True).start()


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

root.after(0, check_log_queue)

main_frame = tk.Frame(root)
main_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

control_frame = tk.Frame(main_frame)
control_frame.pack(pady=5)

start_button = tk.Button(
    control_frame, text="启动", command=start_script, width=10
)
start_button.pack(side=tk.LEFT, padx=5)

stop_button = tk.Button(
    control_frame,
    text="停止",
    command=stop_script,
    width=10,
    state=tk.DISABLED
)
stop_button.pack(side=tk.LEFT, padx=5)

script_path_frame = tk.LabelFrame(
    main_frame, text="Frida 脚本路径配置", padx=10, pady=10
)
script_path_frame.pack(pady=5, fill=tk.X, padx=10)

script_path_input_frame = tk.Frame(script_path_frame)
script_path_input_frame.pack(fill=tk.X, pady=5)

tk.Label(script_path_input_frame, text="脚本路径:").pack(
    side=tk.LEFT, padx=5
)
script_path_entry = tk.Entry(script_path_input_frame, width=60)
script_path_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
script_path_entry.insert(0, "(使用默认搜索路径)")

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

script_path_hint = tk.Label(
    script_path_frame,
    text=(
        "开发态优先加载仓库 dist/agent/wx391027/index.js；"
        "也可 GUI 指定或设置 FRIDA_SCRIPT_PATH"
    ),
    fg="gray",
    font=("TkDefaultFont", 8)
)
script_path_hint.pack(pady=2)

push_config_frame = tk.LabelFrame(
    main_frame, text="消息推送配置", padx=10, pady=10
)

push_enabled_var = tk.BooleanVar()
push_enabled_checkbox = tk.Checkbutton(
    push_config_frame,
    text="启用消息推送",
    variable=push_enabled_var
)
push_enabled_checkbox.pack(anchor=tk.W, pady=2)

callback_url_frame = tk.Frame(push_config_frame)
callback_url_frame.pack(fill=tk.X, pady=5)

tk.Label(callback_url_frame, text="回调地址:").pack(
    side=tk.LEFT, padx=5
)
callback_url_entry = tk.Entry(callback_url_frame, width=50)
callback_url_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
callback_url_entry.insert(0, DEFAULT_CALLBACK_URL)

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

push_hint = tk.Label(
    push_config_frame,
    text=f"默认指向 Apps Server Hook: {DEFAULT_CALLBACK_URL}",
    fg="gray",
    font=("TkDefaultFont", 8)
)
push_hint.pack(anchor=tk.W, pady=2)

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

log("WeeBot 已启动")
log("请点击'启动'按钮开始附加到微信进程")
log(f"Agent API 地址: {API_BASE_URL}")
log(f"默认推送回调: {DEFAULT_CALLBACK_URL}")

resolved = find_script_path()
if resolved:
    log(f"将加载脚本: {resolved}")
else:
    log("⚠ 未找到脚本；请先 npm run build，或通过 GUI 指定路径")

root.mainloop()
