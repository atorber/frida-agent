from datetime import datetime
import os
import sys
import frida
import tkinter as tk
from tkinter import scrolledtext, messagebox
import asyncio
import websockets
from threading import Thread
import queue
import json

clients = set()  # 追踪所有连接的 WebSocket 客户端
log_queue = queue.Queue()  # 创建一个线程安全的队列
stop_event = asyncio.Event()  # 用于停止异步任务的事件

# 日志记录函数
def log(message):
    log_queue.put(message)

# 检查队列中的日志消息，并更新GUI
def check_log_queue():
    try:
        while True:
            message = log_queue.get_nowait()
            update_gui(message)
    except queue.Empty:
        pass
    root.after(100, check_log_queue)

# 更新GUI日志显示
def update_gui(message):
    debug_text.config(state=tk.NORMAL)
    debug_text.insert(tk.END, f"[{datetime.now().strftime('%D %H:%M:%S')}] {message}\n")
    debug_text.config(state=tk.DISABLED)
    debug_text.yview(tk.END)

# 获取资源的绝对路径
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# Frida消息处理函数
def on_message(message, data):
    if 'payload' in message:
        content = message['payload']['text']
        contactId = message['payload']['talkerId'] | 'self'
        log(f"接收到的内容: {content}, 来自用户: {contactId}")
        log(f"消息原文: {json.dumps(message['payload'])}")
        if content == "ding":
            log('内容是 ding: ' + content)
            script.post({
                'type': 'send',
                'payload': {
                    'text': 'dong',
                    'contactId': contactId,
                }})
        asyncio.run(broadcast_message(message['payload']))

# 广播消息到所有 WebSocket 客户端
async def broadcast_message(payload):
    if clients:
        message = json.dumps(payload)
        log(f"广播消息推送成功: {payload['id']}")
        tasks = [asyncio.create_task(client.send(message)) for client in clients]
        await asyncio.wait(tasks)
    else:
        log("没有客户端连接")

# 启动Frida脚本
def start_script():
    global session, script
    try:
        server_thread.start()

        log("尝试附加到 WeChat.exe 进程...")
        session = frida.attach("WeChat.exe")
        script_path = resource_path("xp-3.9.10.27-lite.js")
        with open(script_path, 'r', encoding="utf-8") as f:
            script_content = f.read()
        script = session.create_script(script_content)
        script.on("message", on_message)
        script.load()
        log("Frida 脚本加载成功。")
    except Exception as e:
        log(f"错误: {str(e)}")

# 停止Frida脚本
def stop_script():
    try:
        if session:
            session.detach()
            log("已从进程分离。")
    except Exception as e:
        log(f"错误: {str(e)}")

# WebSocket连接处理函数
async def websocket_handler(websocket, path):
    clients.add(websocket)
    log("新客户端连接")
    try:
        async for message in websocket:
            log(f"收到客户端消息: {message}")
    except websockets.ConnectionClosed:
        log("客户端断开连接")
    finally:
        clients.remove(websocket)
        log("客户端已移除")

# 启动WebSocket服务器
async def start_websocket_server():
    server = await websockets.serve(websocket_handler, "localhost", 19099)
    log("WebSocket 服务器已启动，监听端口 19099")
    await server.wait_closed()

# 创建主窗口
root = tk.Tk()
root.title("WeeBot")

# 启动检查队列的循环
root.after(0, check_log_queue)

# 创建按钮和文本框的框架
frame = tk.Frame(root)
frame.pack(pady=10, padx=10)

# 创建启动 Frida 脚本的按钮
start_button = tk.Button(frame, text="Start", command=start_script)
start_button.pack(side=tk.LEFT, padx=5)

# 创建停止 Frida 脚本的按钮
stop_button = tk.Button(frame, text="Stop", command=stop_script)
stop_button.pack(side=tk.LEFT, padx=5)

# 创建用于显示调试输出的滚动文本框
debug_text = scrolledtext.ScrolledText(frame, state=tk.DISABLED, width=80, height=20)
debug_text.pack(pady=10)

# 在另一个线程中启动WebSocket服务器
def start_server():
    asyncio.run(start_websocket_server())

# 启动WebSocket服务器线程
server_thread = Thread(target=start_server)

# 关闭程序时的清理操作
def on_closing():
    stop_event.set()  # 触发停止事件
    stop_script()  # 停止Frida脚本
    # 关闭WebSocket服务器
    if server_thread.is_alive():
        server_thread.join()
    root.destroy()  # 销毁Tkinter主窗口
    log("程序已退出")

root.protocol("WM_DELETE_WINDOW", on_closing)

# 启动Tkinter主循环
async def run_tk():
    log("程序已启动")
    while not stop_event.is_set():
        root.update()
        try:
            await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            print("CancelledError")
            break
            

asyncio.run(run_tk())
