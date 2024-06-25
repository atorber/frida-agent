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
import time

import os
import binascii

userpath = os.path.expanduser('~')
# print('userpath:', userpath)
rootpath =  userpath + '\\Documents\\WeChat Files\\'

xor_cache = None
xor_len = 2

isStart = False

def image_decrypt(data_path: str, message_id: str):
    try:
        with open(data_path, 'rb') as file:
            data = file.read().hex()
        res = handle_encrypted(data)  # 解密后的十六进制数据
        extension = get_name_extension(res[:4])
        image_info = {
            'base64': binascii.b2a_base64(binascii.unhexlify(res)).decode().strip(),
            'extension': extension,
            'fileName': f'message-{message_id}-url-thumb.{extension}',
        }
        return image_info
    except Exception as err:
        print(err)
        raise Exception('ImageDecrypt fail')

def handle_encrypted(str_encrypted: str):
    code = get_xor(str_encrypted[:4])
    str_length = len(str_encrypted)
    source = ''
    list_ = []
    for i in range(0, str_length, xor_len):
        str_ = str_encrypted[:xor_len]
        str_encrypted = str_encrypted[xor_len:]
        res = hex_xor(str_, code)
        list_.append(res)
    source = ''.join(list_)
    return source

def get_xor(str_: str):
    global xor_cache
    if xor_cache is not None:
        return xor_cache
    str01 = str_[:2]
    str23 = str_[2:]
    for head in data_head:
        h = head['hex']
        h01 = h[:2]
        h23 = h[2:]
        code = hex_xor(h01, str01)
        test_result = hex_xor(str23, code)
        if test_result == h23:
            xor_cache = code
            return xor_cache
    raise Exception('getXor error')

def get_name_extension(hex_str: str):
    for item in data_head:
        if item['hex'] == hex_str:
            return item['name']
    return None

def hex_to_bin(str_: str):
    hex_array = {
        '0': '0000', '1': '0001', '2': '0010', '3': '0011',
        '4': '0100', '5': '0101', '6': '0110', '7': '0111',
        '8': '1000', '9': '1001', 'a': '1010', 'b': '1011',
        'c': '1100', 'd': '1101', 'e': '1110', 'f': '1111'
    }
    value = ''
    for char in str_:
        value += hex_array[char]
    return value

def bin_to_hex(str_: str):
    hex_array = {
        '0000': '0', '0001': '1', '0010': '2', '0011': '3',
        '0100': '4', '0101': '5', '0110': '6', '0111': '7',
        '1000': '8', '1001': '9', '1010': 'a', '1011': 'b',
        '1100': 'c', '1101': 'd', '1110': 'e', '1111': 'f'
    }
    value = ''
    list_ = [str_[i:i+4] for i in range(0, len(str_), 4)]
    for item in list_:
        value += hex_array[item]
    return value

def hex_xor(a: str, b: str):
    A = hex_to_bin(a)
    B = hex_to_bin(b)
    d = ''
    for i in range(len(A)):
        if A[i] == B[i]:
            d += '0'
        else:
            d += '1'
    return bin_to_hex(d)

data_head = [
    {'hex': 'ffd8', 'name': 'jpg'},
    {'hex': '8950', 'name': 'png'},
    {'hex': '4749', 'name': 'gif'},
    {'hex': '424d', 'name': 'bmp'},
]

# 示例调用
# print(image_decrypt('path_to_image_file', 'message_id'))

clients = set()  # 追踪所有连接的 WebSocket 客户端
log_queue = queue.Queue()  # 创建一个线程安全的队列
stop_event = asyncio.Event()  # 用于停止异步任务的事件
ws_stop_event = asyncio.Event()  # 用于停止 WebSocket 服务器的事件
ws_server = None  # 保存 WebSocket 服务器实例
session = None  # 保存 frida 会话实例
loop = asyncio.new_event_loop()

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
        contactId = message['payload']['talkerId'] or 'self'
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
        type = message['payload']['type']
        if type == 3:
            log('内容是图片: ' + content)
            # 延时500ms处理，等待图片文件写入完成
            time.sleep(0.5)

            filename = message['payload']['filename']
            # 获取用户目录
            filepath = rootpath + filename
            print('filePath:', filepath)
            try:
                image_info = image_decrypt(filepath, message['payload']['id'])
                # print('image_info:', image_info)
                # 保存为图片文件
                # 获取filepath路径文件所在的目录，将filepath文件解密后保存到该目录下
                savepath = os.path.dirname(filepath)+'\\'+image_info['fileName']
                print('savepath:', savepath)
                with open(savepath, 'wb') as f:
                    f.write(binascii.a2b_base64(image_info['base64']))
                message['payload']['filename'] = savepath
                log(f"图片消息: {json.dumps(message['payload'])}")

            except Exception as e:
                log(f"解密图片失败: {str(e)}")
        if type == 49:
            filename = message['payload']['filename']
            filepath = rootpath + filename
            print('filePath:', filepath)
            message['payload']['filename'] = filepath
            log(f"文件消息: {json.dumps(message['payload'])}")
        asyncio.run_coroutine_threadsafe(broadcast_message(message['payload']), loop)

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
        log("尝试附加到 WeChat.exe 进程...")
        session = frida.attach("WeChat.exe")
        script_path = resource_path("xp-3.9.10.27.js")
        with open(script_path, 'r', encoding="utf-8") as f:
            script_content = f.read()
        script = session.create_script(script_content)
        script.on("message", on_message)
        script.load()
        log("API服务加载成功...")
        isStart = True
        # 启动开关禁用，防止重复启动；停止开关激活
        start_button.config(state=tk.DISABLED)
        stop_button.config(state=tk.NORMAL)

    except Exception as e:
        log(f"错误: {str(e)}")

# 停止Frida脚本
def stop_script():
    global session
    try:
        if session:
            session.detach()
            session = None
            log("已从进程分离。")
            isStart = False
            # 启动开关激活；停止开关禁用，防止重复启动
            start_button.config(state=tk.NORMAL)
            stop_button.config(state=tk.DISABLED)
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
    global ws_server
    ws_server = await websockets.serve(websocket_handler, "localhost", 19099)
    log("WebSocket 服务器已启动，监听端口 19099")
    await ws_stop_event.wait()  # 等待停止事件
    ws_server.close()
    await ws_server.wait_closed()
    log("WebSocket 服务器已停止")

# 停止 WebSocket 服务器
def stop_websocket_server():
    ws_stop_event.set()
    log("停止 WebSocket 服务器的请求已发送")

# 创建主窗口
root = tk.Tk()
root.title("WeeBot")

# 启动检查队列的循环
root.after(0, check_log_queue)

# 创建按钮和文本框的框架
frame = tk.Frame(root)
frame.pack(pady=10, padx=10)

# 创建启动 Frida 脚本的按钮
start_button = tk.Button(frame, text="启动", command=start_script )
start_button.pack(side=tk.LEFT, padx=5)

# 创建停止 Frida 脚本的按钮
stop_button = tk.Button(frame, text="停止", command=stop_script)  # Fixed syntax error here
stop_button.pack(side=tk.LEFT, padx=5)

# 创建停止 WebSocket 服务器的按钮
# stop_ws_button = tk.Button(frame, text="Stop WS Service", command=stop_websocket_server)
# stop_ws_button.pack(side=tk.LEFT, padx=5)

# 创建退出程序的按钮
# exit_button = tk.Button(frame, text="Exit", command=lambda: on_closing(force=True))
# exit_button.pack(side=tk.LEFT, padx=5)

# 创建用于显示调试输出的滚动文本框
debug_text = scrolledtext.ScrolledText(frame, state=tk.DISABLED, width=80, height=20)
debug_text.pack(pady=10)

# 在另一个线程中启动WebSocket服务器
def start_server():
    asyncio.run_coroutine_threadsafe(start_websocket_server(), loop)

# 启动WebSocket服务器线程
server_thread = Thread(target=start_server)
server_thread.start()

# 关闭程序时的清理操作
def on_closing(force=False):
    if force or messagebox.askokcancel("Quit", "确定退出?"):
        # 设置停止事件
        stop_event.set()
        # 停止 WebSocket 服务器
        ws_stop_event.set()
        # 停止 Frida 脚本
        stop_script()
        # 确保异步任务在主线程中执行
        root.after(100, lambda: root.quit())

# 异步停止Frida脚本
async def stop_script_async():
    stop_script()

# 异步关闭WebSocket服务器
async def stop_websocket_server_async():
    if ws_server is not None:
        ws_stop_event.set()
        await ws_server.wait_closed()
    log("WebSocket 服务器已关闭")

# 在关闭过程中等待所有异步任务完成
async def wait_for_closing():
    await stop_script_async()
    await stop_websocket_server_async()
    root.destroy()  # 销毁Tkinter主窗口
    log("程序已退出")

root.protocol("WM_DELETE_WINDOW", on_closing)

# 启动Tkinter主循环
async def run_tk():
    log("程序已启动")
    start_script()
    while not stop_event.is_set():
        root.update()
        try:
            await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            print("CancelledError")
            break

    await wait_for_closing()

# Create and set the event loop
asyncio.set_event_loop(loop)
loop.run_until_complete(run_tk())
