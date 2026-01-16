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

import binascii

userpath = os.path.expanduser('~')
# print('userpath:', userpath)
rootpath =  userpath + '\\Documents\\WeChat Files\\'

xor_cache = None
xor_len = 2

is_start = False

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
script = None  # 保存 frida 脚本实例
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
    # 处理命令响应
    if 'type' in message and message['type'] == 'command_response':
        log(f"收到命令响应: {json.dumps(message.get('payload', {}))}")
        # 可以通过 WebSocket 发送响应给客户端
        asyncio.run_coroutine_threadsafe(
            broadcast_command_response(message.get('payload', {})), 
            loop
        )
        return
    
    # 处理普通消息
    if 'payload' in message:
        content = message['payload']['text']
        contactId = message['payload']['talkerId'] or 'self'
        log(f"接收到的内容: {content}, 来自用户: {contactId}")
        log(f"消息原文: {json.dumps(message['payload'])}")
        if content == "ding":
            log('内容是 ding: ' + content)
            # 使用 RPC 调用发送消息
            try:
                if script and hasattr(script.exports_sync, 'messageSendText'):
                    result = script.exports_sync.messageSendText(contactId, 'dong')
                    log(f"自动回复发送结果: {result}")
                elif script:
                    # 备用方案：通过 script.post 发送
                    script.post({
                        'type': 'send',
                        'payload': {
                            'text': 'dong',
                            'contactId': contactId,
                        }})
            except Exception as e:
                log(f"发送自动回复失败: {str(e)}")
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
        log(f"广播消息推送成功: {payload.get('id', 'unknown')}")
        tasks = [asyncio.create_task(client.send(message)) for client in clients]
        await asyncio.wait(tasks)
    else:
        log("没有客户端连接")

# 广播命令响应到所有 WebSocket 客户端
async def broadcast_command_response(response):
    if clients:
        message = json.dumps({
            'type': 'command_response',
            'data': response
        })
        tasks = [asyncio.create_task(client.send(message)) for client in clients]
        await asyncio.wait(tasks)

# 启动Frida脚本
def start_script():
    global session, script
    try:
        log("尝试附加到 WeChat.exe 进程...")
        session = frida.attach("WeChat.exe")
        script_path = resource_path("xp-3.9.10.27.js")
        
        # 读取脚本文件
        with open(script_path, 'r', encoding="utf-8") as f:
            script_content = f.read()
        
        # 检查是否是打包格式（以 📦 开头）
        if script_content.startswith('📦'):
            log("检测到打包格式，尝试提取 JavaScript 代码...")
            # 从打包格式中提取实际的 JavaScript 代码
            # 打包格式的结构：📦\n文件列表\n✄\n实际的 JavaScript 代码\n✄\n{source map}
            parts = script_content.split('✄')
            if len(parts) >= 3:
                # 打包格式结构：
                # 📦\n文件列表\n✄\n{source map}\n✄\n实际的 JavaScript 代码\n✄\n{source map}
                # parts[0]: 文件列表
                # parts[1]: 第一个 source map
                # parts[2]: 实际的 JavaScript 代码
                script_content = parts[2].strip()
                
                # 移除后续的 source map（查找第一个 ✄）
                # parts[2] 应该包含完整的 JavaScript 代码，直到下一个 ✄
                first_separator = script_content.find('✄')
                if first_separator > 0:
                    # 找到第一个 ✄，这是代码的结束位置
                    script_content = script_content[:first_separator].strip()
                else:
                    # 如果没有找到 ✄，查找第一个 source map
                    lines = script_content.split('\n')
                    cleaned_lines = []
                    for line in lines:
                        # 如果遇到 source map 开始，停止添加
                        if line.strip().startswith('{"version"'):
                            break
                        cleaned_lines.append(line)
                    script_content = '\n'.join(cleaned_lines).strip()
                
                # 确保代码以完整语句结尾（server.listen 应该以 }); 结尾）
                if script_content:
                    # 查找最后一个 });（server.listen 的结束）
                    last_server_end = script_content.rfind('});')
                    if last_server_end > 0:
                        # 检查前面是否有 server.listen
                        before_end = script_content[max(0, last_server_end - 200):last_server_end]
                        if 'server.listen' in before_end:
                            script_content = script_content[:last_server_end + 3].strip()
                        else:
                            # 查找最后一个 };
                            last_semicolon = script_content.rfind('};')
                            if last_semicolon > 0:
                                script_content = script_content[:last_semicolon + 2].strip()
                            else:
                                last_brace = script_content.rfind('}')
                                if last_brace > 0:
                                    script_content = script_content[:last_brace + 1].strip()
                    else:
                        # 查找最后一个 };
                        last_semicolon = script_content.rfind('};')
                        if last_semicolon > 0:
                            script_content = script_content[:last_semicolon + 2].strip()
                        else:
                            last_brace = script_content.rfind('}')
                            if last_brace > 0:
                                script_content = script_content[:last_brace + 1].strip()
            elif len(parts) >= 2:
                # 如果只有两个部分，可能是旧格式
                # 第二个部分应该是 JavaScript 代码
                script_content = parts[1].strip()
                # 移除 source map
                lines = script_content.split('\n')
                cleaned_lines = []
                for line in lines:
                    if line.strip().startswith('{"version"'):
                        break
                    cleaned_lines.append(line)
                script_content = '\n'.join(cleaned_lines).strip()
            else:
                raise Exception("无法从打包格式中提取 JavaScript 代码，请重新编译：frida-compile agent/wx391027/index.ts -o weebot/xp-3.9.10.27.js（不使用 -c 参数）")
        
        # 检查脚本是否包含 rpc.exports
        if 'rpc.exports' not in script_content:
            log("警告: 脚本中未找到 rpc.exports，RPC 功能可能不可用")
        
        # 调试：检查提取后的代码
        if len(script_content) < 10000:
            first_lines = script_content.split('\n')[:10]
            last_lines = script_content.split('\n')[-5:]
            log(f"警告: 提取后的代码可能不完整，长度: {len(script_content)} 字符")
            log(f"前10行: {first_lines}")
            log(f"最后5行: {last_lines}")
        
        script = session.create_script(script_content)
        script.on("message", on_message)
        script.load()
        log("API服务加载成功...")
        
        # 测试 RPC 调用
        try:
            # 检查 RPC 导出是否成功
            if hasattr(script.exports_sync, 'checkLogin'):
                try:
                    login_status = script.exports_sync.checkLogin()
                    log(f"登录状态检查: {login_status}")
                except Exception as e:
                    log(f"RPC 调用测试失败: {str(e)}")
            else:
                # 列出所有可用的导出方法
                available_methods = [m for m in dir(script.exports_sync) if not m.startswith('_')]
                log(f"可用的 RPC 方法: {available_methods}")
        except Exception as e:
            log(f"RPC 测试警告: {str(e)}")
        
        is_start = True
        # 启动开关禁用，防止重复启动；停止开关激活
        start_button.config(state=tk.DISABLED)
        stop_button.config(state=tk.NORMAL)

    except Exception as e:
        log(f"错误: {str(e)}")
        import traceback
        log(f"详细错误: {traceback.format_exc()}")

# 停止Frida脚本
def stop_script():
    global session, script
    try:
        if script:
            script.unload()
            script = None
        if session:
            session.detach()
            session = None
            log("已从进程分离。")
            is_start = False
            # 启动开关激活；停止开关禁用，防止重复启动
            start_button.config(state=tk.NORMAL)
            stop_button.config(state=tk.DISABLED)
    except Exception as e:
        log(f"错误: {str(e)}")

# 处理 WebSocket 客户端命令
async def handle_websocket_command(command_data):
    """
    处理来自 WebSocket 客户端的命令
    
    支持的命令：
    - sendText: 发送文本消息
      params: {contactId: string, text: string}
    - getSelfInfo: 获取登录用户信息
    - getContactList: 获取联系人列表
    - getRoomList: 获取群列表
    - getContact: 获取联系人详情
      params: {contactId: string}
    - getRoom: 获取群详情
      params: {roomId: string}
    - checkLogin: 检查登录状态
    - getDbNames: 获取数据库名称列表
    - getDbTables: 获取数据库表列表
      params: {dbName: string}
    - execDbQuery: 执行数据库查询
      params: {dbName: string, sql: string}
    """
    try:
        cmd = command_data.get('command')
        params = command_data.get('params', {})
        
        if not script:
            return {'success': False, 'error': 'Frida 脚本未加载'}
        
        # 通过 script.exports_sync 调用 Frida 脚本中的函数
        try:
            if cmd == 'sendText':
                result = script.exports_sync.messageSendText(
                    params.get('contactId', ''),
                    params.get('text', '')
                )
                return {'success': True, 'data': result}
            
            elif cmd == 'getSelfInfo':
                result = script.exports_sync.contactSelfInfo()
                return {'success': True, 'data': result}
            
            elif cmd == 'getContactList':
                result = script.exports_sync.contactList()
                return {'success': True, 'data': result}
            
            elif cmd == 'getRoomList':
                result = script.exports_sync.roomList()
                return {'success': True, 'data': result}
            
            elif cmd == 'getContact':
                result = script.exports_sync.contactRawPayload(params.get('contactId', ''))
                return {'success': True, 'data': result}
            
            elif cmd == 'getRoom':
                result = script.exports_sync.roomRawPayload(params.get('roomId', ''))
                return {'success': True, 'data': result}
            
            elif cmd == 'checkLogin':
                result = script.exports_sync.checkLogin()
                return {'success': True, 'data': result}
            
            elif cmd == 'getDbNames':
                result = script.exports_sync.getDbNames()
                return {'success': True, 'data': result}
            
            elif cmd == 'getDbTables':
                result = script.exports_sync.getDbTables(params.get('dbName', ''))
                return {'success': True, 'data': result}
            
            elif cmd == 'execDbQuery':
                result = script.exports_sync.execDbQuery(
                    params.get('dbName', ''),
                    params.get('sql', '')
                )
                return {'success': True, 'data': result}
            
            else:
                return {'success': False, 'error': f'未知命令: {cmd}'}
        
        except AttributeError:
            # 如果 script.exports_sync 不存在，尝试通过 script.post 发送命令
            script.post({
                'type': 'command',
                'command': cmd,
                'params': params
            })
            return {'success': True, 'message': '命令已发送，等待响应'}
        
    except Exception as e:
        log(f"处理命令错误: {str(e)}")
        return {'success': False, 'error': str(e)}

# WebSocket连接处理函数
async def websocket_handler(websocket, path):
    clients.add(websocket)
    log("新客户端连接")
    try:
        async for message in websocket:
            try:
                # 尝试解析 JSON 命令
                command_data = json.loads(message)
                if 'command' in command_data:
                    # 处理命令
                    response = await handle_websocket_command(command_data)
                    await websocket.send(json.dumps(response))
                    log(f"处理命令: {command_data.get('command')}, 响应: {response.get('success', False)}")
                else:
                    log(f"收到客户端消息: {message}")
            except json.JSONDecodeError:
                # 如果不是 JSON，当作普通消息处理
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
