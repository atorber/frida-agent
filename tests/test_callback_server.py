#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
消息推送回调测试服务器
用于测试 Frida Agent 的消息推送功能

使用方法:
    python test_callback_server.py [--port PORT] [--host HOST]

示例:
    python test_callback_server.py
    python test_callback_server.py --port 8888
    python test_callback_server.py --host 0.0.0.0 --port 8888
"""

import json
import argparse
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse


class CallbackHandler(BaseHTTPRequestHandler):
    """处理回调请求的处理器"""
    
    def do_POST(self):
        """处理 POST 请求"""
        try:
            # 读取请求体
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            
            # 解析 JSON
            try:
                data = json.loads(body.decode('utf-8'))
            except json.JSONDecodeError as e:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ❌ JSON 解析失败: {e}")
                self.send_error_response(400, f"JSON 解析失败: {e}")
                return
            
            # 打印接收到的消息
            print(f"\n{'='*80}")
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 📨 收到消息推送")
            print(f"{'='*80}")
            print(f"消息ID: {data.get('id', 'N/A')}")
            print(f"消息类型: {data.get('type', 'N/A')}")
            print(f"是否自己发送: {data.get('isSelf', 'N/A')}")
            print(f"时间戳: {data.get('timestamp', 'N/A')}")
            print(f"发送者ID: {data.get('talkerId', 'N/A')}")
            print(f"接收者ID: {data.get('listenerId', 'N/A')}")
            print(f"群ID: {data.get('roomId', 'N/A')}")
            print(f"消息内容: {data.get('text', 'N/A')}")
            if data.get('filename'):
                print(f"文件名: {data.get('filename')}")
            if data.get('mentionIds'):
                print(f"@列表: {data.get('mentionIds')}")
            print(f"\n完整消息数据:")
            print(json.dumps(data, indent=2, ensure_ascii=False))
            print(f"{'='*80}\n")
            
            # 发送成功响应
            self.send_success_response({
                "status": "ok",
                "message": "消息接收成功",
                "received_at": datetime.now().isoformat()
            })
            
        except Exception as e:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ❌ 处理请求失败: {e}")
            self.send_error_response(500, f"服务器错误: {e}")
    
    def do_GET(self):
        """处理 GET 请求（用于测试服务器是否运行）"""
        if self.path == '/':
            self.send_success_response({
                "status": "ok",
                "message": "回调测试服务器运行中",
                "endpoints": {
                    "POST /": "接收消息推送",
                    "GET /": "检查服务器状态"
                }
            })
        else:
            self.send_error_response(404, "Not Found")
    
    def send_success_response(self, data):
        """发送成功响应"""
        response = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(response)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(response)
    
    def send_error_response(self, status_code, message):
        """发送错误响应"""
        response = json.dumps({
            "status": "error",
            "message": message
        }, ensure_ascii=False).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)
    
    def log_message(self, format, *args):
        """重写日志方法，避免打印默认的请求日志"""
        # 可以选择性地打印日志
        pass


def main():
    parser = argparse.ArgumentParser(description='消息推送回调测试服务器')
    parser.add_argument('--host', default='127.0.0.1', help='监听地址 (默认: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=8888, help='监听端口 (默认: 8888)')
    
    args = parser.parse_args()
    
    server_address = (args.host, args.port)
    httpd = HTTPServer(server_address, CallbackHandler)
    
    print(f"""
{'='*80}
🚀 消息推送回调测试服务器
{'='*80}
监听地址: http://{args.host}:{args.port}
{'='*80}

📝 使用说明:
1. 在 Frida Agent 中设置推送回调地址:
   curl -X POST http://localhost:19088/api/push/config \\
     -H "Content-Type: application/json" \\
     -d '{{"enabled": true, "callbackUrl": "http://{args.host}:{args.port}"}}'

2. 发送测试消息到微信，服务器会自动接收并显示推送的消息

3. 按 Ctrl+C 停止服务器
{'='*80}
""")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ⏹️  服务器已停止")
        httpd.server_close()


if __name__ == '__main__':
    main()
