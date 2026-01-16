#!/usr/bin/env node
/**
 * 消息推送回调测试服务器 (Node.js 版本)
 * 用于测试 Frida Agent 的消息推送功能
 * 
 * 使用方法:
 *     node test_callback_server.js [--port PORT] [--host HOST]
 * 
 * 示例:
 *     node test_callback_server.js
 *     node test_callback_server.js --port 8888
 *     node test_callback_server.js --host 0.0.0.0 --port 8888
 */

const http = require('http');
const url = require('url');

// 解析命令行参数
const args = process.argv.slice(2);
const host = args.includes('--host') ? args[args.indexOf('--host') + 1] : '127.0.0.1';
const port = args.includes('--port') ? parseInt(args[args.indexOf('--port') + 1]) : 8888;

const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const method = req.method;
    const path = parsedUrl.pathname;

    // 设置 CORS 头
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    if (method === 'GET' && path === '/') {
        // 返回服务器状态
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({
            status: 'ok',
            message: '回调测试服务器运行中',
            endpoints: {
                'POST /': '接收消息推送',
                'GET /': '检查服务器状态'
            }
        }, null, 2));
        return;
    }

    if (method === 'POST' && path === '/') {
        // 接收消息推送
        let body = '';
        
        req.on('data', (chunk) => {
            body += chunk.toString();
        });
        
        req.on('end', () => {
            try {
                const data = JSON.parse(body);
                const timestamp = new Date().toISOString();
                
                // 打印接收到的消息
                console.log('\n' + '='.repeat(80));
                console.log(`[${timestamp}] 📨 收到消息推送`);
                console.log('='.repeat(80));
                console.log(`消息ID: ${data.id || 'N/A'}`);
                console.log(`消息类型: ${data.type || 'N/A'}`);
                console.log(`是否自己发送: ${data.isSelf || 'N/A'}`);
                console.log(`时间戳: ${data.timestamp || 'N/A'}`);
                console.log(`发送者ID: ${data.talkerId || 'N/A'}`);
                console.log(`接收者ID: ${data.listenerId || 'N/A'}`);
                console.log(`群ID: ${data.roomId || 'N/A'}`);
                console.log(`消息内容: ${data.text || 'N/A'}`);
                if (data.filename) {
                    console.log(`文件名: ${data.filename}`);
                }
                if (data.mentionIds && data.mentionIds.length > 0) {
                    console.log(`@列表: ${data.mentionIds.join(', ')}`);
                }
                console.log('\n完整消息数据:');
                console.log(JSON.stringify(data, null, 2));
                console.log('='.repeat(80) + '\n');
                
                // 发送成功响应
                res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
                res.end(JSON.stringify({
                    status: 'ok',
                    message: '消息接收成功',
                    received_at: timestamp
                }, null, 2));
                
            } catch (e) {
                console.error(`[${new Date().toISOString()}] ❌ JSON 解析失败:`, e);
                res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
                res.end(JSON.stringify({
                    status: 'error',
                    message: `JSON 解析失败: ${e.message}`
                }));
            }
        });
        
        req.on('error', (err) => {
            console.error(`[${new Date().toISOString()}] ❌ 请求错误:`, err);
            res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({
                status: 'error',
                message: `服务器错误: ${err.message}`
            }));
        });
        
        return;
    }

    // 404 处理
    res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({
        status: 'error',
        message: 'Not Found'
    }));
});

server.listen(port, host, () => {
    console.log(`
${'='.repeat(80)}
🚀 消息推送回调测试服务器
${'='.repeat(80)}
监听地址: http://${host}:${port}
${'='.repeat(80)}

📝 使用说明:
1. 在 Frida Agent 中设置推送回调地址:
   curl -X POST http://localhost:19088/api/push/config \\
     -H "Content-Type: application/json" \\
     -d '{"enabled": true, "callbackUrl": "http://${host}:${port}"}'

2. 发送测试消息到微信，服务器会自动接收并显示推送的消息

3. 按 Ctrl+C 停止服务器
${'='.repeat(80)}
`);
});

server.on('error', (err) => {
    console.error(`[${new Date().toISOString()}] ❌ 服务器错误:`, err);
    process.exit(1);
});

process.on('SIGINT', () => {
    console.log(`\n[${new Date().toISOString()}] ⏹️  服务器已停止`);
    server.close(() => {
        process.exit(0);
    });
});
