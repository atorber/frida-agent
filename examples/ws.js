// 连接ws服务127.0.0.1:8082，发送消息 hello world
const WebSocket = require("ws");
const ws = new WebSocket("ws://127.0.0.1:8082");
// 连接成功建立时执行的回调函数
ws.onopen = function() {
    console.log("已连接到WebSocket服务");
    // 发送消息
    ws.send("hello world");
};

// 接收到消息时执行的回调函数
ws.onmessage = function(event) {
    console.log("接收到的服务器返回消息: " + event.data);
};

// 连接发生错误时执行的回调函数
ws.onerror = function(error) {
    console.error("WebSocket发生错误: ");
    console.error(error);
};

// 连接关闭时执行的回调函数
ws.onclose = function() {
    console.log("WebSocket连接已关闭");
};