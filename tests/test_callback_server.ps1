# 消息推送回调测试服务器 (PowerShell 版本)
# 用于测试 Frida Agent 的消息推送功能
#
# 使用方法:
#     .\test_callback_server.ps1 [-Port PORT] [-Host HOST]
#
# 示例:
#     .\test_callback_server.ps1
#     .\test_callback_server.ps1 -Port 8888
#     .\test_callback_server.ps1 -Host 0.0.0.0 -Port 8888

param(
    [string]$Host = "127.0.0.1",
    [int]$Port = 8888
)

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://${Host}:${Port}/")
$listener.Start()

Write-Host @"
$('='*80)
🚀 消息推送回调测试服务器
$('='*80)
监听地址: http://${Host}:${Port}
$('='*80)

📝 使用说明:
1. 在 Frida Agent 中设置推送回调地址:
   Invoke-WebRequest -Uri http://localhost:19088/api/push/config -Method POST `
     -ContentType "application/json" `
     -Body '{"enabled": true, "callbackUrl": "http://${Host}:${Port}"}'

2. 发送测试消息到微信，服务器会自动接收并显示推送的消息

3. 按 Ctrl+C 停止服务器
$('='*80)
"@

function Send-Response {
    param(
        [System.Net.HttpListenerContext]$Context,
        [int]$StatusCode,
        [object]$Data
    )
    
    $json = $Data | ConvertTo-Json -Depth 10 -Compress:$false
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
    
    $response = $Context.Response
    $response.StatusCode = $StatusCode
    $response.ContentType = "application/json; charset=utf-8"
    $response.ContentLength64 = $buffer.Length
    $response.AddHeader("Access-Control-Allow-Origin", "*")
    
    $response.OutputStream.Write($buffer, 0, $buffer.Length)
    $response.OutputStream.Close()
}

try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        
        $method = $request.HttpMethod
        $path = $request.Url.AbsolutePath
        
        if ($method -eq "GET" -and $path -eq "/") {
            # 返回服务器状态
            Send-Response -Context $context -StatusCode 200 -Data @{
                status = "ok"
                message = "回调测试服务器运行中"
                endpoints = @{
                    "POST /" = "接收消息推送"
                    "GET /" = "检查服务器状态"
                }
            }
            continue
        }
        
        if ($method -eq "POST" -and $path -eq "/") {
            # 接收消息推送
            $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
            $body = $reader.ReadToEnd()
            $reader.Close()
            
            try {
                $data = $body | ConvertFrom-Json
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                
                # 打印接收到的消息
                Write-Host ""
                Write-Host $('='*80)
                Write-Host "[$timestamp] 📨 收到消息推送" -ForegroundColor Green
                Write-Host $('='*80)
                Write-Host "消息ID: $($data.id)"
                Write-Host "消息类型: $($data.type)"
                Write-Host "是否自己发送: $($data.isSelf)"
                Write-Host "时间戳: $($data.timestamp)"
                Write-Host "发送者ID: $($data.talkerId)"
                Write-Host "接收者ID: $($data.listenerId)"
                Write-Host "群ID: $($data.roomId)"
                Write-Host "消息内容: $($data.text)"
                if ($data.filename) {
                    Write-Host "文件名: $($data.filename)"
                }
                if ($data.mentionIds) {
                    Write-Host "@列表: $($data.mentionIds -join ', ')"
                }
                Write-Host ""
                Write-Host "完整消息数据:"
                Write-Host ($data | ConvertTo-Json -Depth 10)
                Write-Host $('='*80)
                Write-Host ""
                
                # 发送成功响应
                Send-Response -Context $context -StatusCode 200 -Data @{
                    status = "ok"
                    message = "消息接收成功"
                    received_at = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ")
                }
                
            } catch {
                Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] ❌ JSON 解析失败: $_" -ForegroundColor Red
                Send-Response -Context $context -StatusCode 400 -Data @{
                    status = "error"
                    message = "JSON 解析失败: $_"
                }
            }
            continue
        }
        
        # 404 处理
        Send-Response -Context $context -StatusCode 404 -Data @{
            status = "error"
            message = "Not Found"
        }
    }
} catch {
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] ❌ 服务器错误: $_" -ForegroundColor Red
} finally {
    $listener.Stop()
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] ⏹️  服务器已停止" -ForegroundColor Yellow
}
