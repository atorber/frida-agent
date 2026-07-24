/**
 * 带 Ctrl+C 优雅退出的启动器：
 * SIGINT/SIGTERM → stopHttpServer() 释放 19088 → unload → detach
 * （纯 `frida -l` 退出不会 close SocketListener，端口会留在 WeChat.exe）
 */
const frida = require('frida')
const fs = require('fs')
const path = require('path')

const TARGET = process.env.FRIDA_TARGET || 'WeChat.exe'
const SCRIPT_PATH = path.resolve(__dirname, '../../../dist/agent/wx391027/index.js')

async function main() {
  if (!fs.existsSync(SCRIPT_PATH)) {
    console.error('[start] 找不到脚本，请先 npm run build:', SCRIPT_PATH)
    process.exit(1)
  }

  const source = fs.readFileSync(SCRIPT_PATH, 'utf8')
  const device = await frida.getLocalDevice()

  let session
  try {
    session = await device.attach(TARGET)
  } catch (e) {
    console.error(`[start] 无法 attach ${TARGET}:`, e.message || e)
    process.exit(1)
  }

  const script = await session.createScript(source)

  // 转发 agent 内 console
  script.logHandler = (level, text) => {
    const line = String(text)
    if (level === 'error' || level === 'warning') {
      console.error(line)
    } else {
      console.log(line)
    }
  }

  script.message.connect((message) => {
    if (message.type === 'error') {
      console.error('[script]', message.stack || message.description || message)
    }
  })

  await script.load()
  console.log(`[start] 已注入 ${TARGET}。Ctrl+C 会先关闭 HTTP 再退出（不杀微信）`)

  let stopping = false
  const gracefulExit = async () => {
    if (stopping) {
      console.error('[start] 再次 Ctrl+C，强制退出')
      process.exit(1)
    }
    stopping = true
    console.log('\n[start] 正在关闭 HTTP 监听...')
    try {
      const exports = script.exports
      if (exports && typeof exports.stopHttpServer === 'function') {
        await exports.stopHttpServer()
        console.log('[start] HTTP 已停止')
      }
    } catch (e) {
      console.error('[start] stopHttpServer 失败:', e.message || e)
    }
    try {
      await script.unload()
    } catch (e) {}
    try {
      await session.detach()
    } catch (e) {}
    console.log('[start] 已退出')
    process.exit(0)
  }

  process.on('SIGINT', () => {
    gracefulExit()
  })
  process.on('SIGTERM', () => {
    gracefulExit()
  })

  // 保持进程；stdin 结束时也优雅退出（便于管道/后台）
  if (process.stdin.isTTY) {
    process.stdin.resume()
  }
  process.stdin.on('end', () => {
    gracefulExit()
  })

  await new Promise(() => {})
}

main().catch((e) => {
  console.error('[start]', e)
  process.exit(1)
})
