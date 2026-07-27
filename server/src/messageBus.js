import { EventEmitter } from 'node:events'

/**
 * Apps 内部消息总线。
 * Agent 推送到 /apps/hook 后，在此抛出 `onMessage`，供助手刷新、速记等订阅。
 *
 * @example
 * import { messageBus, onMessage } from './messageBus.js'
 * onMessage((msg) => { console.log(msg.talkerId, msg.text) })
 * // 或 messageBus.on('onMessage', handler)
 */
class MessageBus extends EventEmitter {
  constructor() {
    super()
    this.setMaxListeners(50)
    /** @type {number} */
    this.receivedCount = 0
    /** @type {object | null} */
    this.lastMessage = null
    /** @type {number | null} */
    this.lastAt = null
  }
}

export const messageBus = new MessageBus()

/**
 * @param {(msg: object) => void} handler
 * @returns {() => void} 取消订阅
 */
export function onMessage(handler) {
  messageBus.on('onMessage', handler)
  return () => messageBus.off('onMessage', handler)
}

/**
 * @param {object} msg Agent Message 对象
 */
export function emitOnMessage(msg) {
  messageBus.receivedCount += 1
  messageBus.lastMessage = msg
  messageBus.lastAt = Date.now()
  messageBus.emit('onMessage', msg)
}
