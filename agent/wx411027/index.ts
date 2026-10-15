/**
 * WeChat 4.1.10.27 Frida Agent
 * HTTP 形态对齐 wx391027；偏移与原生 call 全部来自 aixed 4.1.10.27
 */
import { startHttpServer } from './httpServer.js'
import { WX_DLL, WX_VERSION } from './offset.js'
import { log } from './utils.js'
import { checkLogin, contactSelfInfo, getHomePath, getSelfWxid } from './login.js'
import { contactList, contactRawPayload } from './contact.js'
import {
  roomList,
  roomRawPayload,
  roomMemberList,
  roomMemberRawPayload,
  roomAdd,
  roomInvite,
  roomDel,
  roomTopic,
} from './room.js'
import { xmlOffsetsLookValid, detectXmlKind } from './forwardXml.js'
import {
  messageSendText,
  messageSendImage,
  messageSendFile,
  messageSendPat,
  messageForward,
  messageForwardXml,
  messageSendRichText,
  messageSendEmotion,
  decryptImage,
  downloadAttach,
  getAudio,
  refreshPyq,
  getMsgTypes,
} from './message.js'
import {
  getDbNames,
  getDbTables,
  execDbQuery,
  getDatabaseInfo,
  queryChatHistory,
  querySessionList,
} from './sqlite.js'

const HTTP_PORT = 19088

function ensureDll(): void {
  const mod = Process.getModuleByName(WX_DLL)
  log('INIT', `${WX_DLL} base=${mod.base} size=${mod.size} ver=${WX_VERSION}`)
}

ensureDll()

let httpHandle: ReturnType<typeof startHttpServer> | null = null

setImmediate(() => {
  try {
    log('INIT', 'homePath=', getHomePath(), 'wxid=', getSelfWxid())
  } catch (e) {
    console.error('延迟初始化失败', e)
  }
})

function ok(data: any = null, msg = 'success') {
  return { code: 1, data, msg }
}
function fail(msg: string, data: any = null) {
  return { code: 0, data, msg }
}
function unsupported(name: string) {
  return fail(`aixed 4.1.10.27 未提供原生实现: ${name}`)
}

function parseBody(body: string): any {
  if (!body) return {}
  return JSON.parse(body)
}

function handleRequest(req: {
  method: string
  url: string
  body: string
  query?: Record<string, string>
}): { code: number; data: any; msg: string } {
  const method = (req.method || 'GET').toUpperCase()
  const path = (req.url || '/').split('?')[0]
  const q = req.query || {}

  try {
    if (path === '/api/health' || path === '/') {
      return ok({
        version: WX_VERSION,
        dll: WX_DLL,
        features: [
          'checkLogin',
          'contacts/self',
          'contacts',
          'rooms',
          'room/members',
          'message/text',
          'message/image',
          'message/decryptImage',
          'message/forward(xml)',
          'db/*',
          'message/history',
          'sessions',
        ],
        note: '偏移与发送/解码/XML转发来自 aixed；联系人/群/会话/历史走 contact/session/message_N.db',
      })
    }

    if (path === '/api/server/status') {
      return ok({ listening: !!httpHandle, port: HTTP_PORT })
    }
    if (path === '/api/server/stop' && method === 'POST') {
      if (httpHandle) httpHandle.close()
      return ok(true, 'stopped')
    }
    if (path === '/api/server/start' && method === 'POST') {
      if (httpHandle) httpHandle.start()
      return ok(true, 'started')
    }

    if (path === '/api/checkLogin') return ok(checkLogin())

    if (path === '/api/contacts/self') return ok(contactSelfInfo())

    if (path === '/api/contacts') return ok(contactList())

    if (path === '/api/contact') {
      const id = q.id || q.contactId
      if (!id) return fail('需要 id')
      return ok(contactRawPayload(id))
    }

    if (path === '/api/rooms') return ok(roomList())

    if (path === '/api/room') {
      const roomId = q.roomId
      if (!roomId) return fail('需要 roomId')
      return ok(roomRawPayload(roomId))
    }

    if (path === '/api/room/members') {
      const roomId = q.roomId
      if (!roomId) return fail('需要 roomId')
      return ok(roomMemberList(roomId))
    }

    if (path === '/api/room/member') {
      const roomId = q.roomId
      const contactId = q.contactId || q.id
      if (!roomId || !contactId) return fail('需要 roomId 和 contactId')
      return ok(roomMemberRawPayload(roomId, contactId))
    }

    if (path === '/api/message/types') return ok(getMsgTypes())

    if (path === '/api/message/text' && method === 'POST') {
      const body = parseBody(req.body)
      if (!body.contactId || body.text === undefined) return fail('需要 contactId 和 text')
      const r = messageSendText(String(body.contactId), String(body.text), body.atWxids)
      return r < 0 ? fail('发送失败', r) : ok(r)
    }

    if (path === '/api/message/image' && method === 'POST') {
      const body = parseBody(req.body)
      if (!body.contactId || !body.path) return fail('需要 contactId 和 path')
      const r = messageSendImage(String(body.contactId), String(body.path))
      return r < 0 ? fail('发送失败', r) : ok(r)
    }

    if (path === '/api/message/decryptImage' && method === 'POST') {
      const body = parseBody(req.body)
      const src = body.src || body.src_path
      const dst = body.dst || body.dst_path || body.dir
      if (!src || !dst) return fail('需要 src/dst')
      const r = decryptImage(String(src), String(dst))
      return r < 0 ? fail('解码失败', r) : ok(r)
    }

    if (path === '/api/message/file' && method === 'POST') {
      const body = parseBody(req.body)
      const r = messageSendFile(String(body.contactId || ''), String(body.path || ''))
      return r === -2 ? unsupported('send_file') : r < 0 ? fail('发送失败', r) : ok(r)
    }

    if (path === '/api/message/pat' && method === 'POST') return unsupported('pat')
    if (path === '/api/message/forward' && method === 'POST') {
      const body = parseBody(req.body)
      const to =
        body.to_wxid || body.contactId || body.receiver || body.to || ''
      const xml = body.content || body.xml || ''
      if (xml && to) {
        if (!detectXmlKind(String(xml))) {
          return fail('不支持的 XML（需含 <img / <videomsg / <emoji ）')
        }
        if (!xmlOffsetsLookValid()) {
          return fail(
            'XML 转发偏移未校准：aixed Offsets 标注为 4.1.5.30，当前 4.1.10.27 Weixin.dll 虚表无效（已拦截避免崩溃）',
          )
        }
        const r = messageForwardXml(String(to), String(xml))
        return r < 0 ? fail('转发失败', r) : ok(r)
      }
      if (body.msgId != null && (body.receiver || body.to)) {
        return unsupported('按 msgId 转发（请传 to_wxid + content XML，对齐 aixed ForwardXMLMsg）')
      }
      return fail('需要 to_wxid/contactId 与 content/xml（img/videomsg/emoji）')
    }
    if (path === '/api/message/richText' && method === 'POST') return unsupported('richText')
    if (path === '/api/message/emotion' && method === 'POST') return unsupported('emotion')
    if (path === '/api/message/downloadAttach' && method === 'POST') return unsupported('downloadAttach')
    if (path === '/api/message/audio' && method === 'POST') return unsupported('audio')
    if (path === '/api/sns/refresh' && method === 'POST') return unsupported('sns')
    if (path === '/api/message/listen') return unsupported('recv hook（aixed RecvType 仅保留配置）')
    if (path === '/api/sns/listen') return unsupported('sns listen')
    if (path === '/api/push/config') return unsupported('push callback')

    if (path === '/api/room/add' && method === 'POST') {
      const body = parseBody(req.body)
      const r = roomAdd(body.roomId, body.wxids || [])
      return r === -2 ? unsupported('roomAdd') : ok(r)
    }
    if (path === '/api/room/invite' && method === 'POST') {
      const body = parseBody(req.body)
      const r = roomInvite(body.roomId, body.wxids || [])
      return r === -2 ? unsupported('roomInvite') : ok(r)
    }
    if (path === '/api/room/del' && method === 'POST') {
      const body = parseBody(req.body)
      const r = roomDel(body.roomId, body.wxids || [])
      return r === -2 ? unsupported('roomDel') : ok(r)
    }
    if (path === '/api/room/topic' && method === 'POST') {
      const body = parseBody(req.body)
      const r = roomTopic(body.roomId, body.topic || '')
      return r === -2 ? unsupported('roomTopic') : ok(r)
    }

    if (path === '/api/db/names') return ok(getDbNames())
    if (path === '/api/db/info') return ok(getDatabaseInfo())
    if (path === '/api/db/tables') {
      const dbName = q.dbName || q.db
      if (!dbName) return fail('需要 dbName')
      return ok(getDbTables(dbName))
    }
    if (path === '/api/db/query' && method === 'POST') {
      const body = parseBody(req.body)
      const dbName = body.dbName || body.optDbName
      const sql = body.sql || body.SQL
      if (!dbName || !sql) return fail('需要 dbName/optDbName 和 sql/SQL')
      const r = execDbQuery(String(dbName), String(sql))
      return r.status === 0 ? ok(r.data) : fail(r.desc || 'query failed', r)
    }

    if (path === '/api/message/history') {
      let talker = q.talker
      let limit = parseInt(q.limit || '20', 10)
      if (method === 'POST') {
        const body = parseBody(req.body)
        talker = body.talker || talker
        limit = body.limit || limit
      }
      if (!talker) return fail('需要 talker')
      return ok(queryChatHistory(String(talker), limit))
    }

    if (path === '/api/sessions') {
      let limit = parseInt(q.limit || '50', 10)
      if (method === 'POST') {
        const body = parseBody(req.body)
        limit = body.limit || limit
      }
      return ok(querySessionList(limit))
    }

    // aixed 原生路径别名（便于对照文档）
    if (path === '/SendTextMsg' && method === 'POST') {
      const body = parseBody(req.body)
      const r = messageSendText(String(body.wxidorgid || body.contactId), String(body.msg || body.text))
      return r < 0 ? fail('fail', r) : ok({ ret: 0, retmsg: 'success' })
    }
    if (path === '/SendImgMsg' && method === 'POST') {
      const body = parseBody(req.body)
      const r = messageSendImage(String(body.wxidorgid || body.contactId), String(body.path))
      return r < 0 ? fail('fail', r) : ok({ ret: 0, retmsg: 'success' })
    }
    if (path === '/Decode_Pic' && method === 'POST') {
      const body = parseBody(req.body)
      const r = decryptImage(String(body.src_path), String(body.dst_path))
      return r < 0 ? fail('fail', r) : ok({ ret: 0, retmsg: 'success' })
    }
    if (path === '/ForwardXMLMsg' && method === 'POST') {
      const body = parseBody(req.body)
      const to = String(body.to_wxid || body.contactId || '')
      const xml = String(body.content || body.xml || '')
      if (!to || !xml) return fail('需要 to_wxid 与 content')
      if (!detectXmlKind(xml)) return fail('不支持的 XML（需含 <img / <videomsg / <emoji ）')
      if (!xmlOffsetsLookValid()) {
        return fail(
          'XML 转发偏移未校准：aixed Offsets 标注为 4.1.5.30，当前 4.1.10.27 Weixin.dll 虚表无效（已拦截避免崩溃）',
        )
      }
      const r = messageForwardXml(to, xml)
      return r < 0 ? fail('fail', r) : ok({ ret: 0, retmsg: 'success' })
    }
    if (path === '/GetSelfProfile' && method === 'POST') return ok(contactSelfInfo())
    if (path === '/QueryDB/status') {
      return ok({ IsLogin: checkLogin() === 1 ? 1 : 0, hWeixin: Process.getModuleByName(WX_DLL).base.toString() })
    }
    if (path === '/QueryDB/GetAllDBName' && method === 'POST') return ok(getDatabaseInfo())
    if (path === '/QueryDB/execute' && method === 'POST') {
      const body = parseBody(req.body)
      return ok(execDbQuery(String(body.optDbName || ''), String(body.SQL || '')))
    }

    return fail(`未知路径: ${path}`)
  } catch (e: any) {
    return fail(e && e.message ? e.message : String(e))
  }
}

// startHttpServer 内部已 listen，勿再调 start()，否则会双绑端口
httpHandle = startHttpServer(HTTP_PORT, handleRequest as any)
log('INIT', `HTTP listening on :${HTTP_PORT}`)

rpc.exports = {
  checkLogin,
  contactSelfInfo,
  contactList,
  contactRawPayload,
  roomList,
  roomRawPayload,
  roomMemberList,
  roomMemberRawPayload,
  roomAdd,
  roomInvite,
  roomDel,
  roomTopic,
  messageSendText,
  messageSendImage,
  messageSendFile,
  messageSendPat,
  messageForward,
  messageForwardXml,
  messageSendRichText,
  messageSendEmotion,
  decryptImage,
  downloadAttach,
  getAudio,
  refreshPyq,
  getMsgTypes,
  getDbNames,
  getDbTables,
  execDbQuery,
  getDatabaseInfo,
  queryChatHistory,
  querySessionList,
  stopHttpServer() {
    if (httpHandle) {
      httpHandle.close()
      httpHandle = null
    }
    return true
  },
  startHttpServer() {
    if (!httpHandle) {
      httpHandle = startHttpServer(HTTP_PORT, handleRequest as any)
    }
    httpHandle.start()
    return true
  },
  ping() {
    return { ok: true, version: WX_VERSION }
  },
}
