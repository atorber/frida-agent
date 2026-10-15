/**
 * In-process SQLite (aixed xdb/db_mgr.cpp): scan SQLITE3_VFS ptr to find db handles.
 */
import { offsets, WX_DLL } from './offset.js'
import { log, md5Hex } from './utils.js'

const SQLITE_OK = 0
const SQLITE_ROW = 100
const SQLITE_MISUSE = 21

const dbMap = new Map<string, NativePointer>()

function base(): NativePointer {
  return Process.getModuleByName(WX_DLL).base
}

function apiSlot(fieldOff: number): NativePointer {
  return base().add(offsets.SQLITE3_API_ROUTINES).add(fieldOff).readPointer()
}

function fn(fieldOff: number, ret: string, args: string[]): any {
  return new NativeFunction(apiSlot(fieldOff), ret as any, args as any)
}

function getApi() {
  return {
    prepare: fn(offsets.api_prepare, 'int', ['pointer', 'pointer', 'int', 'pointer', 'pointer']),
    step: fn(offsets.api_step, 'int', ['pointer']),
    finalize: fn(offsets.api_finalize, 'int', ['pointer']),
    column_blob: fn(offsets.api_column_blob, 'pointer', ['pointer', 'int']),
    column_bytes: fn(offsets.api_column_bytes, 'int', ['pointer', 'int']),
    column_count: fn(offsets.api_column_count, 'int', ['pointer']),
    column_name: fn(offsets.api_column_name, 'pointer', ['pointer', 'int']),
    column_type: fn(offsets.api_column_type, 'int', ['pointer', 'int']),
    errcode: fn(offsets.api_errcode, 'int', ['pointer']),
  }
}

function toHex(bytes: ArrayBuffer | null, len: number): string {
  if (!bytes || len <= 0) return ''
  const u8 = new Uint8Array(bytes)
  let s = ''
  const hex = '0123456789ABCDEF'
  for (let i = 0; i < len && i < u8.length; i++) {
    s += hex[u8[i] >> 4] + hex[u8[i] & 0xf]
  }
  return s
}

function executeOnHandle(db: NativePointer, sql: string): { status: number; desc: string; data: any[] } {
  const api = getApi()
  if (db.isNull()) return { status: -1, desc: 'input db handle is nullptr', data: [] }
  const stmtBuf = Memory.alloc(Process.pointerSize)
  stmtBuf.writePointer(ptr(0))
  const sqlPtr = Memory.allocUtf8String(sql)
  const rc = api.prepare(db, sqlPtr, -1, stmtBuf, ptr(0)) as number
  if (rc !== SQLITE_OK) {
    return { status: rc, desc: 'sqlite3_prepare failed rc=' + rc, data: [] }
  }
  const stmt = stmtBuf.readPointer()
  const items: any[] = []
  try {
    while ((api.step(stmt) as number) === SQLITE_ROW) {
      const cols = api.column_count(stmt) as number
      const item: Record<string, string> = {}
      for (let i = 0; i < cols; i++) {
        const namePtr = api.column_name(stmt, i) as NativePointer
        const key = namePtr.isNull() ? 'col' + i : namePtr.readUtf8String() || 'col' + i
        const nType = api.column_type(stmt, i) as number
        const blob = api.column_blob(stmt, i) as NativePointer
        const nLen = api.column_bytes(stmt, i) as number
        if (nType === 4) {
          item[key] = blob.isNull() ? '' : toHex(blob.readByteArray(nLen), nLen)
        } else if (blob.isNull() || nLen <= 0) {
          item[key] = ''
        } else {
          item[key] = blob.readUtf8String(nLen) || ''
        }
      }
      items.push(item)
    }
  } finally {
    api.finalize(stmt)
  }
  return { status: 0, desc: '', data: items }
}

export function searchDatabases(force = false): Map<string, NativePointer> {
  if (!force && dbMap.size > 0) {
    const api = getApi()
    let ok = true
    for (const h of dbMap.values()) {
      try {
        if ((api.errcode(h) as number) === SQLITE_MISUSE) {
          ok = false
          break
        }
      } catch {
        ok = false
        break
      }
    }
    if (ok) return dbMap
  }

  dbMap.clear()
  const vfsAddr = base().add(offsets.SQLITE3_VFS)
  const lo = vfsAddr.and(ptr('0xffffffff')).toInt32() >>> 0
  const hi = vfsAddr.shr(32).toInt32() >>> 0
  const b0 = (n: number) => ('0' + (n & 0xff).toString(16)).slice(-2)
  const pattern =
    b0(lo) +
    ' ' +
    b0(lo >>> 8) +
    ' ' +
    b0(lo >>> 16) +
    ' ' +
    b0(lo >>> 24) +
    ' ' +
    b0(hi) +
    ' ' +
    b0(hi >>> 8) +
    ' ' +
    b0(hi >>> 16) +
    ' ' +
    b0(hi >>> 24)

  const api = getApi()
  const ranges = Process.enumerateRanges('rw-')
  for (const range of ranges) {
    if (range.size > 32 * 1024 * 1024) continue
    try {
      const hits = Memory.scanSync(range.base, range.size, pattern)
      for (const hit of hits) {
        const candidate = hit.address
        try {
          if ((api.errcode(candidate) as number) !== SQLITE_OK) continue
          const list = executeOnHandle(candidate, 'PRAGMA database_list')
          if (!list.data.length) continue
          const file = list.data[0].file || ''
          if (!file) continue
          const slash = Math.max(file.lastIndexOf('\\'), file.lastIndexOf('/'))
          const name = slash >= 0 ? file.substring(slash + 1) : file
          if (name) dbMap.set(name, candidate)
        } catch (e) {}
      }
    } catch (e) {}
  }
  log('DB', 'searchDatabases found ' + dbMap.size + ':', Array.from(dbMap.keys()).join(', '))
  return dbMap
}

export function getDbNames(): string[] {
  return Array.from(searchDatabases().keys())
}

export function getDbHandles(): Map<string, NativePointer> {
  return searchDatabases()
}

export function getDatabaseInfo(): Array<{ dbName: string; dbHandle: string }> {
  const m = searchDatabases(true)
  return Array.from(m.entries()).map(([dbName, h]) => ({
    dbName,
    dbHandle: h.toString(),
  }))
}

export function execDbQuery(dbName: string, sql: string): { status: number; desc: string; data: any[] } {
  const m = searchDatabases()
  const h = m.get(dbName)
  if (!h) return { status: -1, desc: 'get database handle which named ' + dbName + ' failed', data: [] }
  return executeOnHandle(h, sql)
}

export function getDbTables(dbName: string): Array<{ name: string; sql: string }> {
  const r = execDbQuery(
    dbName,
    "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name",
  )
  return (r.data || []).map((row: any) => ({ name: row.name || '', sql: row.sql || '' }))
}

export function queryChatHistory(talker: string, limit = 20): any[] {
  const lim = Math.max(1, Math.min(limit, 200))
  const table = 'Msg_' + md5Hex(talker)
  const names = getDbNames().filter((n) => /^message_\d+\.db$/i.test(n))
  for (const db of names) {
    const exists = execDbQuery(
      db,
      "SELECT name FROM sqlite_master WHERE type='table' AND name='" + table + "' LIMIT 1",
    )
    if (exists.status !== 0 || !exists.data.length) continue
    const sql =
      'SELECT local_id, server_id, local_type, create_time, real_sender_id, status, message_content, source ' +
      'FROM ' +
      table +
      ' ORDER BY create_time DESC LIMIT ' +
      lim
    const r = execDbQuery(db, sql)
    if (r.status === 0) {
      return r.data.map((row: any) => ({
        ...row,
        talker,
        dbName: db,
        table,
      }))
    }
  }
  return []
}

export function querySessionList(limit = 50): any[] {
  const lim = Math.max(1, Math.min(limit, 200))
  const r = execDbQuery(
    'session.db',
    'SELECT username, type, unread_count, summary, last_timestamp, sort_timestamp, ' +
      'last_msg_sender, last_sender_display_name, last_msg_type, is_hidden ' +
      'FROM SessionTable WHERE is_hidden=0 ORDER BY sort_timestamp DESC LIMIT ' +
      lim,
  )
  return r.status === 0 ? r.data : []
}
