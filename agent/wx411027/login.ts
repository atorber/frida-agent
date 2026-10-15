/**
 * 登录 / 账号资料（aixed 无原生 GetAccountService；用 contact.db 路径 + Contact 行）
 */
import { execDbQuery, getDatabaseInfo, searchDatabases } from './sqlite.js'
import { log } from './utils.js'

const CONTACT_DB = 'contact.db'

let cachedSelf: any = null

export function checkLogin(): number {
  try {
    const info = getDatabaseInfo()
    return info.some((d) => /^(contact|session|message_\d+)\.db$/i.test(d.dbName)) ? 1 : -1
  } catch {
    return -1
  }
}

/** 从 db 路径解析账号目录名，并规范成 wxid（去掉 _xxxx 后缀） */
function extractAccountFromPath(): { folder: string; wxid: string; home: string } {
  try {
    searchDatabases()
    const r = execDbQuery(CONTACT_DB, 'PRAGMA database_list')
    const file = (r.data[0] && r.data[0].file) || ''
    let m = file.match(/xwechat_files[\\/]([^\\/]+)[\\/]/i)
    if (!m) m = file.match(/WeChat Files[\\/]([^\\/]+)[\\/]/i)
    if (!m || !m[1]) return { folder: '', wxid: '', home: '' }
    const folder = m[1]
    if (folder === 'All Users' || folder === 'Applet') return { folder: '', wxid: '', home: '' }
    const wxid = folder.replace(/_[0-9a-f]{4}$/i, '')
    const idx = file.toLowerCase().indexOf(folder.toLowerCase())
    const home = idx >= 0 ? file.substring(0, idx + folder.length + 1) : ''
    return { folder, wxid, home }
  } catch (e) {}
  return { folder: '', wxid: '', home: '' }
}

export function getSelfWxid(): string {
  const info = getUserInfo()
  return info.wxid || info.id || ''
}

export function getUserInfo(): any {
  if (cachedSelf && cachedSelf.wxid) return cachedSelf
  const acc = extractAccountFromPath()
  let wxid = acc.wxid
  let row: any = {}
  if (wxid) {
    const sql =
      "SELECT username, nick_name, alias, remark, local_type, verify_flag, big_head_url, small_head_url " +
      "FROM contact WHERE username='" +
      wxid.replace(/'/g, "''") +
      "' LIMIT 1"
    const r = execDbQuery(CONTACT_DB, sql)
    if (r.status === 0 && r.data.length) {
      row = r.data[0]
      wxid = row.username || wxid
    }
  }
  cachedSelf = {
    id: row.username || wxid,
    wxid: row.username || wxid,
    name: row.nick_name || '',
    nickname: row.nick_name || '',
    alias: row.alias || '',
    remark: row.remark || '',
    avatar: row.big_head_url || row.small_head_url || '',
    phone: '',
    email: '',
    qq: 0,
    proiv: '',
    area: '',
    signinfo: '',
  }
  log('LOGIN', 'self=', JSON.stringify(cachedSelf))
  return cachedSelf
}

export function getHomePath(): string {
  return extractAccountFromPath().home
}

export function contactSelfInfo(): any {
  return getUserInfo()
}
