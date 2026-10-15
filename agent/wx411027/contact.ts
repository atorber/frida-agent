/**
 * 联系人（4.1.x contact.db.contact，对齐 wx391027 接口形态）
 */
import { execDbQuery } from './sqlite.js'
import { getSelfWxid } from './login.js'
import { Contact } from './types.js'

const CONTACT_DB = 'contact.db'

function mapContact(row: any): Contact {
  const id = row.username || row.UserName || ''
  const localType = parseInt(row.local_type || row.Type || '0', 10) || 0
  const verify = parseInt(row.verify_flag || row.VerifyFlag || '0', 10) || 0
  return {
    id,
    gender: 0,
    type: localType,
    name: row.nick_name || row.NickName || row.remark || '',
    avatar: row.big_head_url || row.small_head_url || '',
    address: '',
    alias: row.alias || row.Alias || row.remark || '',
    city: '',
    friend: localType === 1 && verify === 0 && !id.includes('@'),
    province: '',
    signature: row.description || '',
    star: false,
    weixin: row.alias || '',
    corporation: '',
    title: '',
    description: row.remark || row.Remark || '',
    coworker: false,
    phone: [],
  }
}

export function contactList(): Contact[] {
  const self = getSelfWxid()
  // local_type=1：好友/系统号；排除群、公众号、陌生人
  const sql =
    "SELECT username, nick_name, alias, remark, local_type, verify_flag, big_head_url, small_head_url, description " +
    "FROM contact WHERE delete_flag=0 AND local_type=1 AND verify_flag=0 " +
    "AND username NOT LIKE '%@chatroom' AND username NOT LIKE '%@openim' " +
    "AND username NOT LIKE 'gh_%' LIMIT 5000"
  const r = execDbQuery(CONTACT_DB, sql)
  if (r.status !== 0) return []
  return r.data.map(mapContact).filter((c) => c.id && c.id !== self)
}

export function contactRawPayload(id: string): Contact | null {
  const sql =
    "SELECT username, nick_name, alias, remark, local_type, verify_flag, big_head_url, small_head_url, description " +
    "FROM contact WHERE username='" +
    String(id).replace(/'/g, "''") +
    "' LIMIT 1"
  const r = execDbQuery(CONTACT_DB, sql)
  if (r.status !== 0 || !r.data.length) return null
  return mapContact(r.data[0])
}

export { contactSelfInfo } from './login.js'
