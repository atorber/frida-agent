/**
 * 群（4.1.x contact.db: chat_room / chatroom_member / name2id / contact）
 * aixed 无加群/踢人/改群名原生 call -> 管理类接口返回 -2
 */
import { execDbQuery } from './sqlite.js'
import { Contact } from './types.js'

const CONTACT_DB = 'contact.db'

export function roomList(): Contact[] {
  const r = execDbQuery(
    CONTACT_DB,
    "SELECT username, nick_name, alias, remark, local_type, verify_flag, big_head_url, small_head_url " +
      "FROM contact WHERE username LIKE '%@chatroom' AND delete_flag=0 LIMIT 2000",
  )
  if (r.status !== 0) return []
  return r.data.map((row: any) => ({
    id: row.username || '',
    gender: 0,
    type: parseInt(row.local_type || '0', 10) || 0,
    name: row.nick_name || row.remark || row.username || '',
    avatar: row.big_head_url || row.small_head_url || '',
    address: '',
    alias: row.alias || '',
    city: '',
    friend: false,
    province: '',
    weixin: '',
    corporation: '',
    title: '',
    description: '',
    coworker: false,
    phone: [],
  }))
}

export function roomRawPayload(roomId: string): any {
  const id = String(roomId).replace(/'/g, "''")
  const c = execDbQuery(
    CONTACT_DB,
    "SELECT username, nick_name, alias, remark, big_head_url, small_head_url FROM contact WHERE username='" +
      id +
      "' LIMIT 1",
  )
  const room = execDbQuery(
    CONTACT_DB,
    "SELECT id, username, owner FROM chat_room WHERE username='" + id + "' LIMIT 1",
  )
  return {
    id: roomId,
    name: (c.data[0] && (c.data[0].nick_name || c.data[0].remark)) || roomId,
    owner: (room.data[0] && room.data[0].owner) || '',
    contact: c.data[0] || null,
    room: room.data[0] || null,
  }
}

export function roomMemberList(roomId: string): string[] {
  const id = String(roomId).replace(/'/g, "''")
  const r = execDbQuery(
    CONTACT_DB,
    "SELECT n.username AS username FROM chat_room cr " +
      "JOIN chatroom_member cm ON cr.id=cm.room_id " +
      "JOIN name2id n ON n.rowid=cm.member_id " +
      "WHERE cr.username='" +
      id +
      "'",
  )
  if (r.status !== 0 || !r.data.length) return []
  return r.data.map((row: any) => row.username).filter((s: string) => !!s)
}

export function roomMemberRawPayload(roomId: string, contactId: string): Contact | null {
  const r = execDbQuery(
    CONTACT_DB,
    "SELECT username, nick_name, alias, remark, local_type, verify_flag, big_head_url, small_head_url " +
      "FROM contact WHERE username='" +
      String(contactId).replace(/'/g, "''") +
      "' LIMIT 1",
  )
  if (r.status !== 0 || !r.data.length) {
    return {
      id: contactId,
      gender: 0,
      type: 0,
      name: contactId,
      avatar: '',
      address: '',
      alias: '',
      city: '',
      province: '',
      weixin: '',
      corporation: '',
      title: '',
      description: 'room=' + roomId,
      coworker: false,
      phone: [],
    }
  }
  const row = r.data[0]
  return {
    id: row.username || contactId,
    gender: 0,
    type: parseInt(row.local_type || '0', 10) || 0,
    name: row.nick_name || '',
    avatar: row.big_head_url || row.small_head_url || '',
    address: '',
    alias: row.alias || row.remark || '',
    city: '',
    province: '',
    weixin: row.alias || '',
    corporation: '',
    title: '',
    description: '',
    coworker: false,
    phone: [],
  }
}

export const roomAdd = (_roomId: string, _wxids: string[]): number => -2
export const roomInvite = (_roomId: string, _wxids: string[]): number => -2
export const roomDel = (_roomId: string, _wxids: string[]): number => -2
export const roomTopic = (_roomId: string, _topic: string): number => -2
export const installAddMemberHook = (): void => {}
