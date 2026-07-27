import { request, requestOk, uploadBinary } from './client'
import type {
  ApiResponse,
  ChatHistoryResult,
  Contact,
  ContactInfo,
  PushConfig,
  Room,
  RoomInfo,
  RoomMember,
} from './types'

export const api = {
  health: (base: string) =>
    requestOk<{ status: string; timestamp: string; apis?: string[] }>(base, 'GET', '/api/health'),

  checkLogin: async (base: string) => {
    const res = await request<number>(base, 'GET', '/api/checkLogin')
    if (res.code !== 1) throw new Error(res.msg || '检查登录失败')
    return res.data
  },

  getSelf: (base: string) => requestOk<Contact>(base, 'GET', '/api/contacts/self'),

  getContacts: (base: string) => requestOk<Contact[]>(base, 'GET', '/api/contacts'),

  getContact: (base: string, contactId: string) =>
    requestOk<ContactInfo>(base, 'GET', '/api/contact', undefined, { contactId }),

  getRooms: (base: string) => requestOk<Room[]>(base, 'GET', '/api/rooms'),

  getRoom: (base: string, roomId: string) =>
    requestOk<RoomInfo>(base, 'GET', '/api/room', undefined, { roomId }),

  getRoomMembers: async (base: string, roomId: string) => {
    const data = await requestOk<{ members?: RoomMember[] } | RoomMember[]>(
      base,
      'GET',
      '/api/room/members',
      undefined,
      { roomId },
    )
    if (Array.isArray(data)) return data
    return data?.members || []
  },

  getRoomMember: (base: string, roomId: string, contactId: string) =>
    request<unknown>(base, 'GET', '/api/room/member', undefined, { roomId, contactId }),

  roomAdd: (base: string, roomId: string, wxids: string) =>
    requestOk(base, 'POST', '/api/room/add', { roomId, wxids }),

  roomInvite: (base: string, roomId: string, wxids: string) =>
    requestOk(base, 'POST', '/api/room/invite', { roomId, wxids }),

  roomDel: (base: string, roomId: string, wxids: string) =>
    requestOk(base, 'POST', '/api/room/del', { roomId, wxids }),

  roomTopic: (base: string, roomId: string, topic: string) =>
    requestOk(base, 'POST', '/api/room/topic', { roomId, topic }),

  messageTypes: (base: string) => requestOk(base, 'GET', '/api/message/types'),

  getMessageListen: (base: string) => requestOk<{ enabled?: boolean } | boolean>(base, 'GET', '/api/message/listen'),

  setMessageListen: (base: string, enabled: boolean) =>
    requestOk(base, 'POST', '/api/message/listen', { enabled }),

  history: (
    base: string,
    opts: {
      talker: string
      limit?: number
      offset?: number
      order?: 'asc' | 'desc'
      type?: number
    },
  ) =>
    requestOk<ChatHistoryResult>(base, 'GET', '/api/message/history', undefined, {
      talker: opts.talker,
      limit: opts.limit,
      offset: opts.offset,
      order: opts.order,
      type: opts.type,
    }),

  sessions: (
    base: string,
    opts?: { limit?: number; offset?: number; includeStranger?: boolean },
  ) =>
    requestOk<{
      total: number
      limit: number
      offset: number
      items: Array<{
        id: string
        name: string
        avatar: string
        kind: 'contact' | 'room'
        unreadCount: number
        isSend: number
        lastMsgType: number
        lastContent: string
        lastTime: number
        lastTimeText: string
        othersAtMe: number
        order: number
      }>
    }>(base, 'GET', '/api/sessions', undefined, {
      limit: opts?.limit,
      offset: opts?.offset,
      includeStranger: opts?.includeStranger ? 1 : undefined,
    }),

  sendText: (base: string, contactId: string, text: string, atWxids?: string[]) =>
    requestOk(base, 'POST', '/api/message/text', { contactId, text, atWxids }),

  sendImage: (base: string, contactId: string, path: string) =>
    requestOk(base, 'POST', '/api/message/image', { contactId, path }),

  sendFile: (base: string, contactId: string, path: string) =>
    requestOk(base, 'POST', '/api/message/file', { contactId, path }),

  sendEmotion: (base: string, contactId: string, path: string) =>
    requestOk(base, 'POST', '/api/message/emotion', { contactId, path }),

  sendRichText: (
    base: string,
    body: {
      receiver: string
      title?: string
      url?: string
      digest?: string
      thumburl?: string
      account?: string
      name?: string
    },
  ) => requestOk(base, 'POST', '/api/message/richText', body),

  pat: (base: string, roomId: string, contactId: string) =>
    requestOk(base, 'POST', '/api/message/pat', { roomId, contactId }),

  forward: (base: string, msgId: string, receiver: string) =>
    requestOk(base, 'POST', '/api/message/forward', { msgId, receiver }),

  downloadAttach: (base: string, body: { msgId: string; thumb?: string; extra?: string }) =>
    requestOk(base, 'POST', '/api/message/downloadAttach', body),

  decryptImage: (base: string, src: string, dir?: string) =>
    requestOk(base, 'POST', '/api/message/decryptImage', { src, dir }),

  audio: (base: string, msgId: string, dir: string) =>
    requestOk(base, 'POST', '/api/message/audio', { msgId, dir }),

  downloadFinderVideo: (base: string, body: { url: string; msgId?: string; savePath?: string }) =>
    requestOk(base, 'POST', '/api/message/downloadFinderVideo', body),

  getSnsListen: (base: string) => requestOk(base, 'GET', '/api/sns/listen'),

  setSnsListen: (base: string, enabled: boolean) =>
    requestOk(base, 'POST', '/api/sns/listen', { enabled }),

  snsRefresh: (base: string, id = 0) => requestOk(base, 'POST', '/api/sns/refresh', { id }),

  dbNames: (base: string) => requestOk<string[]>(base, 'GET', '/api/db/names'),

  dbTables: (base: string, dbName: string) =>
    requestOk(base, 'GET', '/api/db/tables', undefined, { dbName }),

  dbQuery: (base: string, dbName: string, sql: string) =>
    requestOk(base, 'POST', '/api/db/query', { dbName, sql }),

  getPushConfig: (base: string) => requestOk<PushConfig>(base, 'GET', '/api/push/config'),

  setPushConfig: (base: string, enabled: boolean, callbackUrl?: string) =>
    requestOk(base, 'POST', '/api/push/config', { enabled, callbackUrl }),

  serverStatus: (base: string) => requestOk(base, 'GET', '/api/server/status'),

  serverStop: (base: string) => requestOk(base, 'POST', '/api/server/stop'),

  serverStart: (base: string) => requestOk(base, 'POST', '/api/server/start'),

  upload: (
    base: string,
    file: Blob,
    filename: string,
    category: 'image' | 'file' | 'emotion' = 'file',
  ) => uploadBinary(base, file, filename, category),

  raw: request as typeof request,
}

export type { ApiResponse }
