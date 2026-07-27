export interface ApiResponse<T = unknown> {
  code: number
  data: T
  msg: string
}

export interface Contact {
  id: string
  name: string
  avatar: string
  gender?: number
  type?: number
  alias?: string
  city?: string
  province?: string
  weixin?: string
  friend?: boolean
  star?: boolean
  [key: string]: unknown
}

export interface ContactInfo {
  UserName?: string
  Alias?: string
  NickName?: string
  Remark?: string
  BigHeadImgUrl?: string
  SmallHeadImgUrl?: string
  Sex?: number
  Province?: string
  City?: string
  error?: boolean
  message?: string
  [key: string]: unknown
}

export interface Room {
  id: string
  name: string
  type?: number
  avatar?: string
  [key: string]: unknown
}

export interface RoomInfo {
  id: string
  name?: string
  topic?: string
  notice?: string
  admin?: string
  alias?: string
  remark?: string
  error?: boolean
  message?: string
  [key: string]: unknown
}

export interface RoomMember {
  wxid: string
  alias?: string
  name?: string
  remark?: string
  displayName?: string
  avatar?: string
  [key: string]: unknown
}

export interface ChatHistoryItem {
  localId: string
  msgId: string
  type: number
  subType: number
  isSender: number
  createTime: number
  createTimeText: string
  talker: string
  content: string
  displayContent: string
  dbName: string
}

export interface ChatHistoryResult {
  talker: string
  total: number
  limit: number
  offset: number
  order: 'asc' | 'desc'
  items: ChatHistoryItem[]
}

export interface PushConfig {
  enabled: boolean
  callbackUrl: string
}

export interface SessionItem {
  id: string
  name: string
  avatar: string
  kind: 'contact' | 'room'
  lastPreview?: string
  lastTime?: number
}

export type NavView = 'chat' | 'contacts' | 'rooms' | 'tools'
