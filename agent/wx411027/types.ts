export interface Contact {
  id: string
  gender: number
  type: number
  name: string
  avatar: string
  address: string
  alias: string
  city: string
  friend?: boolean
  province: string
  signature?: string
  star?: boolean
  weixin: string
  corporation: string
  title: string
  description: string
  coworker: boolean
  phone: string[]
}

export interface Message {
  id: string
  filename?: string
  text: string
  timestamp: number
  type: number
  talkerId: string
  roomId: string
  listenerId?: string
  mentionIds: string[]
  isSelf: boolean
}

export interface RichTextMsg {
  name?: string
  account?: string
  title?: string
  digest?: string
  url?: string
  thumburl?: string
  receiver: string
}
