import { useEffect, useState } from 'react'
import { api } from '../api/endpoints'
import type { Contact, ContactInfo } from '../api/types'
import { useAgent } from '../context/AgentContext'
import { Avatar } from './Avatar'

type Props = { contact: Contact | null }

export function ContactPanel({ contact }: Props) {
  const { baseUrl, openSession } = useAgent()
  const [info, setInfo] = useState<ContactInfo | null>(null)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    setInfo(null)
    setErr(null)
    if (!contact) return
    void api
      .getContact(baseUrl, contact.id)
      .then(setInfo)
      .catch((e) => setErr((e as Error).message))
  }, [contact?.id, baseUrl])

  if (!contact) {
    return (
      <div className="stage-empty">
        <div>
          <h2>选择联系人</h2>
          <p>查看资料并发起私信。</p>
        </div>
      </div>
    )
  }

  const name = info?.Remark || info?.NickName || contact.name || contact.id
  const nick = info?.NickName && info.NickName !== name ? info.NickName : null
  const avatar = info?.BigHeadImgUrl || info?.SmallHeadImgUrl || contact.avatar
  const region = [info?.Province, info?.City].filter(Boolean).join(' · ')
  const aliasRaw = String(info?.Alias || contact.weixin || '').trim()
  // 过滤误读的 EncryptUserName（v3_…@stranger）
  const alias =
    aliasRaw && !aliasRaw.endsWith('@stranger') && !/^v\d+_/i.test(aliasRaw) ? aliasRaw : ''

  return (
    <div className="profile">
      {err && <div className="banner error">{err}</div>}
      <section className="profile-hero center">
        <Avatar src={String(avatar || '')} name={String(name)} size="lg" />
        <div className="identity">
          <h2>{name}</h2>
          {nick && <div className="sub">昵称 {nick}</div>}
          {alias && <div className="sub">{alias}</div>}
          {region && <div className="sub">{region}</div>}
        </div>
      </section>
      <div className="profile-cta">
        <button
          type="button"
          onClick={() =>
            openSession({
              id: contact.id,
              name: String(name),
              avatar: String(avatar || ''),
              kind: 'contact',
            })
          }
        >
          发消息
        </button>
      </div>
      <details className="fold">
        <summary>系统标识</summary>
        <p>
          <code>{contact.id}</code>
        </p>
      </details>
    </div>
  )
}
