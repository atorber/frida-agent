import { useCallback, useEffect, useState } from 'react'
import { api } from '../api/endpoints'
import type { Contact } from '../api/types'
import { useAgent } from '../context/AgentContext'
import { Avatar } from './Avatar'

type Tab = 'service' | 'listen' | 'push' | 'db' | 'media'

type HealthInfo = { status: string; timestamp: string; apis?: string[] }
type ServerStatus = { closed?: boolean; port?: number; host?: string; [k: string]: unknown }

const tabs: { id: Tab; label: string; lead: string }[] = [
  { id: 'service', label: '服务', lead: '连接健康、登录态与 HTTP 监听' },
  { id: 'listen', label: '接收', lead: '消息与动态的接收开关' },
  { id: 'push', label: '推送', lead: '回调到你的业务服务' },
  { id: 'db', label: '数据', lead: '只读查询本地微信库' },
  { id: 'media', label: '媒体', lead: '附件、语音与视频号工具' },
]

function StatusDot({ ok, warn }: { ok?: boolean; warn?: boolean }) {
  const cls = warn ? 'warn' : ok ? 'ok' : 'off'
  return <span className={`svc-dot ${cls}`} aria-hidden />
}

export function ToolsPanel() {
  const { baseUrl, refresh } = useAgent()
  const [tab, setTab] = useState<Tab>('service')
  const [result, setResult] = useState('')
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [msgListen, setMsgListen] = useState(false)
  const [snsListen, setSnsListen] = useState(false)
  const [pushEnabled, setPushEnabled] = useState(false)
  const [callbackUrl, setCallbackUrl] = useState('http://127.0.0.1:19089/apps/hook')
  const [dbNames, setDbNames] = useState<string[]>([])
  const [dbName, setDbName] = useState('')
  const [sql, setSql] = useState("SELECT name FROM sqlite_master WHERE type='table' LIMIT 20;")
  const [msgId, setMsgId] = useState('')
  const [mediaPath, setMediaPath] = useState('')
  const [mediaDir, setMediaDir] = useState('')
  const [finderUrl, setFinderUrl] = useState('')

  const [svcLoading, setSvcLoading] = useState(false)
  const [health, setHealth] = useState<HealthInfo | null>(null)
  const [loggedIn, setLoggedIn] = useState<boolean | null>(null)
  const [self, setSelf] = useState<Contact | null>(null)
  const [server, setServer] = useState<ServerStatus | null>(null)
  const [svcUpdatedAt, setSvcUpdatedAt] = useState<string>('')

  const show = (data: unknown) =>
    setResult(typeof data === 'string' ? data : JSON.stringify(data, null, 2))

  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true)
    setErr(null)
    try {
      const data = await fn()
      show(data ?? 'ok')
      return data
    } catch (e) {
      setErr((e as Error).message)
      throw e
    } finally {
      setBusy(false)
    }
  }

  const loadService = useCallback(async () => {
    setSvcLoading(true)
    setErr(null)
    try {
      const [h, login, me, st] = await Promise.all([
        api.health(baseUrl).catch((e) => {
          throw e
        }),
        api.checkLogin(baseUrl).catch(() => 0),
        api.getSelf(baseUrl).catch(() => null),
        api.serverStatus(baseUrl).catch(() => null),
      ])
      setHealth(h)
      const ok = login === 1
      setLoggedIn(ok)
      setSelf(ok ? me : null)
      setServer(st as ServerStatus | null)
      setSvcUpdatedAt(new Date().toLocaleTimeString('zh-CN', { hour12: false }))
    } catch (e) {
      setHealth(null)
      setLoggedIn(null)
      setSelf(null)
      setServer(null)
      setErr((e as Error).message)
    } finally {
      setSvcLoading(false)
    }
  }, [baseUrl])

  const loadListen = async () => {
    try {
      const [m, s] = await Promise.all([api.getMessageListen(baseUrl), api.getSnsListen(baseUrl)])
      setMsgListen(typeof m === 'boolean' ? m : !!(m as { enabled?: boolean })?.enabled)
      setSnsListen(typeof s === 'boolean' ? s : !!(s as { enabled?: boolean })?.enabled)
    } catch (e) {
      setErr((e as Error).message)
    }
  }

  useEffect(() => {
    if (tab === 'service') void loadService()
    if (tab === 'listen') void loadListen()
    if (tab === 'push') {
      void api
        .getPushConfig(baseUrl)
        .then((cfg) => {
          setPushEnabled(!!cfg.enabled)
          if (cfg.callbackUrl) setCallbackUrl(cfg.callbackUrl)
          show(cfg)
        })
        .catch((e) => setErr((e as Error).message))
    }
    if (tab === 'db') {
      void api
        .dbNames(baseUrl)
        .then((names) => {
          setDbNames(names || [])
          if (names?.[0] && !dbName) setDbName(names[0])
        })
        .catch((e) => setErr((e as Error).message))
    }
  }, [tab, baseUrl, loadService])

  const current = tabs.find((t) => t.id === tab)!
  const healthOk = !!health
  const httpRunning = !!server && server.closed !== true

  return (
    <div className="tools">
      <aside className="tools-side">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            className={tab === t.id ? 'on' : ''}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </aside>
      <div className="tools-main">
        <h2>{current.label}</h2>
        <p className="lead">{current.lead}</p>
        {err && <div className="banner error">{err}</div>}

        {tab === 'service' && (
          <div className="svc">
            <div className="svc-toolbar">
              <span className="svc-meta">
                {svcLoading ? '同步中…' : svcUpdatedAt ? `更新于 ${svcUpdatedAt}` : '等待同步'}
              </span>
              <button
                type="button"
                className="btn soft"
                disabled={svcLoading || busy}
                onClick={() => void loadService()}
              >
                刷新
              </button>
            </div>

            <div className="svc-grid">
              <div className="svc-card">
                <div className="svc-card-top">
                  <StatusDot ok={healthOk} />
                  <span className="svc-k">Agent 健康</span>
                </div>
                <div className="svc-v">{healthOk ? '正常' : svcLoading ? '…' : '不可用'}</div>
                <div className="svc-sub mono">{baseUrl}</div>
                {health?.timestamp && <div className="svc-sub">{health.timestamp}</div>}
              </div>

              <div className="svc-card">
                <div className="svc-card-top">
                  <StatusDot ok={loggedIn === true} warn={loggedIn === false} />
                  <span className="svc-k">微信登录</span>
                </div>
                <div className="svc-v">
                  {loggedIn === null ? (svcLoading ? '…' : '未知') : loggedIn ? '已登录' : '未登录'}
                </div>
                <div className="svc-sub">checkLogin = {loggedIn === null ? '—' : loggedIn ? '1' : '0'}</div>
              </div>

              <div className="svc-card">
                <div className="svc-card-top">
                  <StatusDot ok={httpRunning && !!server} />
                  <span className="svc-k">HTTP 监听</span>
                </div>
                <div className="svc-v">
                  {!server ? (svcLoading ? '…' : '未知') : httpRunning ? '运行中' : '已停止'}
                </div>
                <div className="svc-sub mono">
                  {server?.port != null ? `0.0.0.0:${server.port}` : '—'}
                </div>
              </div>

              <div className="svc-card svc-card-account">
                <div className="svc-card-top">
                  <StatusDot ok={!!self} />
                  <span className="svc-k">当前账号</span>
                </div>
                {self ? (
                  <div className="svc-account">
                    <Avatar name={self.name || self.id} src={self.avatar} size="md" />
                    <div>
                      <div className="svc-v">{self.name || '未命名'}</div>
                      <div className="svc-sub mono">{self.id}</div>
                      {self.weixin ? <div className="svc-sub">微信号 {String(self.weixin)}</div> : null}
                    </div>
                  </div>
                ) : (
                  <>
                    <div className="svc-v">{svcLoading ? '…' : '无'}</div>
                    <div className="svc-sub">登录后显示账号资料</div>
                  </>
                )}
              </div>
            </div>

            {health?.apis && health.apis.length > 0 && (
              <div className="svc-apis">
                <div className="svc-apis-title">已注册接口 · {health.apis.length}</div>
                <ul className="svc-api-list">
                  {health.apis.map((a) => (
                    <li key={a}>
                      <code>{a}</code>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div className="svc-actions">
              <button
                type="button"
                className="btn primary"
                disabled={busy || svcLoading}
                onClick={() =>
                  void (async () => {
                    setBusy(true)
                    setErr(null)
                    setResult('')
                    try {
                      await api.serverStart(baseUrl)
                      await refresh()
                      await loadService()
                    } catch (e) {
                      setErr((e as Error).message)
                    } finally {
                      setBusy(false)
                    }
                  })()
                }
              >
                启动 HTTP
              </button>
              <button
                type="button"
                className="btn ghost"
                disabled={busy || svcLoading}
                onClick={() =>
                  void (async () => {
                    setBusy(true)
                    setErr(null)
                    setResult('')
                    try {
                      await api.serverStop(baseUrl)
                      await refresh()
                      await loadService()
                    } catch (e) {
                      setErr((e as Error).message)
                    } finally {
                      setBusy(false)
                    }
                  })()
                }
              >
                停止 HTTP
              </button>
            </div>
          </div>
        )}

        {tab === 'listen' && (
          <div className="setting-list">
            <div className="setting-row">
              <div>
                <div className="label">聊天消息</div>
                <div className="desc">Hook 接收实时聊天</div>
              </div>
              <button
                type="button"
                className="btn soft"
                disabled={busy}
                onClick={() =>
                  void run(async () => {
                    const next = !msgListen
                    const r = await api.setMessageListen(baseUrl, next)
                    setMsgListen(next)
                    return r
                  })
                }
              >
                {msgListen ? '已开启' : '已关闭'}
              </button>
            </div>
            <div className="setting-row">
              <div>
                <div className="label">朋友圈</div>
                <div className="desc">接收动态流</div>
              </div>
              <button
                type="button"
                className="btn soft"
                disabled={busy}
                onClick={() =>
                  void run(async () => {
                    const next = !snsListen
                    const r = await api.setSnsListen(baseUrl, next)
                    setSnsListen(next)
                    return r
                  })
                }
              >
                {snsListen ? '已开启' : '已关闭'}
              </button>
            </div>
            <div className="setting-row">
              <div>
                <div className="label">刷新首页</div>
                <div className="desc">需先开启朋友圈接收</div>
              </div>
              <button
                type="button"
                className="btn ghost"
                disabled={busy}
                onClick={() => void run(() => api.snsRefresh(baseUrl, 0))}
              >
                刷新
              </button>
            </div>
          </div>
        )}

        {tab === 'push' && (
          <>
            <div className="field">
              <span>回调 URL</span>
              <input value={callbackUrl} onChange={(e) => setCallbackUrl(e.target.value)} />
            </div>
            <div className="actions">
              <button
                type="button"
                className="btn primary"
                disabled={busy}
                onClick={() =>
                  void run(async () => {
                    const r = await api.setPushConfig(baseUrl, true, callbackUrl.trim())
                    setPushEnabled(true)
                    return r
                  })
                }
              >
                开启推送
              </button>
              <button
                type="button"
                className="btn ghost"
                disabled={busy}
                onClick={() =>
                  void run(async () => {
                    const r = await api.setPushConfig(baseUrl, false)
                    setPushEnabled(false)
                    return r
                  })
                }
              >
                关闭
              </button>
            </div>
            <p className="lead">状态：{pushEnabled ? '开启' : '关闭'} · 浏览器本身收不到推送</p>
          </>
        )}

        {tab === 'db' && (
          <>
            <div className="field">
              <span>数据库</span>
              <select value={dbName} onChange={(e) => setDbName(e.target.value)}>
                {dbNames.map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </select>
            </div>
            <div className="actions">
              <button
                type="button"
                className="btn ghost"
                disabled={busy || !dbName}
                onClick={() => void run(() => api.dbTables(baseUrl, dbName))}
              >
                列出表
              </button>
            </div>
            <div className="field">
              <span>SQL</span>
              <textarea value={sql} onChange={(e) => setSql(e.target.value)} />
            </div>
            <button
              type="button"
              className="btn primary"
              disabled={busy || !dbName || !sql.trim()}
              onClick={() => void run(() => api.dbQuery(baseUrl, dbName, sql.trim()))}
            >
              执行
            </button>
          </>
        )}

        {tab === 'media' && (
          <>
            <div className="field">
              <span>消息 ID</span>
              <input value={msgId} onChange={(e) => setMsgId(e.target.value)} />
            </div>
            <div className="field">
              <span>路径</span>
              <input value={mediaPath} onChange={(e) => setMediaPath(e.target.value)} />
            </div>
            <div className="field">
              <span>目录</span>
              <input value={mediaDir} onChange={(e) => setMediaDir(e.target.value)} />
            </div>
            <div className="actions">
              <button
                type="button"
                className="btn ghost"
                disabled={busy || !msgId}
                onClick={() =>
                  void run(() => api.downloadAttach(baseUrl, { msgId, extra: mediaPath || undefined }))
                }
              >
                下载附件
              </button>
              <button
                type="button"
                className="btn ghost"
                disabled={busy || !mediaPath}
                onClick={() => void run(() => api.decryptImage(baseUrl, mediaPath, mediaDir || undefined))}
              >
                解密图片
              </button>
              <button
                type="button"
                className="btn ghost"
                disabled={busy || !msgId || !mediaDir}
                onClick={() => void run(() => api.audio(baseUrl, msgId, mediaDir))}
              >
                导出语音
              </button>
            </div>
            <div className="field">
              <span>视频号 URL</span>
              <input value={finderUrl} onChange={(e) => setFinderUrl(e.target.value)} />
            </div>
            <button
              type="button"
              className="btn ghost"
              disabled={busy || !finderUrl}
              onClick={() =>
                void run(() =>
                  api.downloadFinderVideo(baseUrl, {
                    url: finderUrl,
                    msgId: msgId || undefined,
                    savePath: mediaPath || undefined,
                  }),
                )
              }
            >
              下载视频号
            </button>
          </>
        )}

        {tab !== 'service' && result && <pre className="console">{result}</pre>}
      </div>
    </div>
  )
}
