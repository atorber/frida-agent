import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import { api } from '../api/endpoints'
import { getStoredBaseUrl, setStoredBaseUrl } from '../api/client'
import type { Contact, NavView, SessionItem } from '../api/types'

const SESSIONS_KEY = 'wx391027.sessions'

function loadSessions(): SessionItem[] {
  try {
    const raw = localStorage.getItem(SESSIONS_KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw) as SessionItem[]
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

function saveSessions(list: SessionItem[]) {
  localStorage.setItem(SESSIONS_KEY, JSON.stringify(list.slice(0, 80)))
}

interface AgentState {
  baseUrl: string
  connected: boolean
  loggedIn: boolean
  self: Contact | null
  error: string | null
  refreshing: boolean
  view: NavView
  sessions: SessionItem[]
  activeTalker: string | null
  setBaseUrl: (url: string) => void
  setView: (v: NavView) => void
  setActiveTalker: (id: string | null) => void
  refresh: () => Promise<void>
  openSession: (item: SessionItem) => void
  touchSession: (id: string, preview?: string) => void
}

const AgentContext = createContext<AgentState | null>(null)

export function AgentProvider({ children }: { children: ReactNode }) {
  const [baseUrl, setBaseUrlState] = useState(getStoredBaseUrl)
  const [connected, setConnected] = useState(false)
  const [loggedIn, setLoggedIn] = useState(false)
  const [self, setSelf] = useState<Contact | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [refreshing, setRefreshing] = useState(false)
  const [view, setView] = useState<NavView>('chat')
  const [sessions, setSessions] = useState<SessionItem[]>(loadSessions)
  const [activeTalker, setActiveTalker] = useState<string | null>(null)

  const setBaseUrl = useCallback((url: string) => {
    const next = url.replace(/\/$/, '')
    setStoredBaseUrl(next)
    setBaseUrlState(next)
  }, [])

  const refresh = useCallback(async () => {
    setRefreshing(true)
    setError(null)
    try {
      await api.health(baseUrl)
      setConnected(true)
      const login = await api.checkLogin(baseUrl)
      const ok = login === 1
      setLoggedIn(ok)
      if (ok) {
        const me = await api.getSelf(baseUrl)
        setSelf(me)
      } else {
        setSelf(null)
      }
    } catch (e) {
      setConnected(false)
      setLoggedIn(false)
      setSelf(null)
      setError((e as Error).message || String(e))
    } finally {
      setRefreshing(false)
    }
  }, [baseUrl])

  useEffect(() => {
    void refresh()
    const t = window.setInterval(() => void refresh(), 30000)
    return () => window.clearInterval(t)
  }, [refresh])

  const openSession = useCallback((item: SessionItem) => {
    setSessions((prev) => {
      const rest = prev.filter((s) => s.id !== item.id)
      const next = [item, ...rest]
      saveSessions(next)
      return next
    })
    setActiveTalker(item.id)
    setView('chat')
  }, [])

  const touchSession = useCallback((id: string, preview?: string) => {
    setSessions((prev) => {
      const next = prev.map((s) =>
        s.id === id
          ? {
              ...s,
              lastPreview: preview ?? s.lastPreview,
              lastTime: Date.now(),
            }
          : s,
      )
      saveSessions(next)
      return next
    })
  }, [])

  const value = useMemo(
    () => ({
      baseUrl,
      connected,
      loggedIn,
      self,
      error,
      refreshing,
      view,
      sessions,
      activeTalker,
      setBaseUrl,
      setView,
      setActiveTalker,
      refresh,
      openSession,
      touchSession,
    }),
    [
      baseUrl,
      connected,
      loggedIn,
      self,
      error,
      refreshing,
      view,
      sessions,
      activeTalker,
      setBaseUrl,
      refresh,
      openSession,
      touchSession,
    ],
  )

  return <AgentContext.Provider value={value}>{children}</AgentContext.Provider>
}

export function useAgent() {
  const ctx = useContext(AgentContext)
  if (!ctx) throw new Error('useAgent must be used within AgentProvider')
  return ctx
}
