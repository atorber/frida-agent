import { useState } from 'react'
import { useAgent } from '../context/AgentContext'
import { AssistantPanel } from './AssistantPanel'
import { NotesApp } from './NotesApp'
import { ToolkitApp } from './ToolkitApp'

export type SideAppId = 'assistant' | 'notes' | 'toolkit'

type AppMeta = {
  id: SideAppId
  label: string
  short: string
  badge?: string
}

const APPS: AppMeta[] = [
  { id: 'assistant', label: '助手', short: '助' },
  { id: 'notes', label: '速记', short: '记' },
  { id: 'toolkit', label: '工具', short: '工' },
]

type Props = {
  onUseReply: (text: string) => void
  composerDraft?: string
}

/** 右侧多应用坞：应用轨常驻，面板可展开/收起（与对话区等宽） */
export function SideApps({ onUseReply, composerDraft }: Props) {
  const { activeTalker, sessions } = useAgent()
  const session = sessions.find((s) => s.id === activeTalker)
  const talkerName = session?.name || activeTalker || '未选择会话'
  const [expanded, setExpanded] = useState(true)
  const [activeId, setActiveId] = useState<SideAppId>('assistant')

  const active = APPS.find((a) => a.id === activeId)!

  const openApp = (id: SideAppId) => {
    setActiveId(id)
    setExpanded(true)
  }

  return (
    <div className={`side-apps ${expanded ? 'expanded' : 'collapsed'}`}>
      {expanded && (
        <aside className="side-panel">
          <header className="side-panel-head">
            <div>
              <div className="side-panel-title">
                {active.label}
                {active.badge && <span className="side-panel-badge">{active.badge}</span>}
              </div>
              <div className="side-panel-sub truncate">{talkerName}</div>
            </div>
            <button
              type="button"
              className="icon-btn"
              title="收起面板"
              onClick={() => setExpanded(false)}
            >
              ›
            </button>
          </header>
          <div className="side-panel-body">
            {activeId === 'assistant' && <AssistantPanel onUseReply={onUseReply} />}
            {activeId === 'notes' && <NotesApp />}
            {activeId === 'toolkit' && (
              <ToolkitApp onUseReply={onUseReply} composerDraft={composerDraft} />
            )}
          </div>
        </aside>
      )}

      <nav className="side-rail" aria-label="会话应用">
        {APPS.map((app) => (
          <button
            key={app.id}
            type="button"
            className={`side-rail-btn ${expanded && activeId === app.id ? 'on' : ''}`}
            title={app.label}
            onClick={() => {
              if (expanded && activeId === app.id) setExpanded(false)
              else openApp(app.id)
            }}
          >
            {app.short}
          </button>
        ))}
      </nav>
    </div>
  )
}
