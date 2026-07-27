import { useState } from 'react'
import { ChatPanel } from './ChatPanel'
import { SideApps } from './SideApps'

/** 会话工作台：对话 + 右侧多应用坞 */
export function ChatWorkspace() {
  const [injectText, setInjectText] = useState<string | null>(null)
  const [composerDraft, setComposerDraft] = useState('')

  return (
    <div className="stage chat-stage">
      <div className="chat-main">
        <ChatPanel
          injectText={injectText}
          onInjectConsumed={() => setInjectText(null)}
          onDraftChange={setComposerDraft}
        />
      </div>
      <SideApps onUseReply={setInjectText} composerDraft={composerDraft} />
    </div>
  )
}
