import { useState } from 'react'
import type { Contact, Room } from './api/types'
import { AgentProvider, useAgent } from './context/AgentContext'
import { Rail } from './components/Rail'
import { SessionList } from './components/SessionList'
import { ContactList } from './components/ContactList'
import { RoomList } from './components/RoomList'
import { ChatWorkspace } from './components/ChatWorkspace'
import { ContactPanel } from './components/ContactPanel'
import { RoomPanel } from './components/RoomPanel'
import { ToolsPanel } from './components/ToolsPanel'

function Shell() {
  const { view } = useAgent()
  const [contact, setContact] = useState<Contact | null>(null)
  const [room, setRoom] = useState<Room | null>(null)

  return (
    <div className="app-shell">
      <div className="app">
        <Rail />
        <div className="workspace">
          {view === 'chat' && (
            <>
              <SessionList />
              <ChatWorkspace />
            </>
          )}
          {view === 'contacts' && (
            <>
              <ContactList selectedId={contact?.id ?? null} onSelect={setContact} />
              <div className="stage">
                <ContactPanel contact={contact} />
              </div>
            </>
          )}
          {view === 'rooms' && (
            <>
              <RoomList selectedId={room?.id ?? null} onSelect={setRoom} />
              <div className="stage">
                <RoomPanel room={room} />
              </div>
            </>
          )}
          {view === 'tools' && (
            <div className="stage">
              <ToolsPanel />
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default function App() {
  return (
    <AgentProvider>
      <Shell />
    </AgentProvider>
  )
}
