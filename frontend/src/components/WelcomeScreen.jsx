const WATCH_ITEMS = [
  { icon: '📁', label: 'Files your agents read and write' },
  { icon: '🌐', label: 'Network connections they open' },
  { icon: '⚙️', label: 'Processes they spawn' },
  { icon: '🔑', label: 'Credential files they access' },
]

export default function WelcomeScreen() {
  return (
    <div className="welcome-screen">
      <div className="welcome-brand">V-LAW</div>
      <div className="welcome-headline">
        Vigil is now watching your AI agents. Start a Claude Code or Cursor session to see activity here.
      </div>

      <div className="welcome-watch-list">
        {WATCH_ITEMS.map((item) => (
          <div className="welcome-watch-item" key={item.label}>
            <span className="welcome-watch-icon">{item.icon}</span>
            <span>{item.label}</span>
          </div>
        ))}
      </div>

      <div className="welcome-status">
        <span className="status-dot green" />
        Watching — no sessions yet
      </div>
    </div>
  )
}
