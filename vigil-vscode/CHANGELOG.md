# Changelog

## [0.2.26] - 2026-10-19
### Fixed
- "Files touched" now shows the real count (the backend returns a number, the extension was reading it as an empty list)
- The extension no longer force-kills `vigil-backend.exe`. If the backend process is running but not answering, it shows a message and leaves the process alone
- Fewer health checks: one shared check per refresh (3 second timeout, reused for 2 seconds), and refreshes no longer overlap when the backend is slow or down
- The installer now runs without freezing VS Code (5 minute limit, exit code checked and reported)
- "Vigil: Install Backend" is now listed in the Command Palette (it was registered but not declared)
- Poll interval default is 30 seconds in code, matching the setting

### Changed
- No download prompt at startup. If Vigil is not installed, the Vigil sidebar shows an install panel with "Install Vigil backend" and "Download installer only". The consent dialog appears only after you click Install
- Status bar shows "Vigil: Not installed" with a click-to-install action when no backend is found
- Wording: "View Evidence" is now "Open Vigil", the report tooltip no longer says "evidence report", and the copy command says "Session summary hash copied"

## [0.2.25] - 2026-10-14
### Changed
- README rewritten to match Vigil 0.9.0: network and MCP monitoring moved to "Not in this version",
  Red Lines section lists only the rules that can fire, "Works with" limited to the agents Vigil
  recognises, VS Code requirement corrected to 1.85+
- Added "Privacy and data flow" and "Limits" sections (records are not protected against edits to the local database, best-guess
  attribution without ETW, file reads not recorded, Windows only)
- Added the unsigned installer / SmartScreen note with SHA256 verification advice, and described the
  first-launch installer download
- Package description and keywords no longer use "evidence" or "audit"
- The "Copy Evidence Hash" command is now titled "Copy Session Summary Hash": the value is a SHA-256 of
  the session summary, not a proof of integrity

## [0.2.12] - 2026-08-15
### Fixed
- Sidebar now correctly displays active sessions, red lines, and findings
- Root cause: MCP response envelope was not being unwrapped — all API calls 
  were reading the wrapper object instead of the result field inside it

## [0.2.11] - 2026-08-14
### Changed
- Published all fixes from 0.2.3 through 0.2.10 to Marketplace

## [0.2.10] - 2026-08-14
### Fixed
- OS-level file lock prevents multiple VS Code windows from spawning duplicate backends

## [0.2.9] - 2026-08-14
### Fixed
- Sidebar crash: backend returns files_touched as a count not an array

## [0.2.7] - 2026-08-13
### Fixed
- Sidebar correctly detects active session from backend status string field

## [0.2.6] - 2026-08-13
### Fixed
- Prevent double backend spawn when process already running

## [0.2.4] - 2026-08-10
### Fixed
- Manifest URL corrected to manifest.json
- Manifest key corrected to win_x64

## [0.2.3] - 2026-08-10
### Fixed
- Download button now links to correct installer URL
