# Changelog

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
