# Vigil Session Report

Generate a Vigil audit report for the current Claude Code session.

1. Call `vigil_get_active_session` to get the current session ID. If none, tell the user the Vigil backend is not running.
2. Call `vigil_get_session_report` with the session ID and display: session ID (first 8 chars), agent name, start time, files touched, network connections, process spawns, red lines.
3. Provide the PDF download link: http://127.0.0.1:7422/api/sessions/{session_id}/report
4. If red lines were triggered, list them in full.
