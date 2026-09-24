---
description: Generate a Vigil session audit report. Use when the user asks to download a session report, generate a PDF, get the audit report, or review what the agent did this session.
---

# Vigil Session Report

Use the `vigil` MCP server to generate and download a session PDF audit report.

## Steps

1. Call `vigil_get_active_session` to get the current session ID.
   - If no active session is returned, tell the user: "No active Vigil session found. Vigil must be running and monitoring an active agent session."

2. Call `vigil_get_session_report` with the session ID to retrieve the report data (JSON preview).

3. Tell the user:
   - Session ID (first 8 characters)
   - Agent name
   - Start time (local timezone)
   - Summary counts: files touched, network connections, process spawns, red lines
   - Whether any red lines were triggered

4. Provide the PDF download URL:
   ```
   http://127.0.0.1:7422/api/sessions/{session_id}/report
   ```
   Tell the user they can open this URL in their browser to download the PDF, or use the **Download Session Report (PDF)** button in the Vigil VS Code sidebar.

5. If the user asks about specific events (e.g., "what files did I touch?"), use `vigil_get_session_events` to list them.

## Notes

- The PDF is generated independently of agent self-reporting — it reflects what the OS actually observed
- Red lines indicate policy violations (credential file access, out-of-scope writes, unapproved network destinations)
- Timestamps are shown in local time (IST or your system timezone)
- The Vigil backend must be running at `http://127.0.0.1:7422` for this to work
