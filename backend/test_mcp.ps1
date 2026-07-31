# Exercises all 6 Vigil MCP tools plus the unknown-tool error path.
# Usage: powershell -File test_mcp.ps1 [-BaseUrl http://localhost:7422]

param(
    [string]$BaseUrl = "http://localhost:7422"
)

$postCalls = @(
    @{ tool = "get_current_session"; params = @{} },
    @{ tool = "get_file_history"; params = @{ filepath = "main.py" } },
    @{ tool = "get_red_line_events"; params = @{ since_hours = 24 } }
)

Write-Host "=== /mcp/info ===" -ForegroundColor Cyan
try {
    $info = Invoke-RestMethod -Uri "$BaseUrl/mcp/info" -Method Get -TimeoutSec 15 -DisableKeepAlive
    Write-Host "server: $($info.server.name) v$($info.server.version), $($info.tools.Count) tools"
} catch {
    Write-Host "FAILED: $_" -ForegroundColor Red
}

foreach ($call in $postCalls) {
    Write-Host "`n=== $($call.tool) ===" -ForegroundColor Cyan
    try {
        $body = $call | ConvertTo-Json -Depth 5
        $resp = Invoke-RestMethod -Uri "$BaseUrl/mcp/call" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 30 -DisableKeepAlive
        if ($resp.error) {
            Write-Host "error: $($resp.error)" -ForegroundColor Yellow
        } else {
            $resp.result | ConvertTo-Json -Depth 6
        }
        Write-Host "evidence_note: $($resp.evidence_note)"
    } catch {
        Write-Host "FAILED: $_" -ForegroundColor Red
    }
}

# Session history
Write-Host "`n=== GET /mcp/sessions ===" -ForegroundColor Cyan
try {
    $t = Measure-Command {
        $resp = Invoke-RestMethod -Uri "$BaseUrl/mcp/sessions?n=5" -Method Get -TimeoutSec 15 -DisableKeepAlive
        $resp.result | ConvertTo-Json -Depth 3
    }
    Write-Host "Time: $($t.TotalSeconds)s"
} catch {
    Write-Host "FAILED: $_" -ForegroundColor Red
}

# Friction findings
Write-Host "`n=== GET /mcp/findings ===" -ForegroundColor Cyan
try {
    $t = Measure-Command {
        $resp = Invoke-RestMethod -Uri "$BaseUrl/mcp/findings" -Method Get -TimeoutSec 15 -DisableKeepAlive
        $resp.result | ConvertTo-Json -Depth 3
    }
    Write-Host "Time: $($t.TotalSeconds)s"
} catch {
    Write-Host "FAILED: $_" -ForegroundColor Red
}

# Evidence summary
Write-Host "`n=== GET /mcp/summary ===" -ForegroundColor Cyan
try {
    $t = Measure-Command {
        $resp = Invoke-RestMethod -Uri "$BaseUrl/mcp/summary?days=7" -Method Get -TimeoutSec 15 -DisableKeepAlive
        $resp.result | ConvertTo-Json -Depth 3
    }
    Write-Host "Time: $($t.TotalSeconds)s"
} catch {
    Write-Host "FAILED: $_" -ForegroundColor Red
}

Write-Host "`n=== unknown tool (expect error) ===" -ForegroundColor Cyan
try {
    $body = @{ tool = "nonexistent_tool"; params = @{} } | ConvertTo-Json
    $resp = Invoke-RestMethod -Uri "$BaseUrl/mcp/call" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 15 -DisableKeepAlive
    Write-Host "error: $($resp.error)"
} catch {
    Write-Host "FAILED: $_" -ForegroundColor Red
}
