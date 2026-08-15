"""Local MCP (Model Context Protocol) server exposing Vigil's evidence data
to MCP clients (Claude Code, Cursor) over HTTP/SSE. Read-only: every tool
queries existing SQLite data populated by the watchers/aggregator — this
router never collects new data and never writes to the DB."""

import asyncio
import json

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from core.mcp_service import (
    EVIDENCE_NOTE,
    _get_evidence_summary,
    _get_friction_findings,
    _get_session_history,
    dispatch_tool,
)

router = APIRouter(prefix="/mcp")

SERVER_INFO = {
    "name": "vigil-mcp",
    "version": "1.0.0",
    "description": "Read-only access to AI coding session evidence observed at OS level by Vigil.",
}

TOOLS = [
    {
        "name": "get_current_session",
        "description": (
            "Returns the current or most recent AI coding session observed by Vigil at OS level. "
            "Use this to understand what the AI agent has been doing in the current session."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_session_history",
        "description": (
            "Returns the last N AI coding sessions with summary data. Useful for understanding "
            "recent AI activity patterns across multiple sessions."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "n": {"type": "integer", "default": 5, "description": "Number of sessions to return"},
            },
        },
    },
    {
        "name": "get_file_history",
        "description": (
            "Returns all AI agent activity observed on a specific file, including how many times "
            "it was edited and any friction signals detected."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "filepath": {"type": "string", "description": "File path to look up"},
            },
            "required": ["filepath"],
        },
    },
    {
        "name": "get_red_line_events",
        "description": (
            "Returns Red Line security alerts observed by Vigil. Red Lines are high-risk events "
            "like credential access, unexpected network connections, or MCP auto-approvals."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "since_hours": {"type": "integer", "default": 24, "description": "Look back N hours"},
            },
        },
    },
    {
        "name": "get_friction_findings",
        "description": (
            "Returns evidence-derived friction findings. These are patterns inferred from OS-level "
            "events such as retry loops, rapid reverts, and abandoned sessions. Each finding includes "
            "confidence level and supporting evidence."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Optional session ID. Omit to get all recent findings.",
                },
            },
        },
    },
    {
        "name": "get_evidence_summary",
        "description": (
            "Returns a signed evidence summary suitable for SOC2 audit export. Includes all AI "
            "session activity, Red Lines, and friction signals for the specified period."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "days": {"type": "integer", "default": 7, "description": "Number of days to summarize"},
            },
        },
    },
]

KEEPALIVE_SECONDS = 30


class CallRequest(BaseModel):
    tool: str
    params: dict = {}


class JsonRpcRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: int | str | None = None
    method: str
    params: dict = {}


MCP_PROTOCOL_VERSION = "2024-11-05"


def _jsonrpc_result(request_id, result):
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _jsonrpc_error(request_id, code, message):
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


async def _handle_jsonrpc(body: JsonRpcRequest) -> dict:
    if body.method == "initialize":
        return _jsonrpc_result(
            body.id,
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_INFO["name"], "version": SERVER_INFO["version"]},
            },
        )

    if body.method == "notifications/initialized":
        return _jsonrpc_result(body.id, {})

    if body.method == "tools/list":
        return _jsonrpc_result(body.id, {"tools": TOOLS})

    if body.method == "tools/call":
        tool_name = body.params.get("name")
        tool_args = body.params.get("arguments") or {}
        outcome = await dispatch_tool(tool_name, tool_args)
        if outcome.get("error"):
            return _jsonrpc_result(
                body.id,
                {
                    "content": [{"type": "text", "text": outcome["error"]}],
                    "isError": True,
                },
            )
        return _jsonrpc_result(
            body.id,
            {
                "content": [
                    {"type": "text", "text": json.dumps(outcome.get("result"))}
                ]
            },
        )

    return _jsonrpc_error(body.id, -32601, f"Method not found: {body.method}")


@router.get("")
async def mcp_sse_handshake():
    async def event_stream():
        yield f"event: endpoint\ndata: /mcp\n\n"

        while True:
            await asyncio.sleep(KEEPALIVE_SECONDS)
            yield "event: ping\ndata: {}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@router.post("")
async def mcp_jsonrpc(body: JsonRpcRequest):
    return await _handle_jsonrpc(body)


@router.get("/info")
async def mcp_info():
    return {"server": SERVER_INFO, "tools": TOOLS}


@router.get("/sse")
async def mcp_sse():
    async def event_stream():
        handshake = {"server": SERVER_INFO, "tools": TOOLS}
        yield f"event: mcp_info\ndata: {json.dumps(handshake)}\n\n"

        while True:
            await asyncio.sleep(KEEPALIVE_SECONDS)
            yield "event: ping\ndata: {}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@router.post("/call")
async def mcp_call(body: CallRequest):
    outcome = await dispatch_tool(body.tool, body.params)
    return {
        "tool": body.tool,
        "result": outcome.get("result"),
        "error": outcome.get("error"),
        "evidence_note": EVIDENCE_NOTE,
    }


# Dedicated GET endpoints for the three multi-query tools, bypassing
# dispatch_tool()/POST /mcp/call entirely. Each GET request gets its own
# request handler coroutine rather than sharing the POST /mcp/call queue.
@router.get("/sessions")
async def mcp_sessions(n: int = 5):
    result = await _get_session_history({"n": n})
    return {"result": result, "evidence_note": EVIDENCE_NOTE}


@router.get("/findings")
async def mcp_findings(session_id: str | None = None):
    result = await _get_friction_findings({"session_id": session_id})
    return {"result": result, "evidence_note": EVIDENCE_NOTE}


@router.get("/summary")
async def mcp_summary(days: int = 7):
    result = await _get_evidence_summary({"days": days})
    return {"result": result, "evidence_note": EVIDENCE_NOTE}
