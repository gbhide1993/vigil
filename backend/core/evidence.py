"""Additive evidence model for Vigil.

This module is purely additive: it does not modify or depend on Alert,
RedLines, session, watcher, API, or UI code. It defines the schema for
recording observed events (RawEvidence), how Vigil attributes them to an
agent (AttributionChain), why a policy surfaced them (PolicyMatch), and how
individual observations (VigilEvidence) roll up into incidents
(VigilIncident).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class AttributionConfidence(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class EvidenceSource(Enum):
    ETW = "etw"
    PSUTIL = "psutil"
    NETWORK = "network"
    MCP = "mcp"


class EvidenceStatus(Enum):
    UNREVIEWED = "unreviewed"
    REVIEWED = "reviewed"
    DISMISSED = "dismissed"
    ESCALATED = "escalated"


@dataclass
class RawEvidence:
    source: EvidenceSource
    observed_at: datetime
    pid: int
    action: str
    target: str
    parent_pid: Optional[int] = None
    process_path: Optional[str] = None
    event_id: Optional[int] = None
    raw_ref: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttributionChain:
    confidence: AttributionConfidence
    chain: list[str]
    basis: str
    attributed_agent: Optional[str] = None
    agent_pid: Optional[int] = None
    session_id: Optional[str] = None


@dataclass
class PolicyMatch:
    rule_id: str
    rule_name: str
    why: str
    severity: str


@dataclass
class VigilEvidence:
    what: str
    when: datetime
    raw: Optional[RawEvidence] = None
    attribution: Optional[AttributionChain] = None
    policy: Optional[PolicyMatch] = None
    status: EvidenceStatus = EvidenceStatus.UNREVIEWED
    id: str = field(default_factory=lambda: f"EVT-{uuid.uuid4().hex[:8]}")


@dataclass
class VigilIncident:
    what: str
    why: str
    when: datetime
    attributed_agent: Optional[str] = None
    session_id: Optional[str] = None
    evidence: list[VigilEvidence] = field(default_factory=list)
    severity: str = "info"
    attribution_confidence: AttributionConfidence = AttributionConfidence.UNKNOWN
    status: EvidenceStatus = EvidenceStatus.UNREVIEWED
    id: str = field(default_factory=lambda: f"VL-{uuid.uuid4().hex[:6]}")
