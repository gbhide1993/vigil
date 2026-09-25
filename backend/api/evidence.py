"""Read-only API for the additive evidence model (core.evidence,
core.evidence_store). Does not touch the existing /alerts path at all."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter

from core.evidence import AttributionChain, PolicyMatch, RawEvidence, VigilEvidence, VigilIncident
from core.evidence_store import evidence_store

router = APIRouter()


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _serialize_raw(raw: RawEvidence | None) -> dict | None:
    if raw is None:
        return None
    return {
        "source": raw.source.value,
        "observed_at": _iso(raw.observed_at),
        "pid": raw.pid,
        "parent_pid": raw.parent_pid,
        "process_path": raw.process_path,
        "action": raw.action,
        "target": raw.target,
        "event_id": raw.event_id,
        "raw_ref": raw.raw_ref,
        "details": raw.details,
    }


def _serialize_attribution(attribution: AttributionChain | None) -> dict | None:
    if attribution is None:
        return None
    return {
        "confidence": attribution.confidence.value,
        "chain": attribution.chain,
        "basis": attribution.basis,
        "attributed_agent": attribution.attributed_agent,
        "agent_pid": attribution.agent_pid,
        "session_id": attribution.session_id,
    }


def _serialize_policy(policy: PolicyMatch | None) -> dict | None:
    if policy is None:
        return None
    return {
        "rule_id": policy.rule_id,
        "rule_name": policy.rule_name,
        "why": policy.why,
        "severity": policy.severity,
    }


def _serialize_evidence(ev: VigilEvidence) -> dict:
    return {
        "id": ev.id,
        "what": ev.what,
        "when": _iso(ev.when),
        "raw": _serialize_raw(ev.raw),
        "attribution": _serialize_attribution(ev.attribution),
        "policy": _serialize_policy(ev.policy),
        "status": ev.status.value,
    }


def _serialize_incident(incident: VigilIncident) -> dict:
    return {
        "id": incident.id,
        "what": incident.what,
        "why": incident.why,
        "when": _iso(incident.when),
        "attributed_agent": incident.attributed_agent,
        "session_id": incident.session_id,
        "severity": incident.severity,
        "attribution_confidence": incident.attribution_confidence.value,
        "status": incident.status.value,
        "evidence": [_serialize_evidence(e) for e in incident.evidence],
    }


@router.get("/evidence")
async def get_evidence():
    return [_serialize_evidence(e) for e in evidence_store.list_evidence(limit=50)]


@router.get("/incidents")
async def get_evidence_incidents():
    return [_serialize_incident(i) for i in evidence_store.list_incidents(limit=20)]
