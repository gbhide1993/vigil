from datetime import datetime, timedelta, timezone

import pytest

from core.evidence import (
    AttributionChain,
    AttributionConfidence,
    EvidenceSource,
    PolicyMatch,
    RawEvidence,
    VigilEvidence,
)
from core.evidence_store import EvidenceStore


def _now():
    return datetime.now(timezone.utc)


def _rl1_evidence(session_id=None, when=None, pid=17220, agent="Claude Code"):
    return VigilEvidence(
        what="Read .env",
        when=when or _now(),
        raw=RawEvidence(
            source=EvidenceSource.ETW,
            observed_at=when or _now(),
            pid=pid,
            action="FILE_READ",
            target=".env",
            details={"rule": "RL1"},
        ),
        attribution=AttributionChain(
            confidence=AttributionConfidence.HIGH,
            chain=[f"{agent} PID {pid}", "FILE_READ .env"],
            basis=f"Process identity resolved to a known agent ({agent}) via PID {pid}.",
            attributed_agent=agent,
            agent_pid=pid,
            session_id=session_id,
        ),
        policy=PolicyMatch(
            rule_id="RL1",
            rule_name="Credential File Access",
            why=".env and credential files are outside the agent's permitted scope",
            severity="critical",
        ),
    )


@pytest.fixture
def store():
    return EvidenceStore()


def test_single_rl1_evidence_produces_one_incident(store):
    store.add_evidence(_rl1_evidence())
    incidents = store.list_incidents()
    assert len(incidents) == 1


def test_incident_has_critical_severity(store):
    store.add_evidence(_rl1_evidence())
    incidents = store.list_incidents()
    assert incidents[0].severity == "critical"


def test_incident_evidence_length_one(store):
    store.add_evidence(_rl1_evidence())
    incidents = store.list_incidents()
    assert len(incidents[0].evidence) == 1


def test_same_session_id_groups_into_one_incident(store):
    store.add_evidence(_rl1_evidence(session_id="sess-1"))
    store.add_evidence(_rl1_evidence(session_id="sess-1", when=_now() + timedelta(seconds=5)))
    incidents = store.list_incidents()
    assert len(incidents) == 1
    assert len(incidents[0].evidence) == 2


def test_different_session_ids_produce_two_incidents(store):
    store.add_evidence(_rl1_evidence(session_id="sess-1"))
    store.add_evidence(_rl1_evidence(session_id="sess-2"))
    incidents = store.list_incidents()
    assert len(incidents) == 2


def test_list_evidence_returns_newest_first(store):
    older = _rl1_evidence(when=_now() - timedelta(seconds=60))
    newer = _rl1_evidence(when=_now())
    store.add_evidence(older)
    store.add_evidence(newer)
    result = store.list_evidence()
    assert result[0].id == newer.id
    assert result[1].id == older.id
