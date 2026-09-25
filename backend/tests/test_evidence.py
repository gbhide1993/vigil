from datetime import datetime, timezone

from core.evidence import (
    AttributionChain,
    AttributionConfidence,
    EvidenceSource,
    EvidenceStatus,
    PolicyMatch,
    RawEvidence,
    VigilEvidence,
    VigilIncident,
)


def _now():
    return datetime.now(timezone.utc)


def test_evidence_with_no_attribution():
    ev = VigilEvidence(what="Read .env", when=_now(), attribution=None)
    assert ev.id.startswith("EVT-")
    assert ev.status == EvidenceStatus.UNREVIEWED


def test_evidence_with_high_confidence_attribution():
    attribution = AttributionChain(
        confidence=AttributionConfidence.HIGH,
        chain=["Claude Code PID 17220", "python.exe PID 18472", "FILE_READ .env"],
        basis="Child process ancestry via psutil; 3-hop chain.",
        attributed_agent="Claude Code",
    )
    ev = VigilEvidence(what="Read .env", when=_now(), attribution=attribution)
    assert ev.attribution.attributed_agent == "Claude Code"
    assert ev.attribution.basis != ""


def test_evidence_with_unknown_confidence():
    attribution = AttributionChain(
        confidence=AttributionConfidence.UNKNOWN,
        chain=[],
        basis="Insufficient process ancestry data to determine origin.",
    )
    ev = VigilEvidence(what="Read .env", when=_now(), attribution=attribution)
    assert ev.attribution.attributed_agent is None
    assert ev.attribution.confidence == AttributionConfidence.UNKNOWN


def test_evidence_with_no_policy_match():
    ev = VigilEvidence(what="Read .env", when=_now(), policy=None)
    assert ev.policy is None


def test_evidence_with_policy_match():
    policy = PolicyMatch(
        rule_id="RL-001",
        rule_name="Sensitive file read",
        why="Process read a file matching a known secrets pattern.",
        severity="high",
    )
    ev = VigilEvidence(what="Read .env", when=_now(), policy=policy)
    assert ev.policy.why != ""


def test_incident_with_two_evidence_records():
    ev1 = VigilEvidence(what="Read .env", when=_now())
    ev2 = VigilEvidence(what="Network connect to unknown host", when=_now())
    incident = VigilIncident(
        what="Suspicious credential exfiltration attempt",
        why="Sensitive file read followed by outbound network connection.",
        when=_now(),
        evidence=[ev1, ev2],
    )
    assert len(incident.evidence) == 2
    assert incident.id.startswith("VL-")


def test_raw_evidence_with_details_preserved():
    details = {"handle_count": 4, "flags": ["READ", "SHARE"]}
    raw = RawEvidence(
        source=EvidenceSource.ETW,
        observed_at=_now(),
        pid=1234,
        action="FILE_READ",
        target=".env",
        details=details,
    )
    assert raw.details == details


def test_two_evidence_have_different_ids():
    ev1 = VigilEvidence(what="Read .env", when=_now())
    ev2 = VigilEvidence(what="Read .env", when=_now())
    assert ev1.id != ev2.id
