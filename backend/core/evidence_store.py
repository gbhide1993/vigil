"""In-memory store for VigilEvidence records (core.evidence).

Purely additive — does not touch the Alert/alerts.db path at all.
VigilIncident rows are not stored directly; they're derived on read by
grouping VigilEvidence records (see list_incidents), keyed by session_id
when available, or by a rolling time window otherwise. No SQLite yet —
this is scoped to a single process's lifetime.
"""

from __future__ import annotations

from typing import Optional

from core.evidence import AttributionConfidence, VigilEvidence, VigilIncident

INCIDENT_WINDOW_SECONDS = 30

_CONFIDENCE_RANK = {
    AttributionConfidence.UNKNOWN: 0,
    AttributionConfidence.LOW: 1,
    AttributionConfidence.MEDIUM: 2,
    AttributionConfidence.HIGH: 3,
}

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class EvidenceStore:
    def __init__(self):
        self._evidence: list[VigilEvidence] = []

    def add_evidence(self, ev: VigilEvidence) -> None:
        self._evidence.append(ev)

    def get_evidence(self, evidence_id: str) -> Optional[VigilEvidence]:
        for ev in self._evidence:
            if ev.id == evidence_id:
                return ev
        return None

    def list_evidence(self, limit: int = 50) -> list[VigilEvidence]:
        return sorted(self._evidence, key=lambda e: e.when, reverse=True)[:limit]

    def list_incidents(self, limit: int = 20) -> list[VigilIncident]:
        groups = self._group_evidence()
        incidents = [self._build_incident(group) for group in groups]
        incidents.sort(key=lambda inc: inc.when, reverse=True)
        return incidents[:limit]

    def _group_evidence(self) -> list[list[VigilEvidence]]:
        """One group per session_id, or per 30s window for evidence with no
        session_id. Processes oldest-first so window groups accumulate
        forward in time from their first event."""
        groups: list[list[VigilEvidence]] = []
        session_group_index: dict[str, int] = {}

        for ev in sorted(self._evidence, key=lambda e: e.when):
            session_id = ev.attribution.session_id if ev.attribution else None

            if session_id:
                idx = session_group_index.get(session_id)
                if idx is not None:
                    groups[idx].append(ev)
                else:
                    groups.append([ev])
                    session_group_index[session_id] = len(groups) - 1
                continue

            placed = False
            for group in reversed(groups):
                group_session = group[0].attribution.session_id if group[0].attribution else None
                if group_session:
                    continue
                if (ev.when - group[0].when).total_seconds() <= INCIDENT_WINDOW_SECONDS:
                    group.append(ev)
                    placed = True
                    break
            if not placed:
                groups.append([ev])

        return groups

    def _build_incident(self, group: list[VigilEvidence]) -> VigilIncident:
        first = min(group, key=lambda e: e.when)

        worst_severity = max(
            (e.policy.severity for e in group if e.policy),
            key=lambda s: _SEVERITY_RANK.get(s, 0),
            default="info",
        )
        best_confidence = max(
            (e.attribution.confidence for e in group if e.attribution),
            key=lambda c: _CONFIDENCE_RANK.get(c, 0),
            default=AttributionConfidence.UNKNOWN,
        )
        attributed_agent = next(
            (e.attribution.attributed_agent for e in group
             if e.attribution and e.attribution.attributed_agent),
            None,
        )
        session_id = next(
            (e.attribution.session_id for e in group if e.attribution and e.attribution.session_id),
            None,
        )
        why = next((e.policy.why for e in group if e.policy), group[0].what)

        return VigilIncident(
            what=group[0].what,
            why=why,
            when=first.when,
            attributed_agent=attributed_agent,
            session_id=session_id,
            evidence=list(group),
            severity=worst_severity,
            attribution_confidence=best_confidence,
        )


evidence_store = EvidenceStore()
