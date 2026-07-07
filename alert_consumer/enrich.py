"""Enrichment logic: map raw Elastic Security alerts to triage-ready records.

Each alert is enriched with:
  - a normalized severity (with a numeric rank for sorting)
  - the MITRE ATT&CK technique ID + name for the rule that fired
  - the key entity (source IP / user) extracted from the alert document
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Static rule -> ATT&CK mapping. Kept in sync with detections/*.json and
# MITRE_MAPPING.md; used as a fallback when an alert carries no threat block.
MITRE_MAPPING: dict[str, dict[str, str]] = {
    "edl-001-ssh-brute-force": {
        "technique_id": "T1110.001",
        "technique": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
    },
    "edl-002-impossible-travel": {
        "technique_id": "T1078",
        "technique": "Valid Accounts",
        "tactic": "Initial Access",
    },
    "edl-003-sudo-escalation": {
        "technique_id": "T1548.003",
        "technique": "Abuse Elevation Control Mechanism: Sudo",
        "tactic": "Privilege Escalation",
    },
    "edl-004-web-shell": {
        "technique_id": "T1505.003",
        "technique": "Server Software Component: Web Shell",
        "tactic": "Persistence",
    },
    "edl-005-data-exfiltration": {
        "technique_id": "T1048",
        "technique": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
    },
    "edl-006-new-admin-account": {
        "technique_id": "T1136.001",
        "technique": "Create Account: Local Account",
        "tactic": "Persistence",
    },
}

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass
class EnrichedAlert:
    rule_name: str
    rule_id: str
    severity: str
    risk_score: int
    technique_id: str
    technique: str
    tactic: str
    entity: str
    timestamp: str
    reason: str = ""

    @property
    def severity_rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 0)


def _get(doc: dict[str, Any], dotted: str, default: Any = None) -> Any:
    """Fetch a value addressed by dotted path from a doc that may store it
    either nested ({"source": {"ip": ...}}) or flattened ({"source.ip": ...})."""
    if dotted in doc:
        return doc[dotted]
    current: Any = doc
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def _extract_entity(source: dict[str, Any]) -> str:
    user = _get(source, "user.name")
    ip = _get(source, "source.ip")
    if user and ip:
        return f"{user} @ {ip}"
    return user or ip or "-"


def _extract_technique(source: dict[str, Any], rule_id: str) -> dict[str, str]:
    """Prefer the threat block embedded in the alert; fall back to the
    static mapping keyed by rule_id."""
    threats = _get(source, "kibana.alert.rule.parameters.threat") or []
    for threat in threats:
        techniques = threat.get("technique") or []
        for tech in techniques:
            subs = tech.get("subtechnique") or []
            chosen = subs[0] if subs else tech
            return {
                "technique_id": chosen.get("id", "-"),
                "technique": chosen.get("name", "-"),
                "tactic": (threat.get("tactic") or {}).get("name", "-"),
            }
    return MITRE_MAPPING.get(
        rule_id,
        {"technique_id": "-", "technique": "unmapped", "tactic": "-"},
    )


def enrich_alert(source: dict[str, Any]) -> EnrichedAlert:
    """Turn one raw alert document (the `_source` of a hit from
    .alerts-security.alerts-*) into an EnrichedAlert."""
    rule_id = _get(source, "kibana.alert.rule.rule_id") or _get(
        source, "kibana.alert.rule.parameters.rule_id", "-"
    )
    mitre = _extract_technique(source, rule_id)
    return EnrichedAlert(
        rule_name=_get(source, "kibana.alert.rule.name", "unknown rule"),
        rule_id=rule_id,
        severity=(_get(source, "kibana.alert.severity") or "low").lower(),
        risk_score=int(_get(source, "kibana.alert.risk_score") or 0),
        technique_id=mitre["technique_id"],
        technique=mitre["technique"],
        tactic=mitre["tactic"],
        entity=_extract_entity(source),
        timestamp=_get(source, "@timestamp", "-"),
        reason=_get(source, "kibana.alert.reason", ""),
    )


def sort_for_triage(alerts: list[EnrichedAlert]) -> list[EnrichedAlert]:
    """Highest severity first, then highest risk score."""
    return sorted(alerts, key=lambda a: (a.severity_rank, a.risk_score), reverse=True)
