"""Tests for the alert enrichment logic (no Elasticsearch required)."""
import json
from pathlib import Path

import pytest

from alert_consumer.enrich import (
    MITRE_MAPPING,
    enrich_alert,
    sort_for_triage,
)

RULES_DIR = Path(__file__).resolve().parent.parent / "detections"


def make_alert(**overrides):
    """A minimal alert doc in the flattened form ES returns for alerts."""
    doc = {
        "@timestamp": "2026-07-06T12:00:00.000Z",
        "kibana.alert.rule.name": "EDL-001 SSH Brute Force Attempts",
        "kibana.alert.rule.rule_id": "edl-001-ssh-brute-force",
        "kibana.alert.severity": "high",
        "kibana.alert.risk_score": 73,
        "kibana.alert.reason": "event created high alert",
        "source.ip": "203.0.113.66",
        "user.name": "svc_backup",
    }
    doc.update(overrides)
    return doc


class TestEnrichAlert:
    def test_maps_rule_to_mitre_technique(self):
        alert = enrich_alert(make_alert())
        assert alert.technique_id == "T1110.001"
        assert alert.tactic == "Credential Access"

    def test_extracts_entity_user_and_ip(self):
        alert = enrich_alert(make_alert())
        assert alert.entity == "svc_backup @ 203.0.113.66"

    def test_entity_falls_back_to_ip_only(self):
        raw = make_alert()
        del raw["user.name"]
        assert enrich_alert(raw).entity == "203.0.113.66"

    def test_entity_dash_when_nothing_available(self):
        raw = make_alert()
        del raw["user.name"]
        del raw["source.ip"]
        assert enrich_alert(raw).entity == "-"

    def test_handles_nested_field_layout(self):
        raw = make_alert()
        del raw["source.ip"], raw["user.name"]
        raw["source"] = {"ip": "198.51.100.99"}
        raw["user"] = {"name": "alice"}
        assert enrich_alert(raw).entity == "alice @ 198.51.100.99"

    def test_severity_normalized_to_lowercase(self):
        alert = enrich_alert(make_alert(**{"kibana.alert.severity": "CRITICAL"}))
        assert alert.severity == "critical"
        assert alert.severity_rank == 4

    def test_unknown_rule_id_is_unmapped_not_crash(self):
        alert = enrich_alert(make_alert(**{"kibana.alert.rule.rule_id": "some-other-rule"}))
        assert alert.technique == "unmapped"
        assert alert.technique_id == "-"

    def test_missing_severity_defaults_low(self):
        raw = make_alert()
        del raw["kibana.alert.severity"]
        alert = enrich_alert(raw)
        assert alert.severity == "low"
        assert alert.severity_rank == 1

    def test_prefers_embedded_threat_block_over_static_mapping(self):
        raw = make_alert(**{
            "kibana.alert.rule.rule_id": "some-other-rule",
            "kibana.alert.rule.parameters.threat": [
                {
                    "tactic": {"id": "TA0011", "name": "Command and Control"},
                    "technique": [{"id": "T1071", "name": "Application Layer Protocol"}],
                }
            ],
        })
        alert = enrich_alert(raw)
        assert alert.technique_id == "T1071"
        assert alert.tactic == "Command and Control"

    def test_embedded_subtechnique_wins_over_parent(self):
        raw = make_alert(**{
            "kibana.alert.rule.parameters.threat": [
                {
                    "tactic": {"id": "TA0006", "name": "Credential Access"},
                    "technique": [{
                        "id": "T1110", "name": "Brute Force",
                        "subtechnique": [{"id": "T1110.001", "name": "Password Guessing"}],
                    }],
                }
            ],
        })
        assert enrich_alert(raw).technique_id == "T1110.001"


class TestSortForTriage:
    def test_orders_by_severity_then_risk(self):
        alerts = [
            enrich_alert(make_alert(**{"kibana.alert.severity": "low",
                                       "kibana.alert.risk_score": 20})),
            enrich_alert(make_alert(**{"kibana.alert.severity": "critical",
                                       "kibana.alert.risk_score": 90})),
            enrich_alert(make_alert(**{"kibana.alert.severity": "high",
                                       "kibana.alert.risk_score": 80})),
            enrich_alert(make_alert(**{"kibana.alert.severity": "high",
                                       "kibana.alert.risk_score": 60})),
        ]
        ordered = sort_for_triage(alerts)
        assert [a.severity for a in ordered] == ["critical", "high", "high", "low"]
        assert ordered[1].risk_score == 80


@pytest.fixture(scope="module")
def rule_files():
    return {
        json.loads(p.read_text())["rule_id"]: json.loads(p.read_text())
        for p in RULES_DIR.glob("*.json")
    }


class TestMappingConsistency:
    """MITRE_MAPPING must stay in sync with the rules-as-code."""

    def test_every_rule_file_has_a_mapping(self, rule_files):
        assert set(rule_files) == set(MITRE_MAPPING)

    def test_mapping_technique_matches_rule_threat_block(self, rule_files):
        for rule_id, rule in rule_files.items():
            technique = rule["threat"][0]["technique"][0]
            expected = technique.get("subtechnique", [technique])[0]["id"]
            assert MITRE_MAPPING[rule_id]["technique_id"] == expected, rule_id

    def test_all_six_rules_present(self, rule_files):
        assert len(rule_files) == 6
