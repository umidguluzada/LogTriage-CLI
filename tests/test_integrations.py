"""Tests for the optional integrations (no network access required)."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from analyzer import Severity, TriageEngine
from integrations import IntegrationError, WebhookNotifier, enrich_with_abuseipdb, is_public_ip
from parsers import EventCategory, LogEvent

START = datetime(2026, 10, 21, 2, 0, 0)


class FakeAbuseIPDB:
    def __init__(self, scores: dict[str, int]) -> None:
        self.scores = scores
        self.queried: list[str] = []

    def check(self, ip: str) -> dict:
        self.queried.append(ip)
        return {"provider": "AbuseIPDB", "ip": ip, "abuse_confidence": self.scores.get(ip, 0),
                "total_reports": 42, "country": "XX", "isp": "Example ISP"}


def _attack(ip: str) -> list[LogEvent]:
    events = [
        LogEvent(timestamp=START + timedelta(seconds=i), category=EventCategory.AUTH_FAILURE,
                 source="sshd", message="", host="web01", user="root", src_ip=ip)
        for i in range(10)
    ]
    events.append(LogEvent(timestamp=START + timedelta(minutes=1), category=EventCategory.AUTH_SUCCESS,
                           source="sshd", message="", host="web01", user="root", src_ip=ip))
    return events


def test_is_public_ip():
    assert is_public_ip("8.8.8.8")
    assert not is_public_ip("10.0.0.1")
    assert not is_public_ip("203.0.113.5")  # documentation range
    assert not is_public_ip("not-an-ip")


def test_enrichment_adds_threat_intel_finding(config):
    engine = TriageEngine(config)
    result = engine.analyze(_attack("8.8.4.4") + _attack("10.1.1.1"))
    client = FakeAbuseIPDB({"8.8.4.4": 97})

    summary = enrich_with_abuseipdb(result, engine, client, max_lookups=5, confidence_threshold=75)

    assert client.queried == ["8.8.4.4"]  # private addresses are never sent
    assert summary["malicious"] == ["8.8.4.4"]
    intel = [f for f in result.findings if f.rule_id == "TI-001"]
    assert len(intel) == 1 and intel[0].severity == Severity.CRITICAL  # linked to a successful login
    assert result.risk.breakdown[0]["points"] > 0


def test_webhook_payload_styles():
    report = {
        "summary": {"risk_level": "High", "risk_score": 61.5, "findings_total": 1,
                    "severity_counts": {"Critical": 0, "High": 1, "Medium": 0, "Low": 0},
                    "events_analyzed": 1200},
        "input": {"files_display": ["auth.log"]},
        "findings": [{"severity": "High", "title": "Brute-force login attempts", "entity": "198.51.100.1"}],
    }
    slack = WebhookNotifier("https://hooks.example.com/x").build_payload(report)
    assert "HIGH risk" in slack["text"] and "198.51.100.1" in slack["text"]
    discord = WebhookNotifier("https://hooks.example.com/x", style="discord").build_payload(report)
    assert "content" in discord

    with pytest.raises(IntegrationError):
        WebhookNotifier("ftp://example.com")
