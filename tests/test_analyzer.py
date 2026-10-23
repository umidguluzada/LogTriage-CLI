"""Tests for the detection engine and risk scoring."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from analyzer import Severity, TriageEngine
from parsers import ConfigError, EventCategory, LogEvent

# 2026-10-21 is a Wednesday.
NIGHT = datetime(2026, 10, 21, 2, 0, 0)
NOON = datetime(2026, 10, 21, 12, 0, 0)


def event(category: str, when: datetime, **kwargs) -> LogEvent:
    kwargs.setdefault("host", "web01")
    return LogEvent(timestamp=when, category=category, source="test", message="", raw="raw", **kwargs)


def failures(ip: str, start: datetime, count: int, step: int = 2, users=("root",)) -> list[LogEvent]:
    return [
        event(EventCategory.AUTH_FAILURE, start + timedelta(seconds=i * step), src_ip=ip, user=users[i % len(users)])
        for i in range(count)
    ]


def rules(result) -> dict[str, list]:
    found: dict[str, list] = {}
    for finding in result.findings:
        found.setdefault(finding.rule_id, []).append(finding)
    return found


def test_brute_force_requires_threshold_within_window(config):
    engine = TriageEngine(config)
    spread_out = failures("192.0.2.1", NOON, 10, step=120)  # 10 attempts, 2 min apart
    burst = failures("192.0.2.2", NOON, 10, step=2)
    found = rules(engine.analyze(spread_out + burst))

    assert [f.entity for f in found["BF-001"]] == ["192.0.2.2"]
    assert found["BF-001"][0].count == 10
    assert found["BF-001"][0].severity == Severity.HIGH


def test_brute_force_is_order_independent_and_correlates_success(config):
    engine = TriageEngine(config)
    stream = failures("203.0.113.5", NIGHT, 60, users=("root", "deploy"))
    stream.append(event(EventCategory.AUTH_SUCCESS, NIGHT + timedelta(minutes=5), src_ip="203.0.113.5", user="deploy"))

    forward = rules(engine.analyze(stream))
    backward = rules(engine.analyze(list(reversed(stream))))

    for found in (forward, backward):
        assert found["BF-001"][0].severity == Severity.CRITICAL  # >= critical_threshold (50)
        assert found["BF-003"][0].details["compromised_accounts"] == ["deploy"]


def test_password_spraying(config):
    users = tuple(f"user{i}" for i in range(8))
    found = rules(TriageEngine(config).analyze(failures("198.51.100.7", NOON, 8, users=users)))
    assert "BF-001" not in found
    assert found["BF-002"][0].details["distinct_accounts"] == 8


def test_off_hours_detection_respects_business_hours_and_ignored_accounts(config):
    stream = [
        event(EventCategory.AUTH_SUCCESS, NOON, user="alice", src_ip="10.0.0.1"),
        event(EventCategory.AUTH_SUCCESS, NIGHT, user="alice", src_ip="10.0.0.1"),
        event(EventCategory.AUTH_SUCCESS, datetime(2026, 10, 24, 12, 0), user="bob"),  # Saturday
        event(EventCategory.AUTH_SUCCESS, NIGHT, user="WS01$"),  # machine account
        event(EventCategory.PRIV_COMMAND, NIGHT, user="alice", target_user="root", command="/usr/bin/id"),
        # Windows service logon (type 5) at night is routine.
        event(EventCategory.AUTH_SUCCESS, NIGHT, user="svc_backup", event_id=4624, fields={"logon_type": "5"}),
    ]
    found = rules(TriageEngine(config).analyze(stream))

    assert sorted(f.entity for f in found["OH-001"]) == ["alice", "bob"]
    assert [f.entity for f in found["OH-002"]] == ["alice"]


def test_privilege_escalation_rules(config):
    stream = [
        event(EventCategory.PRIV_COMMAND, NOON, user="deploy", target_user="root", command="/bin/bash"),
        event(EventCategory.PRIV_COMMAND, NOON, user="alice", target_user="root", command="/usr/bin/apt update"),
        event(EventCategory.ACCOUNT_CREATED, NOON, user="sysbackup", fields={"uid": "0"}),
        event(EventCategory.ACCOUNT_CREATED, NOON, user="intern", fields={"uid": "1005"}),
        event(EventCategory.GROUP_CHANGE, NOON, user="deploy", group="sudo"),
        event(EventCategory.GROUP_CHANGE, NOON, user="deploy", group="audio"),
        event(EventCategory.PRIV_SWITCH, NOON, user="root", target_user="postgres"),
        event(EventCategory.AUTH_SUCCESS, NOON, user="root", src_ip="192.0.2.10"),
        event(EventCategory.LOG_CLEARED, NOON, user="Administrator"),
    ]
    found = rules(TriageEngine(config).analyze(stream))

    assert found["PE-002"][0].entity == "deploy"
    assert found["PE-001"][0].entity == "alice"
    assert found["PE-009"][0].entity == "sysbackup"
    assert found["PE-006"][0].entity == "intern"
    assert len(found["PE-005"]) == 1 and found["PE-005"][0].samples["groups"] == ["sudo"]
    assert "PE-003" not in found  # root dropping to a service account is routine
    assert found["PE-007"][0].severity == Severity.HIGH
    assert found["DE-001"][0].severity == Severity.CRITICAL


def test_risk_scoring_levels(config):
    engine = TriageEngine(config)
    empty = engine.analyze([])
    assert (empty.risk.score, empty.risk.level) == (0, Severity.LOW)

    low = engine.analyze([event(EventCategory.PRIV_COMMAND, NOON, user="alice", target_user="root", command="id")])
    assert low.risk.level == Severity.LOW

    critical_only = engine.analyze([event(EventCategory.LOG_CLEARED, NOON, user="Administrator")])
    assert critical_only.risk.level >= Severity.HIGH  # critical finding floor

    attack = failures("203.0.113.9", NIGHT, 120)
    attack.append(event(EventCategory.AUTH_SUCCESS, NIGHT + timedelta(minutes=5), src_ip="203.0.113.9", user="root"))
    assert engine.analyze(attack).risk.level == Severity.CRITICAL


def test_invalid_configuration_is_rejected(config):
    broken = {**config, "detection": {**config["detection"], "off_hours": {"business_hours_start": "25:99"}}}
    with pytest.raises(ConfigError):
        TriageEngine(broken)
