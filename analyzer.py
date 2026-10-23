"""
Detection engine and risk scoring for LogTriage-CLI.

The :class:`TriageEngine` consumes a stream of normalized
:class:`~parsers.LogEvent` objects in a single pass and feeds them to a set of
detectors:

* :class:`BruteForceDetector` - sliding-window failed-login bursts, password
  spraying and successful logins that follow a burst.
* :class:`OffHoursDetector` - logins, privileged actions and process execution
  outside configured business hours.
* :class:`PrivilegeEscalationDetector` - sudo/su/pkexec usage, suspicious
  privileged commands, privileged group changes, account creation, direct
  root/Administrator logins and audit log clearing.

All detectors aggregate state per entity instead of keeping raw events, and
none of them depends on input ordering, so reverse-chronological exports
(e.g. Event Viewer CSV) are handled correctly.

Findings are scored by :class:`RiskScorer` using weighted heuristics and
mapped to an overall Low / Medium / High / Critical risk level.
"""

from __future__ import annotations

import ipaddress
import logging
import math
import re
from array import array
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta
from enum import IntEnum
from typing import Any

from parsers import ConfigError, EventCategory, LogEvent

logger = logging.getLogger(__name__)

_EPOCH = datetime(1970, 1, 1)
MAX_EVIDENCE_LINE_LENGTH = 600
_WEEKDAYS = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}


def _to_seconds(value: datetime) -> float:
    return (value - _EPOCH).total_seconds()


def _from_seconds(value: float) -> datetime:
    return _EPOCH + timedelta(seconds=value)


def _format_duration(seconds: float) -> str:
    if seconds >= 3600 and seconds % 3600 == 0:
        return f"{int(seconds // 3600)} h"
    if seconds >= 60 and seconds % 60 == 0:
        return f"{int(seconds // 60)} min"
    return f"{int(seconds)} s"


def _evidence_line(event: LogEvent) -> str:
    line = f"[{event.origin}] {event.raw}" if event.origin else event.raw
    if event.count > 1:
        line = f"{line}  (x{event.count})"
    return line if len(line) <= MAX_EVIDENCE_LINE_LENGTH else line[: MAX_EVIDENCE_LINE_LENGTH - 3] + "..."


def is_remote_address(value: str | None) -> bool:
    """Return ``True`` if ``value`` is a non-loopback network address or hostname."""
    if not value:
        return False
    try:
        return not ipaddress.ip_address(value).is_loopback
    except ValueError:
        return value.lower() not in ("localhost", "local")


# --------------------------------------------------------------------------- #
# Severity, rules and findings
# --------------------------------------------------------------------------- #
class Severity(IntEnum):
    """Ordered severity / risk levels."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        """Title-cased name, e.g. ``"High"``."""
        return self.name.capitalize()

    @classmethod
    def parse(cls, value: str | int | Severity) -> Severity:
        """Convert a configuration value into a :class:`Severity`.

        Raises:
            ConfigError: If the value is not a known level.
        """
        if isinstance(value, Severity):
            return value
        try:
            if isinstance(value, int):
                return cls(value)
            return cls[str(value).strip().upper()]
        except (KeyError, ValueError) as exc:
            raise ConfigError(f"Unknown severity level: {value!r}") from exc


@dataclass(frozen=True)
class RuleSpec:
    """Static metadata describing a detection rule."""

    rule_id: str
    title: str
    tactic: str
    severity: Severity
    mitre: tuple[str, ...]
    description: str


RULES: dict[str, RuleSpec] = {
    spec.rule_id: spec
    for spec in (
        RuleSpec("BF-001", "Brute-force login attempts", "Credential Access", Severity.HIGH, ("T1110.001",),
                 "Repeated authentication failures from a single source exceeded the configured "
                 "threshold within the sliding time window."),
        RuleSpec("BF-002", "Password spraying", "Credential Access", Severity.HIGH, ("T1110.003",),
                 "A single source failed to authenticate against many distinct accounts, a pattern "
                 "typical of password spraying."),
        RuleSpec("BF-003", "Successful login after brute-force", "Initial Access", Severity.CRITICAL,
                 ("T1110", "T1078"),
                 "A successful authentication from a source that was previously brute-forcing, "
                 "indicating likely credential compromise."),
        RuleSpec("OH-001", "Off-hours activity", "Defense Evasion", Severity.MEDIUM, ("T1078",),
                 "Logins or process execution outside configured business hours."),
        RuleSpec("OH-002", "Off-hours privileged activity", "Privilege Escalation", Severity.HIGH, ("T1078",),
                 "Privileged operations (sudo, su, group or account changes) outside business hours."),
        RuleSpec("PE-001", "Privileged command execution", "Privilege Escalation", Severity.LOW, ("T1548.003",),
                 "Commands executed with elevated privileges through sudo or pkexec."),
        RuleSpec("PE-002", "Suspicious privileged command", "Privilege Escalation", Severity.HIGH,
                 ("T1548", "T1059"),
                 "A command matching a known privilege-abuse, persistence or anti-forensics pattern."),
        RuleSpec("PE-003", "Switch to privileged account", "Privilege Escalation", Severity.MEDIUM, ("T1548",),
                 "A user switched identity to another (typically privileged) account using su."),
        RuleSpec("PE-004", "Failed privilege escalation attempt", "Privilege Escalation", Severity.MEDIUM,
                 ("T1548.003",),
                 "sudo, su or pkexec denied the request or the password was rejected."),
        RuleSpec("PE-005", "Account added to privileged group", "Persistence", Severity.HIGH, ("T1098",),
                 "An account was added to a group that grants administrative privileges."),
        RuleSpec("PE-006", "New user account created", "Persistence", Severity.MEDIUM, ("T1136.001",),
                 "A new local or domain account was created."),
        RuleSpec("PE-007", "Direct login to privileged account", "Privilege Escalation", Severity.HIGH,
                 ("T1078.003",),
                 "Successful authentication directly as root / Administrator."),
        RuleSpec("PE-008", "Special privileges assigned to logon", "Privilege Escalation", Severity.LOW,
                 ("T1078",),
                 "Sensitive privileges (e.g. SeDebugPrivilege) were assigned to a new logon session."),
        RuleSpec("PE-009", "Root-equivalent account created", "Persistence", Severity.CRITICAL, ("T1136.001",),
                 "A new account was created with UID 0, giving it full root privileges."),
        RuleSpec("DE-001", "Security audit log cleared", "Defense Evasion", Severity.CRITICAL, ("T1070.001",),
                 "The security or system event log was cleared, a common anti-forensics step."),
        RuleSpec("TI-001", "Source IP with malicious reputation", "Threat Intelligence", Severity.HIGH, (),
                 "Threat intelligence reports this address as abusive with high confidence."),
    )
}


@dataclass
class Finding:
    """An aggregated detection result for a single entity."""

    rule: RuleSpec
    entity: str
    entity_type: str
    host: str | None
    severity: Severity
    first_seen: datetime
    last_seen: datetime
    count: int = 0
    summary: str = ""
    evidence: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    samples: dict[str, list[str]] = field(default_factory=dict)
    score: float = 0.0

    @property
    def rule_id(self) -> str:
        return self.rule.rule_id

    def add_sample(self, key: str, value: str | None, limit: int = 10) -> None:
        """Remember up to ``limit`` distinct values for ``key``."""
        if not value:
            return
        values = self.samples.setdefault(key, [])
        if len(values) < limit and value not in values:
            values.append(value)

    def describe(self) -> str:
        """Return the detector-provided summary or a generic fallback."""
        if self.summary:
            return self.summary
        where = f" on {self.host}" if self.host else ""
        return f"{self.count} matching event(s) for {self.entity_type} '{self.entity}'{where}."

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "rule_id": self.rule.rule_id,
            "title": self.rule.title,
            "tactic": self.rule.tactic,
            "severity": self.severity.label,
            "score": round(self.score, 1),
            "entity": self.entity,
            "entity_type": self.entity_type,
            "host": self.host,
            "count": self.count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "summary": self.describe(),
            "description": self.rule.description,
            "mitre_attack": list(self.rule.mitre),
            "details": {**self.details, **self.samples},
            "evidence": list(self.evidence),
        }


class FindingStore:
    """Collects and aggregates findings keyed by rule, entity and host."""

    def __init__(self, max_evidence: int = 5, max_samples: int = 10) -> None:
        self.max_evidence = max_evidence
        self.max_samples = max_samples
        self._findings: dict[tuple[str, str, str, str], Finding] = {}

    def record(
        self,
        rule_id: str,
        entity: str,
        entity_type: str,
        event: LogEvent,
        *,
        severity: Severity | None = None,
        samples: dict[str, str | None] | None = None,
    ) -> Finding:
        """Aggregate ``event`` into the finding for (rule, entity, host)."""
        finding = self.get_or_create(
            rule_id, entity, entity_type, event.host, event.timestamp, event.timestamp, severity
        )
        if severity is not None and severity > finding.severity:
            finding.severity = severity
        if event.timestamp < finding.first_seen:
            finding.first_seen = event.timestamp
        elif event.timestamp > finding.last_seen:
            finding.last_seen = event.timestamp
        finding.count += event.count
        if len(finding.evidence) < self.max_evidence:
            finding.evidence.append(_evidence_line(event))
        if samples:
            for key, value in samples.items():
                finding.add_sample(key, value, self.max_samples)
        return finding

    def get_or_create(
        self,
        rule_id: str,
        entity: str,
        entity_type: str,
        host: str | None,
        first_seen: datetime,
        last_seen: datetime,
        severity: Severity | None = None,
    ) -> Finding:
        """Return the existing finding for the key or create an empty one."""
        key = (rule_id, entity_type, entity, host or "")
        finding = self._findings.get(key)
        if finding is None:
            rule = RULES[rule_id]
            finding = Finding(
                rule=rule, entity=entity, entity_type=entity_type, host=host,
                severity=severity or rule.severity, first_seen=first_seen, last_seen=last_seen,
            )
            self._findings[key] = finding
        return finding

    def by_rule(self, *rule_ids: str) -> list[Finding]:
        return [finding for finding in self._findings.values() if finding.rule_id in rule_ids]

    def all(self) -> list[Finding]:
        return list(self._findings.values())


# --------------------------------------------------------------------------- #
# Detection context and detectors
# --------------------------------------------------------------------------- #
def _compile_patterns(patterns: Iterable[str], setting: str) -> list[re.Pattern[str]]:
    compiled = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern, re.IGNORECASE))
        except re.error as exc:
            raise ConfigError(f"Invalid regex in '{setting}': {pattern!r} ({exc})") from exc
    return compiled


def _primary_entity(event: LogEvent) -> tuple[str, str]:
    if event.user:
        return event.user, "user"
    if event.src_ip:
        return event.src_ip, "ip"
    if event.host:
        return event.host, "host"
    return "unknown", "unknown"


@dataclass
class DetectionContext:
    """Shared, pre-compiled detection settings."""

    ignored_accounts: list[re.Pattern[str]]
    ignored_ips: frozenset[str]
    privileged_accounts: frozenset[str]
    privileged_groups: frozenset[str]
    suspicious_commands: list[re.Pattern[str]]
    _ignored_cache: dict[str, bool] = field(default_factory=dict, repr=False)

    @classmethod
    def from_config(cls, detection: dict[str, Any]) -> DetectionContext:
        privilege = detection.get("privilege_escalation", {})
        return cls(
            ignored_accounts=_compile_patterns(detection.get("ignored_accounts", []), "ignored_accounts"),
            ignored_ips=frozenset(detection.get("ignored_source_ips", [])),
            privileged_accounts=frozenset(a.lower() for a in privilege.get("privileged_accounts", ["root"])),
            privileged_groups=frozenset(g.lower() for g in privilege.get("privileged_groups", [])),
            suspicious_commands=_compile_patterns(
                privilege.get("suspicious_command_patterns", []), "suspicious_command_patterns"
            ),
        )

    def is_ignored_account(self, user: str | None) -> bool:
        """Return ``True`` for service / machine accounts excluded from noisy rules."""
        if not user:
            return False
        cached = self._ignored_cache.get(user)
        if cached is None:
            cached = any(pattern.search(user) for pattern in self.ignored_accounts)
            if len(self._ignored_cache) < 50_000:
                self._ignored_cache[user] = cached
        return cached

    def is_privileged_account(self, user: str | None) -> bool:
        return bool(user) and user.lower() in self.privileged_accounts

    def is_privileged_group(self, group: str | None) -> bool:
        return bool(group) and group.lower() in self.privileged_groups

    def match_suspicious(self, command: str | None) -> str | None:
        """Return the first suspicious pattern matching ``command``, if any."""
        if not command:
            return None
        for pattern in self.suspicious_commands:
            if pattern.search(command):
                return pattern.pattern
        return None


class Detector:
    """Base class for streaming detectors."""

    name = "detector"

    def __init__(self, settings: dict[str, Any], context: DetectionContext, store: FindingStore) -> None:
        self.settings = settings
        self.context = context
        self.store = store

    def process(self, event: LogEvent) -> None:
        """Consume a single event."""

    def finalize(self) -> None:
        """Emit findings that require the complete event stream."""


@dataclass
class _FailureMeta:
    users: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    evidence: list[str] = field(default_factory=list)


class BruteForceDetector(Detector):
    """Detects bursts of failed logins, password spraying and follow-up success.

    Failure timestamps are stored per source in compact ``array('d')`` buffers
    (8 bytes per attempt) and evaluated with a sliding window once the stream
    has been consumed, which makes detection independent of input ordering.
    """

    name = "brute_force"
    _MAX_TRACKED_USERS = 1000

    def __init__(self, settings: dict[str, Any], context: DetectionContext, store: FindingStore) -> None:
        super().__init__(settings, context, store)
        self.threshold = int(settings.get("failure_threshold", 5))
        self.window = float(settings.get("time_window_seconds", 300))
        self.critical_threshold = int(settings.get("critical_threshold", 50))
        self.spray_min_users = int(settings.get("password_spray_min_users", 5))
        self.correlation_window = float(settings.get("success_correlation_window_seconds", 3600))
        if self.threshold < 2 or self.window <= 0:
            raise ConfigError("brute_force: 'failure_threshold' must be >= 2 and 'time_window_seconds' > 0.")
        self._failures: dict[tuple[str, str], array] = {}
        self._meta: dict[tuple[str, str], _FailureMeta] = {}
        self._successes: dict[tuple[str, str], list[tuple[float, str | None, str | None, str | None]]] = (
            defaultdict(list)
        )

    @staticmethod
    def _key(event: LogEvent) -> tuple[str, str] | None:
        if event.src_ip:
            return ("ip", event.src_ip)
        if event.user:
            return ("user", f"{event.user}@{event.host}" if event.host else event.user)
        return None

    def process(self, event: LogEvent) -> None:
        if event.category == EventCategory.AUTH_FAILURE:
            if event.src_ip in self.context.ignored_ips:
                return
            key = self._key(event)
            if key is None:
                return
            stamps = self._failures.get(key)
            if stamps is None:
                stamps = self._failures[key] = array("d")
                self._meta[key] = _FailureMeta()
            seconds = _to_seconds(event.timestamp)
            if event.count == 1:
                stamps.append(seconds)
            else:
                stamps.extend(array("d", [seconds]) * event.count)
            meta = self._meta[key]
            if event.user and len(meta.users) < self._MAX_TRACKED_USERS:
                meta.users.add(event.user)
            if event.host and len(meta.hosts) < 50:
                meta.hosts.add(event.host)
            if len(meta.evidence) < self.store.max_evidence:
                meta.evidence.append(_evidence_line(event))

        elif event.category == EventCategory.AUTH_SUCCESS:
            key = self._key(event)
            if key is None:
                return
            # Keep the raw line only when failures were already seen, so that
            # memory stays bounded on hosts with a high volume of normal logins.
            evidence = _evidence_line(event) if key in self._failures else None
            self._successes[key].append((_to_seconds(event.timestamp), event.user, evidence, event.host))

    def _find_bursts(self, stamps: list[float]) -> tuple[list[list[float]], int]:
        """Return merged [start, end] intervals in which the threshold was reached."""
        bursts: list[list[float]] = []
        peak = 0
        left = 0
        for right, current in enumerate(stamps):
            while current - stamps[left] > self.window:
                left += 1
            in_window = right - left + 1
            peak = max(peak, in_window)
            if in_window >= self.threshold:
                start = stamps[left]
                if bursts and start <= bursts[-1][1]:
                    bursts[-1][1] = current
                else:
                    bursts.append([start, current])
        return bursts, peak

    def finalize(self) -> None:
        window_label = _format_duration(self.window)
        for key, buffer in self._failures.items():
            if len(buffer) < self.threshold:
                continue
            stamps = sorted(buffer)
            bursts, peak = self._find_bursts(stamps)
            if not bursts:
                continue

            entity_type, entity = key
            meta = self._meta[key]
            in_bursts = sum(bisect_right(stamps, end) - bisect_left(stamps, start) for start, end in bursts)
            accounts = sorted(meta.users)
            spraying = entity_type == "ip" and len(accounts) >= self.spray_min_users
            severity = Severity.CRITICAL if in_bursts >= self.critical_threshold else Severity.HIGH
            host = next(iter(meta.hosts)) if len(meta.hosts) == 1 else None

            finding = self.store.get_or_create(
                "BF-002" if spraying else "BF-001", entity, entity_type, host,
                _from_seconds(bursts[0][0]), _from_seconds(bursts[-1][1]), severity,
            )
            finding.count = in_bursts
            finding.evidence = meta.evidence
            finding.details = {
                "total_failures": len(stamps),
                "failures_in_bursts": in_bursts,
                "bursts": len(bursts),
                "peak_failures_per_window": peak,
                "window": window_label,
                "distinct_accounts": len(accounts),
                "targeted_accounts": accounts[:25],
                "hosts": sorted(meta.hosts),
            }
            if spraying:
                finding.summary = (
                    f"{in_bursts} failed logins from {entity} against {len(accounts)} distinct accounts "
                    f"(peak {peak} attempts per {window_label})."
                )
            else:
                targets = ", ".join(accounts[:5]) or "unknown accounts"
                finding.summary = (
                    f"{in_bursts} failed logins from {entity} in {len(bursts)} burst(s), peak {peak} "
                    f"attempts per {window_label}; targeted: {targets}."
                )
            self._correlate_success(key, bursts, in_bursts)

    def _correlate_success(self, key: tuple[str, str], bursts: list[list[float]], failures: int) -> None:
        successes = self._successes.get(key)
        if not successes:
            return
        entity_type, entity = key
        compromised: list[tuple[float, str | None, str | None, str | None]] = []
        for record in successes:
            moment = record[0]
            if any(start <= moment <= end + self.correlation_window for start, end in bursts):
                compromised.append(record)
        if not compromised:
            return

        compromised.sort(key=lambda item: item[0])
        users = sorted({user for _, user, _, _ in compromised if user})
        hosts = {host for _, _, _, host in compromised if host}
        finding = self.store.get_or_create(
            "BF-003", entity, entity_type, next(iter(hosts)) if len(hosts) == 1 else None,
            _from_seconds(compromised[0][0]), _from_seconds(compromised[-1][0]),
        )
        finding.count = len(compromised)
        finding.evidence = [
            evidence or f"Successful login as '{user or '?'}' at {_from_seconds(moment).isoformat(sep=' ')}"
            for moment, user, evidence, _ in compromised[: self.store.max_evidence]
        ]
        finding.details = {
            "compromised_accounts": users,
            "preceding_failures": failures,
            "correlation_window": _format_duration(self.correlation_window),
        }
        finding.summary = (
            f"Successful login as {', '.join(users) or 'an unknown account'} from {entity} "
            f"after {failures} failed attempts - credentials are likely compromised."
        )


def _parse_clock(value: str, setting: str) -> time:
    try:
        return time.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"off_hours: invalid time for '{setting}': {value!r} (expected HH:MM)") from exc


class OffHoursDetector(Detector):
    """Flags activity outside configured business hours, days and holidays."""

    name = "off_hours"
    PRIVILEGED_CATEGORIES = frozenset({
        EventCategory.PRIV_COMMAND, EventCategory.PRIV_SWITCH,
        EventCategory.GROUP_CHANGE, EventCategory.ACCOUNT_CREATED,
    })

    def __init__(self, settings: dict[str, Any], context: DetectionContext, store: FindingStore) -> None:
        super().__init__(settings, context, store)
        self.start = _parse_clock(settings.get("business_hours_start", "08:00"), "business_hours_start")
        self.end = _parse_clock(settings.get("business_hours_end", "18:00"), "business_hours_end")
        try:
            self.days = frozenset(
                _WEEKDAYS[day.strip().lower()[:3]]
                for day in settings.get("business_days", ["Mon", "Tue", "Wed", "Thu", "Fri"])
            )
            self.holidays = frozenset(date.fromisoformat(d) for d in settings.get("holidays", []))
        except (KeyError, ValueError) as exc:
            raise ConfigError(f"off_hours: invalid business day or holiday value ({exc})") from exc
        self.monitored = frozenset(settings.get("monitored_categories", []))
        unknown = self.monitored - EventCategory.ALL
        if unknown:
            raise ConfigError(f"off_hours: unknown monitored categories: {sorted(unknown)}")
        self.logon_types = frozenset(str(t) for t in settings.get("windows_logon_types", []))

    def is_business_hour(self, moment: time) -> bool:
        """Return ``True`` if the clock time falls inside business hours."""
        if self.start <= self.end:
            return self.start <= moment < self.end
        return moment >= self.start or moment < self.end  # Overnight shift, e.g. 22:00-06:00.

    def is_business_time(self, moment: datetime) -> bool:
        if moment.weekday() not in self.days or moment.date() in self.holidays:
            return False
        return self.is_business_hour(moment.time())

    def hour_flags(self) -> list[bool]:
        """Business-hour flag for each hour of the day (used by the HTML chart)."""
        return [self.is_business_hour(time(hour, 30)) for hour in range(24)]

    def describe_window(self) -> str:
        names = [name.capitalize() for name, index in _WEEKDAYS.items() if index in self.days]
        return f"{self.start:%H:%M}-{self.end:%H:%M} {', '.join(names)}"

    def process(self, event: LogEvent) -> None:
        if event.category not in self.monitored or self.context.is_ignored_account(event.user):
            return
        if event.category == EventCategory.AUTH_SUCCESS and event.event_id is not None and self.logon_types:
            logon_type = event.fields.get("logon_type")
            if logon_type is not None and logon_type not in self.logon_types:
                return
        if self.is_business_time(event.timestamp):
            return
        rule_id = "OH-002" if event.category in self.PRIVILEGED_CATEGORIES else "OH-001"
        entity, entity_type = _primary_entity(event)
        self.store.record(rule_id, entity, entity_type, event, samples={
            "activity": EventCategory.label(event.category),
            "timestamps": event.timestamp.strftime("%a %Y-%m-%d %H:%M"),
            "source_ips": event.src_ip,
            "commands": event.command,
        })

    def finalize(self) -> None:
        window = self.describe_window()
        for finding in self.store.by_rule("OH-001", "OH-002"):
            kind = "privileged action(s)" if finding.rule_id == "OH-002" else "login/execution event(s)"
            where = f" on {finding.host}" if finding.host else ""
            finding.summary = (
                f"{finding.count} off-hours {kind} by {finding.entity}{where} "
                f"outside business hours ({window})."
            )


class PrivilegeEscalationDetector(Detector):
    """Detects privilege escalation and related persistence indicators."""

    name = "privilege_escalation"

    def _severity_hint(self, event: LogEvent) -> Severity | None:
        return Severity.parse(event.severity_hint) if event.severity_hint else None

    def process(self, event: LogEvent) -> None:
        category = event.category
        ctx = self.context
        entity, entity_type = _primary_entity(event)

        if category == EventCategory.PRIV_COMMAND:
            matched = ctx.match_suspicious(event.command)
            if matched:
                self.store.record("PE-002", entity, entity_type, event, samples={
                    "commands": event.command, "run_as": event.target_user, "matched_patterns": matched,
                })
            elif not ctx.is_ignored_account(event.user):
                self.store.record("PE-001", entity, entity_type, event, samples={
                    "commands": event.command, "run_as": event.target_user,
                })

        elif category == EventCategory.PRIV_SWITCH:
            to_privileged = ctx.is_privileged_account(event.target_user)
            # Privileged users dropping to a service account (e.g. root -> postgres) is routine.
            if not to_privileged and (not event.user or ctx.is_privileged_account(event.user)):
                return
            self.store.record("PE-003", entity, entity_type, event,
                              severity=Severity.MEDIUM if to_privileged else Severity.LOW,
                              samples={"switched_to": event.target_user})

        elif category == EventCategory.PRIV_FAILURE:
            self.store.record("PE-004", entity, entity_type, event, severity=self._severity_hint(event),
                              samples={"commands": event.command, "run_as": event.target_user,
                                       "reasons": event.rule_id})

        elif category == EventCategory.GROUP_CHANGE:
            if ctx.is_privileged_group(event.group):
                self.store.record("PE-005", entity, entity_type, event, samples={
                    "groups": event.group, "changed_by": event.fields.get("actor"),
                })

        elif category == EventCategory.ACCOUNT_CREATED:
            rule_id = "PE-009" if event.fields.get("uid") == "0" else "PE-006"
            self.store.record(rule_id, entity, entity_type, event, samples={
                "created_by": event.fields.get("actor"), "uid": event.fields.get("uid"),
            })

        elif category == EventCategory.AUTH_SUCCESS:
            if ctx.is_privileged_account(event.user):
                remote = is_remote_address(event.src_ip)
                self.store.record("PE-007", entity, entity_type, event,
                                  severity=Severity.HIGH if remote else Severity.MEDIUM,
                                  samples={"source_ips": event.src_ip,
                                           "logon_types": event.fields.get("logon_type")})

        elif category == EventCategory.SPECIAL_PRIVILEGES:
            if not ctx.is_ignored_account(event.user):
                self.store.record("PE-008", entity, entity_type, event, samples={
                    "privileges": event.fields.get("privileges"),
                })

        elif category == EventCategory.PROCESS_EXEC:
            matched = ctx.match_suspicious(event.command)
            if matched:
                self.store.record("PE-002", entity, entity_type, event, samples={
                    "commands": event.command, "matched_patterns": matched,
                    "parent_processes": event.fields.get("parent_process"),
                })

        elif category == EventCategory.LOG_CLEARED:
            self.store.record("DE-001", entity, entity_type, event, samples={"providers": event.source})

    def finalize(self) -> None:
        for finding in self.store.by_rule(*self._SUMMARIES):
            values = {key: ", ".join(items) for key, items in finding.samples.items()}
            actor = values.get("changed_by") or values.get("created_by")
            finding.summary = self._SUMMARIES[finding.rule_id].format(
                entity=finding.entity,
                count=finding.count,
                where=f" on {finding.host}" if finding.host else "",
                commands=_first(finding.samples.get("commands")),
                run_as=values.get("run_as") or "another user",
                switched_to=values.get("switched_to") or "another account",
                groups=values.get("groups") or "a privileged group",
                by=f" by {actor}" if actor else "",
                sources=f" from {values['source_ips']}" if values.get("source_ips") else "",
                privileges=values.get("privileges") or "special privileges",
            )

    _SUMMARIES = {
        "PE-001": "{entity} ran {count} command(s) as {run_as} via sudo/pkexec{where}.",
        "PE-002": "{entity} executed {count} suspicious privileged command(s){where}, e.g. \"{commands}\".",
        "PE-003": "{entity} switched to {switched_to} {count} time(s) using su{where}.",
        "PE-004": "{count} privilege escalation attempt(s) by {entity} were denied or failed{where}.",
        "PE-005": "{entity} was added to {groups}{by}{where}.",
        "PE-006": "Account '{entity}' was created{by}{where}.",
        "PE-007": "{count} direct login(s) as {entity}{sources}{where}.",
        "PE-008": "{entity} received {privileges} in {count} logon session(s){where}.",
        "PE-009": "Account '{entity}' was created with UID 0 (root-equivalent){by}{where}.",
        "DE-001": "The audit log was cleared {count} time(s) by {entity}{where}.",
    }


def _first(values: list[str] | None) -> str:
    return values[0] if values else "-"


# --------------------------------------------------------------------------- #
# Statistics
# --------------------------------------------------------------------------- #
@dataclass
class EventStatistics:
    """Aggregate statistics over all security-relevant events."""

    total_events: int = 0
    by_category: Counter[str] = field(default_factory=Counter)
    hourly: list[int] = field(default_factory=lambda: [0] * 24)
    failed_by_ip: Counter[str] = field(default_factory=Counter)
    failed_by_user: Counter[str] = field(default_factory=Counter)
    success_by_user: Counter[str] = field(default_factory=Counter)
    hosts: Counter[str] = field(default_factory=Counter)
    first_event: datetime | None = None
    last_event: datetime | None = None

    def update(self, event: LogEvent) -> None:
        count = event.count
        self.total_events += count
        self.by_category[event.category] += count
        self.hourly[event.timestamp.hour] += count
        if event.host:
            self.hosts[event.host] += count
        if event.category == EventCategory.AUTH_FAILURE:
            if event.src_ip:
                self.failed_by_ip[event.src_ip] += count
            if event.user:
                self.failed_by_user[event.user] += count
        elif event.category == EventCategory.AUTH_SUCCESS and event.user:
            self.success_by_user[event.user] += count
        if self.first_event is None or event.timestamp < self.first_event:
            self.first_event = event.timestamp
        if self.last_event is None or event.timestamp > self.last_event:
            self.last_event = event.timestamp

    def to_dict(self, top_n: int = 10) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        def top(counter: Counter[str]) -> list[dict[str, Any]]:
            return [{"name": name, "count": count} for name, count in counter.most_common(top_n)]

        return {
            "total_events": self.total_events,
            "first_event": self.first_event.isoformat() if self.first_event else None,
            "last_event": self.last_event.isoformat() if self.last_event else None,
            "by_category": [
                {"category": cat, "label": EventCategory.label(cat), "count": count}
                for cat, count in self.by_category.most_common()
            ],
            "hourly_activity": list(self.hourly),
            "top_failed_source_ips": top(self.failed_by_ip),
            "top_failed_accounts": top(self.failed_by_user),
            "top_successful_accounts": top(self.success_by_user),
            "hosts": top(self.hosts),
        }


# --------------------------------------------------------------------------- #
# Risk scoring
# --------------------------------------------------------------------------- #
DEFAULT_RULE_WEIGHTS: dict[str, float] = {
    "BF-001": 15, "BF-002": 18, "BF-003": 25, "OH-001": 6, "OH-002": 10,
    "PE-001": 4, "PE-002": 12, "PE-003": 6, "PE-004": 8, "PE-005": 15,
    "PE-006": 8, "PE-007": 10, "PE-008": 3, "PE-009": 25, "DE-001": 25, "TI-001": 12,
}
DEFAULT_SEVERITY_MULTIPLIERS = {"low": 0.5, "medium": 1.0, "high": 1.5, "critical": 2.0}


@dataclass
class RiskAssessment:
    """Overall and per-entity risk derived from findings."""

    score: float
    level: Severity
    severity_counts: dict[str, int]
    breakdown: list[dict[str, Any]]
    entities: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level.label,
            "severity_counts": self.severity_counts,
            "breakdown": self.breakdown,
            "entities": self.entities,
        }


class RiskScorer:
    """Weighted heuristic risk scoring.

    Each finding scores ``weight(rule) x multiplier(severity) x volume`` where
    ``volume = 1 + min(1, log10(count) / 3)`` rewards repetition with
    diminishing returns (1x for a single event, 2x at 1,000 events). Points are
    capped per rule so a single noisy detector cannot dominate, and the total is
    capped at 100. The total maps onto Low / Medium / High / Critical using the
    configured thresholds; any critical finding raises the overall level to at
    least ``critical_finding_minimum_level``.
    """

    def __init__(self, settings: dict[str, Any]) -> None:
        self.weights = {**DEFAULT_RULE_WEIGHTS, **settings.get("rule_weights", {})}
        multipliers = {**DEFAULT_SEVERITY_MULTIPLIERS, **settings.get("severity_multipliers", {})}
        self.multipliers = {Severity.parse(name): float(value) for name, value in multipliers.items()}
        self.rule_cap = float(settings.get("max_points_per_rule", 40))
        levels = settings.get("risk_levels", {"medium": 20, "high": 45, "critical": 75})
        self.thresholds = sorted(
            ((float(value), Severity.parse(name)) for name, value in levels.items()), reverse=True
        )
        self.critical_floor = Severity.parse(settings.get("critical_finding_minimum_level", "high"))

    def score_finding(self, finding: Finding) -> float:
        volume = 1.0 + min(1.0, math.log10(max(1, finding.count)) / 3.0)
        weight = float(self.weights.get(finding.rule_id, 5))
        return weight * self.multipliers.get(finding.severity, 1.0) * volume

    def level_for(self, score: float) -> Severity:
        for threshold, level in self.thresholds:
            if score >= threshold:
                return level
        return Severity.LOW

    def assess(self, findings: list[Finding]) -> RiskAssessment:
        """Score every finding in place and compute the overall assessment."""
        per_rule: dict[str, float] = defaultdict(float)
        rule_counts: Counter[str] = Counter()
        per_entity: dict[tuple[str, str], dict[str, Any]] = {}

        for finding in findings:
            finding.score = round(self.score_finding(finding), 1)
            per_rule[finding.rule_id] += finding.score
            rule_counts[finding.rule_id] += 1
            entry = per_entity.setdefault(
                (finding.entity_type, finding.entity),
                {"entity": finding.entity, "entity_type": finding.entity_type,
                 "score": 0.0, "findings": 0, "rules": set(), "max_severity": Severity.LOW},
            )
            entry["score"] += finding.score
            entry["findings"] += 1
            entry["rules"].add(finding.rule_id)
            entry["max_severity"] = max(entry["max_severity"], finding.severity)

        capped = {rule_id: min(self.rule_cap, points) for rule_id, points in per_rule.items()}
        total = round(min(100.0, sum(capped.values())), 1)
        level = self.level_for(total)
        if any(f.severity == Severity.CRITICAL for f in findings) and level < self.critical_floor:
            level = self.critical_floor

        breakdown = sorted(
            (
                {"rule_id": rule_id, "title": RULES[rule_id].title, "findings": rule_counts[rule_id],
                 "raw_points": round(per_rule[rule_id], 1), "points": round(points, 1)}
                for rule_id, points in capped.items()
            ),
            key=lambda item: item["points"], reverse=True,
        )

        entities = []
        for entry in sorted(per_entity.values(), key=lambda item: item["score"], reverse=True)[:20]:
            score = round(min(100.0, entry["score"]), 1)
            entity_level = self.level_for(score)
            if entry["max_severity"] == Severity.CRITICAL and entity_level < self.critical_floor:
                entity_level = self.critical_floor
            entities.append({
                "entity": entry["entity"], "entity_type": entry["entity_type"], "score": score,
                "level": entity_level.label, "findings": entry["findings"], "rules": sorted(entry["rules"]),
            })

        severity_counts = {sev.label: 0 for sev in sorted(Severity, reverse=True)}
        for finding in findings:
            severity_counts[finding.severity.label] += 1

        return RiskAssessment(total, level, severity_counts, breakdown, entities)


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #
@dataclass
class AnalysisResult:
    """Everything produced by a triage run."""

    findings: list[Finding]
    risk: RiskAssessment
    statistics: EventStatistics
    context: dict[str, Any] = field(default_factory=dict)

    def sort_findings(self) -> None:
        self.findings.sort(key=lambda f: (f.severity, f.score, f.count), reverse=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk": self.risk.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
            "statistics": self.statistics.to_dict(),
            "context": self.context,
        }


class TriageEngine:
    """Runs all enabled detectors over an event stream and scores the results."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        general = config.get("general", {})
        self.max_evidence = int(general.get("max_evidence_per_finding", 5))
        self.max_samples = int(general.get("max_samples_per_detail", 10))
        self.detection = config.get("detection", {})
        self.context = DetectionContext.from_config(self.detection)
        self.scorer = RiskScorer(config.get("scoring", {}))
        # Validate detector settings eagerly so configuration errors surface before parsing.
        self._build_detectors(FindingStore())

    def _build_detectors(self, store: FindingStore) -> list[Detector]:
        detectors: list[Detector] = []
        for cls in (BruteForceDetector, OffHoursDetector, PrivilegeEscalationDetector):
            settings = self.detection.get(cls.name, {})
            if settings.get("enabled", True):
                detectors.append(cls(settings, self.context, store))
        return detectors

    def analyze(self, events: Iterable[LogEvent]) -> AnalysisResult:
        """Consume ``events`` in a single pass and return the analysis result."""
        store = FindingStore(self.max_evidence, self.max_samples)
        detectors = self._build_detectors(store)
        statistics = EventStatistics()
        process_calls = [detector.process for detector in detectors]

        for event in events:
            statistics.update(event)
            for process in process_calls:
                process(event)

        for detector in detectors:
            detector.finalize()

        findings = store.all()
        result = AnalysisResult(findings, self.scorer.assess(findings), statistics)
        result.sort_findings()

        off_hours = next((d for d in detectors if isinstance(d, OffHoursDetector)), None)
        if off_hours is not None:
            result.context["business_hours"] = off_hours.describe_window()
            result.context["business_hour_flags"] = off_hours.hour_flags()
        result.context["detectors"] = [d.name for d in detectors]
        return result

    def rescore(self, result: AnalysisResult) -> None:
        """Recompute risk after findings were added or modified."""
        result.risk = self.scorer.assess(result.findings)
        result.sort_findings()
