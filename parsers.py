"""
Streaming parsers for Linux and Windows security logs.

Every parser is a generator: input is consumed incrementally (line by line for
syslog and ``wevtutil`` text exports, row by row for CSV, record by record for
EVTX and XML) so memory usage stays flat regardless of file size. Parsers emit
normalized :class:`LogEvent` objects for security-relevant records only;
everything else is counted in :class:`ParseStats` and discarded as early as
possible.

Supported inputs
----------------
Linux:
    ``auth.log``, ``secure``, ``syslog``, ``messages`` (classic BSD syslog or
    RFC 3339 timestamps), including gzip-compressed rotations (``*.gz``).
Windows:
    ``.evtx`` (native binary), ``.xml`` (Event Viewer / ``wevtutil /f:xml``),
    ``.csv`` (Event Viewer or ``Get-WinEvent | Export-Csv``) and ``.txt``
    (``wevtutil qe /f:text``).
"""

from __future__ import annotations

import codecs
import csv
import gzip
import io
import logging
import re
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Any, TextIO

logger = logging.getLogger(__name__)

READ_BUFFER_SIZE = 1024 * 1024
XML_CHUNK_SIZE = 256 * 1024
MAX_RAW_LENGTH = 2000

# Windows event messages can be large; the csv module default (128 KiB) is too small.
csv.field_size_limit(16 * 1024 * 1024)


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #
class LogParseError(Exception):
    """Raised when an input file cannot be opened, decoded or parsed."""


class MissingDependencyError(LogParseError):
    """Raised when an optional dependency required for an input format is missing."""


class ConfigError(ValueError):
    """Raised when the configuration contains missing or invalid values."""


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
class EventCategory:
    """Normalized security event categories shared by all parsers."""

    AUTH_FAILURE = "auth_failure"
    AUTH_SUCCESS = "auth_success"
    PRIV_COMMAND = "priv_command"
    PRIV_SWITCH = "priv_switch"
    PRIV_FAILURE = "priv_failure"
    SPECIAL_PRIVILEGES = "special_privileges"
    GROUP_CHANGE = "group_change"
    ACCOUNT_CREATED = "account_created"
    PROCESS_EXEC = "process_exec"
    LOG_CLEARED = "log_cleared"

    LABELS: dict[str, str] = {
        AUTH_FAILURE: "Authentication failure",
        AUTH_SUCCESS: "Successful authentication",
        PRIV_COMMAND: "Privileged command (sudo/pkexec)",
        PRIV_SWITCH: "Account switch (su)",
        PRIV_FAILURE: "Failed privilege escalation",
        SPECIAL_PRIVILEGES: "Special privileges assigned",
        GROUP_CHANGE: "Group membership change",
        ACCOUNT_CREATED: "Account created",
        PROCESS_EXEC: "Process execution",
        LOG_CLEARED: "Audit log cleared",
    }
    ALL: frozenset[str] = frozenset(LABELS)

    @classmethod
    def label(cls, category: str) -> str:
        """Return a human-readable label for ``category``."""
        return cls.LABELS.get(category, category)


@dataclass(slots=True)
class LogEvent:
    """A normalized, security-relevant log record.

    Attributes:
        timestamp: Naive datetime expressed in the analysis timezone.
        category: One of the :class:`EventCategory` constants.
        source: Emitting program (Linux) or event provider (Windows).
        message: Message body without the syslog header.
        host: Hostname / computer name that produced the record.
        user: Primary account the event is about (actor for sudo/su,
            target account for logons, member for group changes).
        target_user: Run-as account for sudo/su/pkexec.
        src_ip: Remote source address, if any.
        command: Executed command line, if any.
        group: Group name for membership changes.
        event_id: Windows event ID (``None`` for Linux).
        rule_id: Identifier of the parsing rule that classified the record.
        severity_hint: Optional severity override supplied by the parsing rule.
        count: Number of occurrences represented (syslog "message repeated").
        origin: ``file:line`` or ``file#record`` locator for evidence.
        raw: Original (truncated) record text used as evidence.
        fields: Additional format-specific attributes.
    """

    timestamp: datetime
    category: str
    source: str
    message: str
    host: str | None = None
    user: str | None = None
    target_user: str | None = None
    src_ip: str | None = None
    command: str | None = None
    group: str | None = None
    event_id: int | None = None
    rule_id: str | None = None
    severity_hint: str | None = None
    count: int = 1
    origin: str = ""
    raw: str = ""
    fields: dict[str, str] = field(default_factory=dict)


@dataclass
class ParseStats:
    """Counters collected while parsing input files."""

    files: list[str] = field(default_factory=list)
    bytes_total: int = 0
    records_read: int = 0
    events_emitted: int = 0
    unmatched: int = 0
    malformed: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return asdict(self)


# --------------------------------------------------------------------------- #
# Generic helpers
# --------------------------------------------------------------------------- #
_EMPTY_VALUES = frozenset({"", "-", "n/a", "null", "none", "(unknown)", "unknown"})
_FRACTION_RE = re.compile(r"(\.\d{6})\d+")
_COMPACT_OFFSET_RE = re.compile(r"([+-]\d{2})(\d{2})$")
_TZ_OFFSET_RE = re.compile(r"^(?:UTC)?([+-])(\d{1,2}):?(\d{2})?$", re.IGNORECASE)


def clean_value(value: str | None) -> str | None:
    """Strip ``value`` and map placeholder values such as ``-`` to ``None``."""
    if value is None:
        return None
    value = value.strip()
    return None if value.lower() in _EMPTY_VALUES else value


def clean_ip(value: str | None) -> str | None:
    """Normalize an address field, unwrapping IPv4-mapped IPv6 addresses."""
    value = clean_value(value)
    if value is not None and value.lower().startswith("::ffff:") and "." in value:
        value = value[7:]
    return value


def parse_iso_timestamp(value: str) -> datetime:
    """Parse ISO 8601 / RFC 3339 timestamps with Windows-specific variations.

    Handles a trailing ``Z`` or `` UTC`` suffix, more than six fractional digits
    (Windows emits seven) and compact ``+0400`` offsets.

    Raises:
        ValueError: If the value is not a valid timestamp.
    """
    text = value.strip()
    if text.endswith(" UTC"):
        text = text[:-4] + "+00:00"
    elif text[-1:] in ("Z", "z"):
        text = text[:-1] + "+00:00"
    text = _FRACTION_RE.sub(r"\1", text, count=1)
    text = _COMPACT_OFFSET_RE.sub(r"\1:\2", text, count=1)
    return datetime.fromisoformat(text)


def _parse_timezone(spec: str | None) -> tzinfo | None:
    """Translate a timezone specification into a ``tzinfo`` (``None`` = local)."""
    if spec is None or spec.strip().lower() in ("", "local"):
        return None
    spec = spec.strip()
    if spec.upper() in ("UTC", "Z", "GMT"):
        return timezone.utc
    match = _TZ_OFFSET_RE.match(spec)
    if match:
        sign = -1 if match.group(1) == "-" else 1
        offset = timedelta(hours=int(match.group(2)), minutes=int(match.group(3) or 0))
        return timezone(sign * offset)
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(spec)
    except Exception as exc:  # ZoneInfoNotFoundError, missing tzdata on Windows, ...
        raise ConfigError(
            f"Invalid timezone '{spec}'. Use 'local', 'UTC', an offset such as '+04:00', "
            "or an IANA name (requires the 'tzdata' package on Windows)."
        ) from exc


class TimeNormalizer:
    """Converts timezone-aware timestamps into naive analysis-timezone datetimes.

    Naive timestamps (classic syslog, CSV exports) are assumed to already be in
    the analysis timezone and are returned unchanged.
    """

    def __init__(self, spec: str | None = "local") -> None:
        self.spec = spec or "local"
        self._target = _parse_timezone(spec)

    def normalize(self, value: datetime) -> datetime:
        """Return ``value`` as a naive datetime in the analysis timezone."""
        if value.tzinfo is None:
            return value
        converted = value.astimezone(self._target) if self._target else value.astimezone()
        return converted.replace(tzinfo=None)


def _detect_encoding(sample: bytes) -> str:
    """Guess the text encoding of a file from its first bytes."""
    if sample.startswith(codecs.BOM_UTF8):
        return "utf-8-sig"
    if sample.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return "utf-16"
    if len(sample) >= 4:
        if sample[0] != 0 and sample[1] == 0 and sample[3] == 0:
            return "utf-16-le"
        if sample[0] == 0 and sample[2] == 0 and sample[1] != 0:
            return "utf-16-be"
    return "utf-8"


def open_text(path: Path, newline: str | None = None) -> TextIO:
    """Open ``path`` as a buffered text stream with automatic decoding.

    Gzip-compressed files are decompressed transparently, BOM-marked UTF-8 and
    UTF-16 files (the PowerShell default) are detected, and undecodable bytes
    are replaced rather than aborting the run.

    Raises:
        LogParseError: If the file cannot be opened.
    """
    try:
        if path.suffix.lower() == ".gz":
            binary: Any = gzip.open(path, "rb")
        else:
            binary = open(path, "rb", buffering=READ_BUFFER_SIZE)
    except OSError as exc:
        raise LogParseError(f"Cannot open '{path}': {exc}") from exc
    try:
        encoding = _detect_encoding(binary.peek(4)[:4])
    except (OSError, EOFError) as exc:
        binary.close()
        raise LogParseError(f"Cannot read '{path}': {exc}") from exc
    return io.TextIOWrapper(binary, encoding=encoding, errors="replace", newline=newline)


# --------------------------------------------------------------------------- #
# Base parser
# --------------------------------------------------------------------------- #
class BaseLogParser(ABC):
    """Common interface for all log parsers."""

    def __init__(self, config: dict[str, Any], normalizer: TimeNormalizer) -> None:
        self.config = config
        self.normalizer = normalizer
        self.stats = ParseStats()

    @abstractmethod
    def parse_file(self, path: Path) -> Iterator[LogEvent]:
        """Yield security-relevant events from a single file."""

    def parse_files(self, paths: Iterable[Path]) -> Iterator[LogEvent]:
        """Yield events from several files sequentially.

        A read or decode error in one file is logged and recorded in
        :attr:`stats` so that the remaining files are still processed. Missing
        optional dependencies are re-raised because they affect every file.
        """
        for path in paths:
            self.stats.files.append(str(path))
            try:
                self.stats.bytes_total += path.stat().st_size
            except OSError:
                pass
            try:
                yield from self.parse_file(path)
            except MissingDependencyError:
                raise
            except (LogParseError, OSError, EOFError, UnicodeError, ET.ParseError, csv.Error) as exc:
                message = f"{path.name}: {exc}"
                logger.error("Stopped reading %s", message)
                self.stats.errors.append(message)

    def _emit(self, event: LogEvent | None) -> LogEvent | None:
        if event is not None:
            self.stats.events_emitted += 1
        return event


# --------------------------------------------------------------------------- #
# Linux syslog / auth.log
# --------------------------------------------------------------------------- #
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}
_SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) (?P<clock>\d{2}:\d{2}:\d{2})(?:\.\d+)? "
    r"(?P<host>\S+) (?P<proc>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$"
)
_ISO_SYSLOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) "
    r"(?P<host>\S+) (?P<proc>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$"
)
_REPEATED_RE = re.compile(r"^message repeated (?P<count>\d+) times: \[ ?(?P<msg>.*?) ?\]$")
_LINUX_CORE_GROUPS = frozenset({"user", "target_user", "ip", "command", "group"})


@dataclass(frozen=True, slots=True)
class _LinuxRule:
    rule_id: str
    category: str
    pattern: re.Pattern[str]
    severity: str | None


def _compile_linux_rule(rule: dict[str, Any], index: int) -> _LinuxRule:
    rule_id = rule.get("id") or f"rule_{index}"
    category = rule.get("category")
    if category not in EventCategory.ALL:
        raise ConfigError(f"Linux rule '{rule_id}' has an unknown category: {category!r}")
    pattern = rule.get("pattern")
    if not pattern:
        raise ConfigError(f"Linux rule '{rule_id}' has no 'pattern'.")
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise ConfigError(f"Linux rule '{rule_id}' has an invalid regex: {exc}") from exc
    return _LinuxRule(rule_id, category, compiled, rule.get("severity"))


class LinuxLogParser(BaseLogParser):
    """Parser for syslog-formatted Linux logs (``auth.log``, ``secure``, ``syslog``).

    Rules are indexed by program name so that each line is only tested against
    the handful of regular expressions relevant to its emitting daemon; lines
    from programs without rules are discarded after a single header match.
    """

    def __init__(
        self,
        config: dict[str, Any],
        normalizer: TimeNormalizer,
        year: int | None = None,
    ) -> None:
        super().__init__(config, normalizer)
        rules_cfg = config.get("linux", {}).get("rules", [])
        if not rules_cfg:
            raise ConfigError("No Linux parsing rules defined ('linux.rules').")

        program_rules: dict[str, list[_LinuxRule]] = {}
        generic_rules: list[_LinuxRule] = []
        for index, rule_cfg in enumerate(rules_cfg):
            if not rule_cfg.get("enabled", True):
                continue
            rule = _compile_linux_rule(rule_cfg, index)
            programs = rule_cfg.get("programs") or []
            if programs:
                for program in programs:
                    program_rules.setdefault(program, []).append(rule)
            else:
                generic_rules.append(rule)

        self._rules_by_program = {prog: rules + generic_rules for prog, rules in program_rules.items()}
        self._generic_rules = generic_rules
        self._year = year
        self._last_month: int | None = None

    def parse_file(self, path: Path) -> Iterator[LogEvent]:
        """Yield classified events from a (optionally gzip-compressed) syslog file."""
        name = path.name
        with open_text(path) as stream:
            for line_no, line in enumerate(stream, 1):
                self.stats.records_read += 1
                event = self._parse_line(line.rstrip("\r\n"))
                if event is not None:
                    event.origin = f"{name}:{line_no}"
                    self.stats.events_emitted += 1
                    yield event

    def _parse_line(self, line: str) -> LogEvent | None:
        if not line:
            self.stats.unmatched += 1
            return None
        try:
            header = _SYSLOG_RE.match(line)
            if header is not None:
                timestamp = self._syslog_timestamp(
                    header.group("mon"), int(header.group("day")), header.group("clock")
                )
            else:
                header = _ISO_SYSLOG_RE.match(line)
                if header is None:
                    self.stats.malformed += 1
                    return None
                timestamp = self.normalizer.normalize(parse_iso_timestamp(header.group("ts")))
        except ValueError:
            self.stats.malformed += 1
            return None

        program = header.group("proc")
        rules = self._rules_by_program.get(program) or self._generic_rules
        if not rules:
            self.stats.unmatched += 1
            return None

        message = header.group("msg")
        count = 1
        if message.startswith("message repeated "):
            repeated = _REPEATED_RE.match(message)
            if repeated is not None:
                count = int(repeated.group("count"))
                message = repeated.group("msg")

        for rule in rules:
            hit = rule.pattern.search(message)
            if hit is not None:
                return self._build_event(rule, hit, timestamp, header.group("host"), program, message, line, count)

        self.stats.unmatched += 1
        return None

    def _syslog_timestamp(self, mon: str, day: int, clock: str) -> datetime:
        """Build a datetime for a year-less BSD syslog timestamp.

        The year is inferred once (current year, or the previous one if that
        would place the log in the future) and then adjusted whenever the month
        sequence wraps around, e.g. December followed by January.
        """
        month = _MONTHS.get(mon)
        if month is None:
            raise ValueError(f"unknown month {mon!r}")
        if self._year is None:
            now = datetime.now()
            self._year = now.year
            if datetime(now.year, month, min(day, 28)) > now + timedelta(days=2):
                self._year -= 1
        elif self._last_month is not None:
            if self._last_month - month > 6:
                self._year += 1
            elif month - self._last_month > 6:
                self._year -= 1
        self._last_month = month
        return datetime(self._year, month, day, int(clock[0:2]), int(clock[3:5]), int(clock[6:8]))

    @staticmethod
    def _build_event(
        rule: _LinuxRule,
        hit: re.Match[str],
        timestamp: datetime,
        host: str,
        program: str,
        message: str,
        line: str,
        count: int,
    ) -> LogEvent:
        groups = hit.groupdict()
        extra = {key: value for key, value in groups.items() if key not in _LINUX_CORE_GROUPS and value}
        return LogEvent(
            timestamp=timestamp,
            category=rule.category,
            source=program,
            message=message,
            host=host,
            user=clean_value(groups.get("user")),
            target_user=clean_value(groups.get("target_user")),
            src_ip=clean_ip(groups.get("ip")),
            command=clean_value(groups.get("command")),
            group=clean_value(groups.get("group")),
            rule_id=rule.rule_id,
            severity_hint=rule.severity,
            count=count,
            raw=line[:MAX_RAW_LENGTH],
            fields=extra,
        )


# --------------------------------------------------------------------------- #
# Windows Event Logs
# --------------------------------------------------------------------------- #
_XML_DECL_RE = re.compile(r"^\s*<\?xml[^>]*\?>")
_EVENT_START_RE = re.compile(r"<Event[\s>]")
_EVENT_END = "</Event>"
_WEVT_RECORD_RE = re.compile(r"^Event\[\d+\]:\s*$")
_KEY_VALUE_RE = re.compile(r"^\s*(?P<key>[A-Za-z][A-Za-z0-9 ()/-]*?):[ \t]*(?P<value>.*?)\s*$")
_CN_RE = re.compile(r"^CN=((?:\\,|[^,])+)", re.IGNORECASE)

# Message sections (rendered event text) whose "Account Name" refers to the
# subject (actor), the target account, or a group member respectively.
_MESSAGE_SECTIONS = {
    "subject": "Subject",
    "creator subject": "Subject",
    "new logon": "Target",
    "account for which logon failed": "Target",
    "new account": "Target",
    "target account": "Target",
    "account information": "Target",
    "member": "Member",
}
_SECTION_FIELDS = {
    ("Subject", "account name"): "SubjectUserName",
    ("Subject", "account domain"): "SubjectDomainName",
    ("Target", "account name"): "TargetUserName",
    ("Target", "account domain"): "TargetDomainName",
    ("Member", "account name"): "MemberName",
    ("Member", "security id"): "MemberSid",
}
_GLOBAL_FIELDS = {
    "logon type": "LogonType",
    "source network address": "IpAddress",
    "client address": "IpAddress",
    "workstation name": "WorkstationName",
    "group name": "TargetUserName",
    "new process name": "NewProcessName",
    "process command line": "CommandLine",
    "creator process name": "ParentProcessName",
    "failure reason": "FailureReason",
    "status": "Status",
    "sub status": "SubStatus",
    "privileges": "PrivilegeList",
}
_SUMMARY_FIELDS = (
    "TargetUserName", "SubjectUserName", "MemberName", "IpAddress", "LogonType",
    "WorkstationName", "NewProcessName", "CommandLine", "Status", "SubStatus",
)
_CSV_COLUMN_ALIASES = {
    "timestamp": ("timecreated", "date and time", "timegenerated", "datetime", "timestamp", "date"),
    "event_id": ("id", "eventid", "event id", "instanceid"),
    "provider": ("providername", "source", "provider"),
    "computer": ("machinename", "computer", "computername"),
    "message": ("message", "description", "details"),
}
_EXTENSION_FORMATS = {".evtx": "evtx", ".xml": "xml", ".csv": "csv", ".txt": "text", ".log": "text"}


def _local_name(tag: str) -> str:
    return tag[tag.find("}") + 1:]


def _member_name(value: str | None) -> str | None:
    """Extract a readable account name from a distinguished name (``CN=...``)."""
    value = clean_value(value)
    if value is None:
        return None
    match = _CN_RE.match(value)
    return match.group(1).replace("\\,", ",") if match else value


def extract_message_fields(message: str) -> dict[str, str]:
    """Extract structured fields from a rendered Windows event message.

    CSV and text exports only contain the human-readable description. This
    function maps its indented ``Key: Value`` lines back to the EventData field
    names used in the XML representation (``TargetUserName``, ``IpAddress``,
    ...) taking the enclosing section into account. English messages only.
    """
    fields: dict[str, str] = {}
    section = ""
    for line in message.splitlines():
        match = _KEY_VALUE_RE.match(line)
        if match is None:
            continue
        key = match.group("key").strip().lower()
        value = match.group("value")
        if not value:
            # Unindented headers such as "Network Information:" open a new section.
            if key in _MESSAGE_SECTIONS:
                section = _MESSAGE_SECTIONS[key]
            elif line[:1] not in (" ", "\t"):
                section = ""
            continue
        name = _SECTION_FIELDS.get((section, key)) or _GLOBAL_FIELDS.get(key)
        if name:
            fields.setdefault(name, value)
    return fields


class WindowsEventParser(BaseLogParser):
    """Parser for Windows Security / System event logs in several formats."""

    FORMATS = ("auto", "evtx", "xml", "csv", "text")

    def __init__(
        self,
        config: dict[str, Any],
        normalizer: TimeNormalizer,
        input_format: str = "auto",
    ) -> None:
        super().__init__(config, normalizer)
        if input_format not in self.FORMATS:
            raise ConfigError(f"Unsupported Windows input format: {input_format!r}")
        self.input_format = input_format
        win_cfg = config.get("windows", {})
        self._categories = self._load_categories(win_cfg.get("event_categories", {}))
        self._timestamp_formats: list[str] = list(win_cfg.get("timestamp_formats", []))
        self._last_format: str | None = None
        self._sid_names: dict[str, str] = {}

    @staticmethod
    def _load_categories(raw: dict[str, Any]) -> dict[int, tuple[str, str | None]]:
        if not raw:
            raise ConfigError("No Windows event categories defined ('windows.event_categories').")
        categories: dict[int, tuple[str, str | None]] = {}
        for key, spec in raw.items():
            try:
                event_id = int(key)
            except ValueError as exc:
                raise ConfigError(f"Invalid Windows event ID in configuration: {key!r}") from exc
            if isinstance(spec, str):
                category, provider = spec, None
            elif isinstance(spec, dict):
                category, provider = spec.get("category"), spec.get("provider_contains")
            else:
                raise ConfigError(f"Invalid mapping for Windows event {key}: {spec!r}")
            if category not in EventCategory.ALL:
                raise ConfigError(f"Windows event {key} maps to unknown category {category!r}")
            categories[event_id] = (category, provider.lower() if provider else None)
        return categories

    # -- format dispatch ---------------------------------------------------- #
    def parse_file(self, path: Path) -> Iterator[LogEvent]:
        """Yield classified events from a Windows event log export."""
        fmt = self.resolve_format(path)
        logger.debug("Parsing %s as Windows '%s' format", path, fmt)
        handlers = {
            "evtx": self._parse_evtx,
            "xml": self._parse_xml,
            "csv": self._parse_csv,
            "text": self._parse_text,
        }
        yield from handlers[fmt](path)

    def resolve_format(self, path: Path) -> str:
        """Determine the input format from the CLI override, extension or content."""
        if self.input_format != "auto":
            return self.input_format
        suffix = path.suffix.lower()
        if suffix == ".gz":
            suffix = Path(path.stem).suffix.lower()
        if suffix in _EXTENSION_FORMATS:
            return _EXTENSION_FORMATS[suffix]
        try:
            with open(path, "rb") as handle:
                if handle.read(8).startswith(b"ElfFile"):
                    return "evtx"
        except OSError as exc:
            raise LogParseError(f"Cannot open '{path}': {exc}") from exc
        with open_text(path) as stream:
            sample = stream.read(4096).lstrip("\ufeff \t\r\n")
        if sample.startswith("<"):
            return "xml"
        if sample.startswith("Event["):
            return "text"
        return "csv"

    # -- EVTX --------------------------------------------------------------- #
    def _parse_evtx(self, path: Path) -> Iterator[LogEvent]:
        name = path.name
        try:
            from evtx import PyEvtxParser  # Optional Rust-based backend, much faster.
        except ImportError:
            PyEvtxParser = None

        if PyEvtxParser is not None:
            for index, record in enumerate(PyEvtxParser(str(path)).records(), 1):
                self.stats.records_read += 1
                xml_text = record.get("data") if isinstance(record, dict) else None
                event = self._event_from_xml_string(xml_text, f"{name}#{index}")
                if self._emit(event):
                    yield event
            return

        try:
            from Evtx.Evtx import Evtx
        except ImportError as exc:
            raise MissingDependencyError(
                "Parsing .evtx files requires 'python-evtx' (pip install python-evtx) "
                "or the faster 'evtx' package (pip install evtx). Install only one of them: "
                "on Windows/macOS they overwrite each other (reinstall with --force-reinstall)."
            ) from exc

        with Evtx(str(path)) as log:
            for index, record in enumerate(log.records(), 1):
                self.stats.records_read += 1
                try:
                    xml_text = record.xml()
                except Exception as exc:  # python-evtx raises assorted errors on corrupt chunks.
                    logger.debug("Skipping unreadable EVTX record %d: %s", index, exc)
                    self.stats.malformed += 1
                    continue
                event = self._event_from_xml_string(xml_text, f"{name}#{index}")
                if self._emit(event):
                    yield event

    def _event_from_xml_string(self, xml_text: str | None, origin: str) -> LogEvent | None:
        if not xml_text:
            self.stats.malformed += 1
            return None
        if xml_text.lstrip().startswith("<?xml"):
            xml_text = _XML_DECL_RE.sub("", xml_text, count=1)
        try:
            element = ET.fromstring(xml_text)
        except ET.ParseError:
            self.stats.malformed += 1
            return None
        return self._event_from_element(element, origin)

    # -- XML ---------------------------------------------------------------- #
    def _parse_xml(self, path: Path) -> Iterator[LogEvent]:
        """Stream ``<Event>`` records from an XML export with bounded memory.

        Works for Event Viewer exports (``<Events>`` root) as well as
        ``wevtutil qe /f:xml`` output (no root element). The text stream is
        split on ``<Event>`` boundaries and each record is parsed on its own
        with the C-accelerated ``ElementTree.fromstring``, which is several
        times faster than per-element pull parsing and keeps memory flat.
        """
        name = path.name
        index = 0
        buffer = ""
        eof = False
        with open_text(path) as stream:
            while not eof:
                chunk = stream.read(XML_CHUNK_SIZE)
                eof = not chunk
                buffer += chunk
                position = 0
                while True:
                    start = _EVENT_START_RE.search(buffer, position)
                    if start is None:
                        # Keep a short tail in case an "<Event" tag spans two chunks.
                        position = max(position, len(buffer) - 16)
                        break
                    end = buffer.find(_EVENT_END, start.end())
                    if end == -1:
                        position = start.start()
                        break
                    end += len(_EVENT_END)
                    index += 1
                    self.stats.records_read += 1
                    event = self._event_from_xml_string(buffer[start.start():end], f"{name}#{index}")
                    if self._emit(event):
                        yield event
                    position = end
                buffer = buffer[position:]
        if _EVENT_START_RE.search(buffer):
            logger.warning("%s ends with a truncated <Event> record", name)
            self.stats.malformed += 1

    def _event_from_element(self, element: ET.Element, origin: str) -> LogEvent | None:
        sections = {_local_name(child.tag): child for child in element}
        system = sections.get("System")
        if system is None:
            self.stats.malformed += 1
            return None
        header = {_local_name(child.tag): child for child in system}
        try:
            event_id = int((header["EventID"].text or "").strip())
        except (KeyError, ValueError):
            self.stats.malformed += 1
            return None

        provider_el = header.get("Provider")
        provider = provider_el.get("Name", "") if provider_el is not None else ""
        if not self._is_relevant(event_id, provider):
            return None

        try:
            timestamp = self.normalizer.normalize(parse_iso_timestamp(header["TimeCreated"].get("SystemTime", "")))
        except (KeyError, ValueError, IndexError):
            self.stats.malformed += 1
            return None

        data: dict[str, str] = {}
        event_data = sections.get("EventData")
        if event_data is not None:
            for item in event_data:
                key = item.get("Name")
                if key:
                    data[key] = (item.text or "").strip()
        user_data = sections.get("UserData")
        if user_data is not None:
            for leaf in user_data.iter():
                if len(leaf) == 0 and leaf.text and leaf is not user_data:
                    data.setdefault(_local_name(leaf.tag), leaf.text.strip())

        message = ""
        rendering = sections.get("RenderingInfo")
        if rendering is not None:
            for child in rendering:
                if _local_name(child.tag) == "Message":
                    message = child.text or ""
                    break
        computer_el = header.get("Computer")
        computer = clean_value(computer_el.text) if computer_el is not None else None
        return self._build_event(event_id, timestamp, provider, computer, data, message, origin)

    # -- CSV ---------------------------------------------------------------- #
    def _parse_csv(self, path: Path) -> Iterator[LogEvent]:
        """Parse Event Viewer or PowerShell ``Export-Csv`` exports row by row."""
        name = path.name
        with open_text(path, newline="") as stream:
            reader = csv.reader(stream)
            header: list[str] | None = None
            for row in reader:
                if not row or (row[0].startswith("#TYPE") and header is None):
                    continue
                header = row
                break
            if header is None:
                return
            columns = self._map_csv_columns(header)
            if "event_id" not in columns or "timestamp" not in columns:
                raise LogParseError(
                    f"Unrecognized CSV header in '{path}': expected event ID and timestamp columns."
                )

            for row_no, row in enumerate(reader, 2):
                if not row:
                    continue
                self.stats.records_read += 1
                event = self._event_from_csv_row(row, columns, f"{name}:{row_no}")
                if self._emit(event):
                    yield event

    @staticmethod
    def _map_csv_columns(header: list[str]) -> dict[str, int]:
        normalized = [column.strip().lstrip("\ufeff").lower() for column in header]
        columns: dict[str, int] = {}
        for key, aliases in _CSV_COLUMN_ALIASES.items():
            for alias in aliases:
                if alias in normalized:
                    columns[key] = normalized.index(alias)
                    break
        # Event Viewer writes the description as an unnamed trailing column.
        columns.setdefault("message", len(header))
        return columns

    def _event_from_csv_row(self, row: list[str], columns: dict[str, int], origin: str) -> LogEvent | None:
        def cell(key: str) -> str:
            index = columns.get(key)
            return row[index] if index is not None and index < len(row) else ""

        try:
            event_id = int(cell("event_id").strip())
        except ValueError:
            self.stats.malformed += 1
            return None
        provider = cell("provider")
        if not self._is_relevant(event_id, provider):
            return None
        timestamp = self._parse_export_timestamp(cell("timestamp"))
        if timestamp is None:
            self.stats.malformed += 1
            return None
        message = cell("message")
        return self._build_event(
            event_id, timestamp, provider, clean_value(cell("computer")),
            extract_message_fields(message), message, origin,
        )

    # -- wevtutil text ------------------------------------------------------ #
    def _parse_text(self, path: Path) -> Iterator[LogEvent]:
        """Parse ``wevtutil qe <log> /f:text`` output record by record."""
        name = path.name
        header: dict[str, str] = {}
        description: list[str] = []
        in_description = False
        index = 0

        with open_text(path) as stream:
            for line in stream:
                line = line.rstrip("\r\n")
                if _WEVT_RECORD_RE.match(line):
                    if header:
                        event = self._event_from_text_record(header, description, f"{name}#{index}")
                        if self._emit(event):
                            yield event
                    header, description, in_description = {}, [], False
                    index += 1
                    continue
                if in_description:
                    description.append(line)
                    continue
                match = _KEY_VALUE_RE.match(line)
                if match is None:
                    continue
                key, value = match.group("key").strip(), match.group("value")
                if key == "Description":
                    in_description = True
                    if value:
                        description.append(value)
                else:
                    header[key] = value

            if header:
                event = self._event_from_text_record(header, description, f"{name}#{index}")
                if self._emit(event):
                    yield event

    def _event_from_text_record(self, header: dict[str, str], description: list[str], origin: str) -> LogEvent | None:
        self.stats.records_read += 1
        try:
            event_id = int(header.get("Event ID", "").strip())
        except ValueError:
            self.stats.malformed += 1
            return None
        provider = header.get("Source", "")
        if not self._is_relevant(event_id, provider):
            return None
        timestamp = self._parse_export_timestamp(header.get("Date", ""))
        if timestamp is None:
            self.stats.malformed += 1
            return None
        message = "\n".join(description)
        return self._build_event(
            event_id, timestamp, provider, clean_value(header.get("Computer")),
            extract_message_fields(message), message, origin,
        )

    # -- shared helpers ----------------------------------------------------- #
    _SID_NAME_FIELDS = (
        ("TargetSid", "TargetUserName"),
        ("TargetUserSid", "TargetUserName"),
        ("SubjectUserSid", "SubjectUserName"),
    )

    def _remember_sids(self, data: dict[str, str]) -> None:
        """Cache SID-to-account-name pairs seen in event data (bounded)."""
        if len(self._sid_names) >= 100_000:
            return
        for sid_key, name_key in self._SID_NAME_FIELDS:
            sid, name = clean_value(data.get(sid_key)), clean_value(data.get(name_key))
            if sid and name and sid.startswith("S-1-5-21-"):
                self._sid_names[sid] = name

    def _is_relevant(self, event_id: int, provider: str) -> bool:
        spec = self._categories.get(event_id)
        if spec is None or (spec[1] and spec[1] not in provider.lower()):
            self.stats.unmatched += 1
            return False
        return True

    def _parse_export_timestamp(self, value: str) -> datetime | None:
        """Parse a timestamp from CSV/text exports (ISO or locale-specific)."""
        value = value.strip()
        if not value:
            return None
        if self._last_format:
            try:
                return datetime.strptime(value, self._last_format)
            except ValueError:
                pass
        try:
            return self.normalizer.normalize(parse_iso_timestamp(value))
        except ValueError:
            pass
        for fmt in self._timestamp_formats:
            try:
                parsed = datetime.strptime(value, fmt)
            except ValueError:
                continue
            self._last_format = fmt
            return parsed
        return None

    def _build_event(
        self,
        event_id: int,
        timestamp: datetime,
        provider: str,
        computer: str | None,
        data: dict[str, str],
        message: str,
        origin: str,
    ) -> LogEvent:
        category = self._categories[event_id][0]
        subject = clean_value(data.get("SubjectUserName"))
        target = clean_value(data.get("TargetUserName"))
        self._remember_sids(data)
        user: str | None = target or subject
        command = group = None
        fields: dict[str, str] = {}

        if category in (EventCategory.AUTH_SUCCESS, EventCategory.AUTH_FAILURE):
            for source_key, field_key in (
                ("LogonType", "logon_type"), ("WorkstationName", "workstation"),
                ("Status", "status"), ("SubStatus", "sub_status"), ("FailureReason", "failure_reason"),
            ):
                value = clean_value(data.get(source_key))
                if value:
                    fields[field_key] = value
        elif category in (EventCategory.SPECIAL_PRIVILEGES, EventCategory.PROCESS_EXEC, EventCategory.LOG_CLEARED):
            user = subject or target
            if category == EventCategory.PROCESS_EXEC:
                command = clean_value(data.get("CommandLine")) or clean_value(data.get("NewProcessName"))
                parent = clean_value(data.get("ParentProcessName"))
                if parent:
                    fields["parent_process"] = parent
            elif category == EventCategory.SPECIAL_PRIVILEGES and data.get("PrivilegeList"):
                fields["privileges"] = " ".join(data["PrivilegeList"].split())
        elif category == EventCategory.GROUP_CHANGE:
            member_sid = clean_value(data.get("MemberSid"))
            # Local group changes (4732) carry only the member SID; resolve it
            # from earlier events such as 4720 when possible.
            user = _member_name(data.get("MemberName")) or self._sid_names.get(member_sid or "") or member_sid
            if member_sid:
                fields["member_sid"] = member_sid
            group = target
            if subject:
                fields["actor"] = subject
        elif category == EventCategory.ACCOUNT_CREATED:
            user = target
            if subject:
                fields["actor"] = subject

        summary = " ".join(
            f"{key}={data[key]}" for key in _SUMMARY_FIELDS if clean_value(data.get(key))
        )
        first_line = message.strip().splitlines()[0] if message.strip() else ""
        raw = f"EventID={event_id} {timestamp.isoformat(sep=' ')} Computer={computer or '-'} {summary}"
        if first_line:
            raw = f"{raw} | {first_line}"

        return LogEvent(
            timestamp=timestamp,
            category=category,
            source=provider,
            message=first_line,
            host=computer,
            user=user,
            src_ip=clean_ip(data.get("IpAddress")),
            command=command,
            group=group,
            event_id=event_id,
            rule_id=f"winevt_{event_id}",
            origin=origin,
            raw=raw[:MAX_RAW_LENGTH],
            fields=fields,
        )


# --------------------------------------------------------------------------- #
# Factory helpers
# --------------------------------------------------------------------------- #
_WINDOWS_EXTENSIONS = frozenset({".evtx", ".xml", ".csv"})


def detect_log_type(path: Path) -> str:
    """Guess whether ``path`` holds Linux or Windows logs (``"linux"``/``"windows"``)."""
    suffix = path.suffix.lower()
    if suffix == ".gz":
        suffix = Path(path.stem).suffix.lower()
    if suffix in _WINDOWS_EXTENSIONS:
        return "windows"
    try:
        with open(path, "rb") as handle:
            if handle.read(8).startswith(b"ElfFile"):
                return "windows"
        with open_text(path) as stream:
            if stream.read(4096).lstrip("\ufeff \t\r\n").startswith("Event["):
                return "windows"
    except (OSError, LogParseError):
        pass
    return "linux"


def create_parser(
    log_type: str,
    config: dict[str, Any],
    normalizer: TimeNormalizer,
    *,
    input_format: str = "auto",
    year: int | None = None,
) -> BaseLogParser:
    """Instantiate the parser matching ``log_type``.

    Raises:
        ConfigError: If the log type is unknown or the configuration is invalid.
    """
    if log_type == "linux":
        return LinuxLogParser(config, normalizer, year=year)
    if log_type == "windows":
        return WindowsEventParser(config, normalizer, input_format=input_format)
    raise ConfigError(f"Unsupported log type: {log_type!r}")
