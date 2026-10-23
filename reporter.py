"""
Report generation for LogTriage-CLI.

* :func:`build_report` assembles a single JSON-serializable report document.
* :func:`write_json` / :func:`write_html` persist it (HTML is rendered with
  Jinja2 from ``templates/report.html.j2`` with autoescaping enabled, because
  log content is attacker-controlled).
* :class:`ConsoleReporter` prints a colorized terminal summary.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO

from analyzer import AnalysisResult
from parsers import ParseStats

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
HTML_TEMPLATE = "report.html.j2"
REPORT_SCHEMA_VERSION = "1.0"


class ReportError(Exception):
    """Raised when a report cannot be rendered or written."""


# --------------------------------------------------------------------------- #
# Report document
# --------------------------------------------------------------------------- #
def build_report(
    result: AnalysisResult,
    parse_stats: ParseStats,
    *,
    tool_version: str,
    log_type: str,
    input_format: str,
    timezone: str,
    elapsed_seconds: float,
    integrations: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the complete report document shared by all output formats."""
    statistics = result.statistics.to_dict()
    elapsed = max(elapsed_seconds, 1e-6)
    return {
        "report_version": REPORT_SCHEMA_VERSION,
        "tool": {"name": "LogTriage-CLI", "version": tool_version},
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "input": {
            "files": parse_stats.files,
            "files_display": [Path(name).name for name in parse_stats.files],
            "log_type": log_type,
            "input_format": input_format,
            "timezone": timezone,
        },
        "summary": {
            "risk_score": result.risk.score,
            "risk_level": result.risk.level.label,
            "findings_total": len(result.findings),
            "severity_counts": result.risk.severity_counts,
            "events_analyzed": result.statistics.total_events,
            "records_processed": parse_stats.records_read,
            "time_range": {"start": statistics["first_event"], "end": statistics["last_event"]},
            "processing_seconds": round(elapsed_seconds, 3),
            "records_per_second": int(parse_stats.records_read / elapsed),
        },
        "risk": result.risk.to_dict(),
        "findings": [finding.to_dict() for finding in result.findings],
        "statistics": statistics,
        "parsing": parse_stats.to_dict(),
        "context": result.context,
        "integrations": integrations or {},
    }


# --------------------------------------------------------------------------- #
# Writers
# --------------------------------------------------------------------------- #
def _atomic_write(path: Path, content: str) -> Path:
    """Write ``content`` to ``path`` via a temporary file to avoid partial reports."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.tmp")
        temporary.write_text(content, encoding="utf-8")
        os.replace(temporary, path)
    except OSError as exc:
        raise ReportError(f"Cannot write report '{path}': {exc}") from exc
    return path


def to_json(report: dict[str, Any]) -> str:
    """Serialize ``report`` as pretty-printed JSON."""
    return json.dumps(report, indent=2, ensure_ascii=False, default=str)


def write_json(report: dict[str, Any], path: Path) -> Path:
    """Write the JSON report to ``path``."""
    return _atomic_write(path, to_json(report) + "\n")


def _format_timestamp(value: str | None) -> str:
    if not value:
        return "-"
    try:
        return datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return value


def _mitre_url(technique: str) -> str:
    return f"https://attack.mitre.org/techniques/{technique.replace('.', '/')}/"


def render_html(report: dict[str, Any]) -> str:
    """Render the HTML report.

    Raises:
        ReportError: If Jinja2 is missing or the template cannot be rendered.
    """
    try:
        from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateError
    except ImportError as exc:
        raise ReportError("HTML reports require Jinja2 (pip install Jinja2).") from exc

    environment = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    environment.filters["ts"] = _format_timestamp
    environment.filters["mitre_url"] = _mitre_url
    environment.filters["thousands"] = lambda value: f"{int(value):,}"

    hourly = report["statistics"]["hourly_activity"]
    flags = report["context"].get("business_hour_flags") or [True] * 24
    try:
        template = environment.get_template(HTML_TEMPLATE)
        return template.render(
            report=report,
            hourly=list(zip(range(24), hourly, flags)),
            hourly_max=max(hourly) or 1,
            category_max=max((c["count"] for c in report["statistics"]["by_category"]), default=1),
        )
    except TemplateError as exc:
        raise ReportError(f"Failed to render HTML report: {exc}") from exc


def write_html(report: dict[str, Any], path: Path) -> Path:
    """Render and write the HTML report to ``path``."""
    return _atomic_write(path, render_html(report))


# --------------------------------------------------------------------------- #
# Console
# --------------------------------------------------------------------------- #
class _Palette:
    """ANSI color helpers backed by colorama, degrading to plain text."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = False
        self.codes: dict[str, str] = {}
        if not enabled:
            return
        try:
            import colorama
        except ImportError:
            return
        if hasattr(colorama, "just_fix_windows_console"):
            colorama.just_fix_windows_console()
        else:
            colorama.init()
        fore, style = colorama.Fore, colorama.Style
        self.codes = {
            "Critical": fore.MAGENTA + style.BRIGHT,
            "High": fore.RED + style.BRIGHT,
            "Medium": fore.YELLOW + style.BRIGHT,
            "Low": fore.GREEN,
            "title": fore.CYAN + style.BRIGHT,
            "dim": style.DIM,
            "bold": style.BRIGHT,
            "reset": style.RESET_ALL,
        }
        self.enabled = True

    def __call__(self, text: str, key: str) -> str:
        if not self.enabled:
            return text
        return f"{self.codes.get(key, '')}{text}{self.codes['reset']}"


class ConsoleReporter:
    """Prints a human-readable triage summary to the terminal."""

    def __init__(self, stream: TextIO | None = None, *, color: bool = True, max_rows: int = 15) -> None:
        self.stream = stream or sys.stdout
        is_tty = hasattr(self.stream, "isatty") and self.stream.isatty()
        self.color = _Palette(color and is_tty and "NO_COLOR" not in os.environ)
        self.max_rows = max_rows

    def _line(self, text: str = "") -> None:
        print(text, file=self.stream)

    def print_summary(self, report: dict[str, Any], outputs: list[Path]) -> None:
        """Print the summary block, top findings and written report paths."""
        c = self.color
        summary, parsing = report["summary"], report["parsing"]
        span = summary["time_range"]

        self._line(c(f"LogTriage-CLI v{report['tool']['version']} - automated log triage", "title"))
        self._line(c("-" * 72, "dim"))
        self._line(f"  Input       {', '.join(report['input']['files_display'])} ({report['input']['log_type']})")
        self._line(
            f"  Records     {parsing['records_read']:,} processed, {summary['events_analyzed']:,} security "
            f"events, {parsing['malformed']:,} malformed"
        )
        self._line(f"  Time range  {_format_timestamp(span['start'])} -> {_format_timestamp(span['end'])}")
        self._line(
            f"  Duration    {summary['processing_seconds']:.2f} s "
            f"({summary['records_per_second']:,} records/s)"
        )
        for error in parsing["errors"]:
            self._line(c(f"  Warning     {error}", "Medium"))
        self._line()

        level = summary["risk_level"]
        self._line(f"  Overall risk: {c(level.upper(), level)}  (score {summary['risk_score']}/100)")
        counts = [f"{c(str(n), lvl)} {lvl.lower()}" for lvl, n in summary["severity_counts"].items() if n]
        self._line(f"  Findings:     {', '.join(counts) if counts else 'none'}")
        self._line()

        findings = report["findings"]
        if findings:
            self._line(c(f"  {'SEVERITY':<9} {'RULE':<7} {'TITLE':<38} {'ENTITY':<22} {'COUNT':>6}", "bold"))
            for finding in findings[: self.max_rows]:
                severity = finding["severity"]
                self._line(
                    f"  {c(f'{severity.upper():<9}', severity)} {finding['rule_id']:<7} "
                    f"{_truncate(finding['title'], 38):<38} {_truncate(finding['entity'], 22):<22} "
                    f"{finding['count']:>6,}"
                )
            if len(findings) > self.max_rows:
                self._line(c(f"  ... and {len(findings) - self.max_rows} more (see report)", "dim"))
            self._line()

        if outputs:
            self._line("  Reports written:")
            for path in outputs:
                self._line(f"    - {path}")


def _truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 3] + "..."
