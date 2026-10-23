#!/usr/bin/env python3
"""
LogTriage-CLI - automated log triage and anomaly detection.

Command-line entry point. Parses arguments, loads configuration, streams the
input logs through the parser and detection engine, optionally enriches the
results via external APIs, and writes JSON and/or HTML reports.

Exit codes:
    0  Analysis completed (and the risk level is below ``--fail-on``).
    1  Error (invalid arguments, configuration, unreadable input, ...).
    2  Analysis completed and the risk level reached ``--fail-on``.
    130 Interrupted by the user.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from analyzer import Severity, TriageEngine
from integrations import AbuseIPDBClient, IntegrationError, WebhookNotifier, enrich_with_abuseipdb
from parsers import (
    ConfigError,
    LogParseError,
    TimeNormalizer,
    WindowsEventParser,
    create_parser,
    detect_log_type,
)
from reporter import ConsoleReporter, ReportError, build_report, to_json, write_html, write_json

__version__ = "1.0.0"

DEFAULT_CONFIG = Path(__file__).resolve().parent / "config.json"
DEFAULT_REPORT_DIR = Path("reports")
EXIT_OK, EXIT_ERROR, EXIT_RISK, EXIT_INTERRUPTED = 0, 1, 2, 130

logger = logging.getLogger("logtriage")


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
def build_arg_parser() -> argparse.ArgumentParser:
    """Create the command-line interface definition."""
    parser = argparse.ArgumentParser(
        prog="logtriage",
        description="LogTriage-CLI: fast, streaming triage of Linux and Windows security logs. "
                    "Detects brute-force attacks, off-hours activity and privilege escalation, "
                    "and produces a risk-scored JSON/HTML report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python main.py /var/log/auth.log\n"
            "  python main.py auth.log auth.log.1 auth.log.2.gz -f both -o reports/web01\n"
            "  python main.py Security.evtx -t windows -f html\n"
            "  python main.py security.csv -t windows --enrich-ips --fail-on high\n"
            "  python main.py auth.log -f json -o - | jq '.summary'\n"
        ),
    )
    parser.add_argument("log_files", nargs="+", type=Path, metavar="LOG_FILE",
                        help="one or more log files to analyze (processed in the given order)")

    group = parser.add_argument_group("input")
    group.add_argument("-t", "--log-type", choices=("auto", "linux", "windows"), default="auto",
                       help="log family (default: auto-detect from the first file)")
    group.add_argument("-i", "--input-format", choices=WindowsEventParser.FORMATS, default="auto",
                       help="Windows input format override (default: detect from extension/content)")
    group.add_argument("-c", "--config", type=Path, default=DEFAULT_CONFIG,
                       help="path to the JSON configuration file (default: %(default)s)")
    group.add_argument("--year", type=int,
                       help="year for classic syslog timestamps, which omit it (default: inferred)")
    group.add_argument("--timezone",
                       help="analysis timezone: 'local', 'UTC', '+04:00' or an IANA name "
                            "(default: from config)")

    group = parser.add_argument_group("output")
    group.add_argument("-f", "--format", choices=("json", "html", "both"), default="html",
                       help="report format (default: %(default)s)")
    group.add_argument("-o", "--output",
                       help="output file, directory or base name; use '-' to print JSON to stdout "
                            f"(default: {DEFAULT_REPORT_DIR}/logtriage_<timestamp>.<ext>)")
    group.add_argument("--fail-on", choices=("low", "medium", "high", "critical"),
                       help="exit with code 2 if the overall risk reaches this level (CI/SOAR gating)")
    group.add_argument("--no-color", action="store_true", help="disable colored console output")
    group.add_argument("-q", "--quiet", action="store_true", help="suppress the console summary")
    group.add_argument("-v", "--verbose", action="count", default=0,
                       help="increase log verbosity (-v info, -vv debug)")

    group = parser.add_argument_group("integrations (optional, require network access)")
    group.add_argument("--enrich-ips", action="store_true",
                       help="look up public source IPs on AbuseIPDB")
    group.add_argument("--abuseipdb-key", default=os.environ.get("ABUSEIPDB_API_KEY"),
                       help="AbuseIPDB API key (default: $ABUSEIPDB_API_KEY)")
    group.add_argument("--max-lookups", type=int,
                       help="maximum number of IP reputation lookups (default: from config)")
    group.add_argument("--webhook-url",
                       help="send a summary to this Slack/Discord/Teams/generic webhook")
    group.add_argument("--webhook-style", choices=WebhookNotifier.STYLES,
                       help="webhook payload style (default: from config)")

    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def configure_logging(verbosity: int) -> None:
    level = logging.WARNING if verbosity <= 0 else logging.INFO if verbosity == 1 else logging.DEBUG
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s", stream=sys.stderr)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def load_config(path: Path) -> dict[str, Any]:
    """Load and minimally validate the JSON configuration file.

    Raises:
        ConfigError: If the file is missing, unreadable or not a JSON object.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            config = json.load(handle)
    except FileNotFoundError as exc:
        raise ConfigError(f"Configuration file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in {path} (line {exc.lineno}, column {exc.colno}): {exc.msg}") from exc
    except OSError as exc:
        raise ConfigError(f"Cannot read configuration file {path}: {exc}") from exc
    if not isinstance(config, dict):
        raise ConfigError(f"Configuration root in {path} must be a JSON object.")
    return config


def validate_inputs(paths: list[Path]) -> list[Path]:
    """Ensure every input path exists and is a regular file."""
    for path in paths:
        if not path.exists():
            raise LogParseError(f"Input file not found: {path}")
        if not path.is_file():
            raise LogParseError(f"Input path is not a file: {path}")
    return paths


def resolve_outputs(output: str | None, fmt: str) -> list[tuple[str, Path]]:
    """Translate ``--output`` and ``--format`` into (format, path) pairs.

    ``output`` may be a file path, an existing directory (or one ending in a
    path separator), or a base name used for both formats.
    """
    formats = ["json", "html"] if fmt == "both" else [fmt]
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_name = f"logtriage_{stamp}"

    if output is None:
        base = DEFAULT_REPORT_DIR / default_name
    elif output.endswith(("/", "\\")) or Path(output).is_dir():
        base = Path(output) / default_name
    else:
        base = Path(output)
        if len(formats) == 1 and base.suffix.lower() in (".json", ".html", ".htm"):
            return [(formats[0], base)]
        if base.suffix.lower() in (".json", ".html", ".htm"):
            base = base.with_suffix("")
    return [(name, base.with_name(f"{base.name}.{name}")) for name in formats]


def run_integrations(args: argparse.Namespace, config: dict[str, Any], engine: TriageEngine,
                     result: Any) -> dict[str, Any]:
    """Run optional enrichment integrations and return their summaries."""
    summaries: dict[str, Any] = {}
    if not args.enrich_ips:
        return summaries
    settings = config.get("integrations", {}).get("abuseipdb", {})
    if not args.abuseipdb_key:
        logger.warning("--enrich-ips requires an API key (--abuseipdb-key or $ABUSEIPDB_API_KEY); skipping.")
        return summaries
    try:
        client = AbuseIPDBClient(
            args.abuseipdb_key,
            max_age_days=int(settings.get("max_age_in_days", 90)),
            timeout=float(settings.get("timeout_seconds", 10)),
        )
        summaries["abuseipdb"] = enrich_with_abuseipdb(
            result, engine, client,
            max_lookups=args.max_lookups if args.max_lookups is not None else int(settings.get("max_lookups", 25)),
            confidence_threshold=int(settings.get("malicious_confidence_threshold", 75)),
        )
    except IntegrationError as exc:
        logger.warning("IP enrichment skipped: %s", exc)
    return summaries


def send_webhook(args: argparse.Namespace, config: dict[str, Any], report: dict[str, Any]) -> None:
    """Deliver the summary to a webhook if requested and the risk is high enough."""
    if not args.webhook_url:
        return
    settings = config.get("integrations", {}).get("webhook", {})
    minimum = Severity.parse(settings.get("min_risk_level", "low"))
    if Severity.parse(report["summary"]["risk_level"]) < minimum:
        logger.info("Risk below webhook threshold (%s); notification not sent.", minimum.label)
        return
    try:
        notifier = WebhookNotifier(
            args.webhook_url,
            style=args.webhook_style or settings.get("payload_style", "slack"),
            timeout=float(settings.get("timeout_seconds", 10)),
        )
        notifier.send(report)
        logger.info("Webhook notification delivered.")
    except IntegrationError as exc:
        logger.warning("%s", exc)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def run(args: argparse.Namespace) -> int:
    """Execute a triage run for parsed arguments and return the exit code."""
    config = load_config(args.config)
    paths = validate_inputs(args.log_files)
    log_type = detect_log_type(paths[0]) if args.log_type == "auto" else args.log_type
    timezone = args.timezone or config.get("general", {}).get("timezone", "local")
    logger.info("Analyzing %d file(s) as %s logs", len(paths), log_type)

    normalizer = TimeNormalizer(timezone)
    log_parser = create_parser(log_type, config, normalizer, input_format=args.input_format, year=args.year)
    engine = TriageEngine(config)

    started = time.perf_counter()
    result = engine.analyze(log_parser.parse_files(paths))
    elapsed = time.perf_counter() - started

    stats = log_parser.stats
    if stats.errors and stats.records_read == 0:
        raise LogParseError("No records could be read: " + "; ".join(stats.errors))
    if stats.records_read and stats.malformed == stats.records_read:
        logger.warning("No record matched the expected %s format - is --log-type correct?", log_type)

    integrations = run_integrations(args, config, engine, result)
    input_format = args.input_format
    if log_type == "windows" and input_format == "auto":
        input_format = ", ".join(sorted({log_parser.resolve_format(p) for p in paths}))
    report = build_report(
        result, stats, tool_version=__version__, log_type=log_type, input_format=input_format,
        timezone=normalizer.spec, elapsed_seconds=elapsed, integrations=integrations,
    )

    written: list[Path] = []
    to_stdout = args.output == "-"
    if to_stdout:
        if args.format != "json":
            raise ConfigError("'-o -' (stdout) is only supported with '-f json'.")
        sys.stdout.write(to_json(report) + "\n")
    else:
        for fmt, path in resolve_outputs(args.output, args.format):
            written.append(write_json(report, path) if fmt == "json" else write_html(report, path))

    if not args.quiet:
        console = ConsoleReporter(sys.stderr if to_stdout else sys.stdout, color=not args.no_color)
        console.print_summary(report, written)

    send_webhook(args, config, report)

    if args.fail_on and result.risk.level >= Severity.parse(args.fail_on):
        return EXIT_RISK
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    args = build_arg_parser().parse_args(argv)
    configure_logging(args.verbose)
    try:
        return run(args)
    except (ConfigError, LogParseError, ReportError) as exc:
        logger.error("%s", exc)
        return EXIT_ERROR
    except KeyboardInterrupt:
        logger.error("Interrupted by user.")
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    sys.exit(main())
