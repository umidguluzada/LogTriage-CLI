"""End-to-end tests for the command-line interface and reporters."""

from __future__ import annotations

import json
from pathlib import Path

from main import EXIT_ERROR, EXIT_OK, EXIT_RISK, main, resolve_outputs

ATTACK_LOG = "".join(
    f"Oct 21 02:13:{i:02d} web01 sshd[1]: Failed password for root from 203.0.113.45 port 4000 ssh2\n"
    for i in range(20)
) + (
    "Oct 21 02:14:00 web01 sshd[2]: Accepted password for root from 203.0.113.45 port 4001 ssh2\n"
    "Oct 21 02:15:00 web01 sudo: <script>alert(1)</script> : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/sh\n"
)


def test_cli_writes_json_and_html(tmp_path: Path):
    log = tmp_path / "auth.log"
    log.write_text(ATTACK_LOG, encoding="utf-8")
    base = tmp_path / "out" / "report"

    code = main([str(log), "-t", "linux", "--year", "2026", "-f", "both", "-o", str(base),
                 "--fail-on", "high", "-q"])
    assert code == EXIT_RISK

    report = json.loads(base.with_name("report.json").read_text(encoding="utf-8"))
    assert report["summary"]["risk_level"] == "Critical"
    assert {"BF-001", "BF-003", "PE-007", "PE-002"} <= {f["rule_id"] for f in report["findings"]}

    html = base.with_name("report.html").read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html  # attacker-controlled content is escaped
    assert "&lt;script&gt;" in html


def test_cli_reports_missing_file(tmp_path: Path):
    assert main([str(tmp_path / "missing.log"), "-q"]) == EXIT_ERROR


def test_cli_json_to_stdout(tmp_path: Path, capsys):
    log = tmp_path / "auth.log"
    log.write_text("Oct 21 12:00:00 web01 sshd[1]: Accepted publickey for alice from 10.0.0.1 port 1 ssh2\n",
                   encoding="utf-8")
    assert main([str(log), "--year", "2026", "-f", "json", "-o", "-", "-q"]) == EXIT_OK
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["events_analyzed"] == 1


def test_resolve_outputs(tmp_path: Path):
    assert resolve_outputs(str(tmp_path / "r.json"), "json") == [("json", tmp_path / "r.json")]
    assert resolve_outputs(str(tmp_path / "r.html"), "both") == [
        ("json", tmp_path / "r.json"), ("html", tmp_path / "r.html")]
    directory_outputs = resolve_outputs(str(tmp_path), "html")
    assert directory_outputs[0][1].parent == tmp_path
