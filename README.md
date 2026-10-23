# LogTriage-CLI

**Fast, streaming triage of Linux and Windows security logs.** LogTriage-CLI reads
`auth.log`/`syslog` files and Windows Event Logs, detects brute-force attacks,
off-hours activity and privilege escalation, scores the overall risk with weighted
heuristics, and produces a clean JSON or HTML report in seconds.

```
LogTriage-CLI v1.0.0 - automated log triage
------------------------------------------------------------------------
  Input       auth.log (linux)
  Records     1,763 processed, 206 security events, 0 malformed
  Time range  2026-10-12 11:24:53 -> 2026-10-16 16:45:43

  Overall risk: CRITICAL  (score 100.0/100)
  Findings:     3 critical, 8 high, 3 medium, 3 low

  SEVERITY  RULE    TITLE                                  ENTITY                  COUNT
  CRITICAL  PE-009  Root-equivalent account created        sysbackup                   1
  CRITICAL  BF-003  Successful login after brute-force     203.0.113.45                1
  CRITICAL  BF-001  Brute-force login attempts             203.0.113.45               78
  HIGH      BF-002  Password spraying                      198.51.100.23              12
  HIGH      PE-005  Account added to privileged group      deploy                      1
  ...
```

---

## Features

- **Streaming, low-memory parsing.** Every parser is a generator. Files are read line by line,
  row by row or record by record, so memory stays flat (about 70 MB) whether the input is 1 MB or 10 GB.
- **Linux:** `auth.log`, `secure`, `syslog`, `messages`. Supports classic BSD syslog and RFC 3339
  timestamps, gzip-compressed rotations (`auth.log.2.gz`), rsyslog `message repeated N times`
  compression and year inference across December/January rollover.
- **Windows:** native `.evtx`, XML (Event Viewer export or `wevtutil /f:xml`), CSV (Event Viewer or
  `Get-WinEvent | Export-Csv`), and `wevtutil /f:text`. UTF-16 PowerShell exports are detected
  automatically, and local group SIDs are resolved to account names when possible.
- **Detection engine:**
  - Brute-force bursts (sliding window), password spraying, and **successful login after brute-force**.
  - Off-hours activity: logins, process execution and privileged actions outside business hours,
    business days and holidays (overnight shifts supported).
  - Privilege escalation: sudo/pkexec/su usage, suspicious privileged commands (root shells,
    SUID changes, reverse shells, `curl | bash`, log wiping, `net user /add`, `vssadmin delete shadows`
    and more), privileged group changes, new accounts, UID-0 backdoors, direct root/Administrator
    logins, special privileges (4672) and audit-log clearing (1102).
  - Order-independent: reverse-chronological exports give identical results.
- **Weighted risk scoring** into **Low / Medium / High / Critical**, with per-rule caps,
  diminishing returns for volume, and per-entity (user / IP) risk ranking.
- **MITRE ATT&CK mapping** for every rule.
- **Reports:** structured JSON for SIEM/SOAR pipelines and a modern, self-contained HTML report
  (no JavaScript, print-friendly, autoescaped against log-injection XSS).
- **Optional integrations:** AbuseIPDB IP reputation enrichment and Slack / Discord / Teams /
  generic webhook notifications.
- **CI/automation friendly:** `--fail-on high` exit codes, JSON to stdout, quiet mode.

## Project structure

```
log-triage-cli/
├── main.py                 # CLI entry point (argparse), orchestration, exit codes
├── parsers.py              # Streaming Linux / Windows parsers and normalized LogEvent model
├── analyzer.py             # Detectors, finding aggregation, risk scoring
├── reporter.py             # JSON / HTML report generation and console summary
├── integrations.py         # Optional AbuseIPDB enrichment and webhook notifications
├── config.json             # Thresholds, time windows, regex patterns, scoring weights
├── templates/
│   └── report.html.j2      # Jinja2 template for the HTML report
├── tools/
│   └── generate_samples.py # Synthetic log generator for demos and benchmarks
├── samples/                # Small generated sample logs (Linux + Windows)
├── tests/                  # pytest suite
├── requirements.txt
└── requirements-dev.txt
```

**Data flow:** `parsers` → stream of `LogEvent` → `analyzer.TriageEngine` (single pass) →
`AnalysisResult` → optional `integrations` enrichment → `reporter`.

## Installation

Requires **Python 3.10+**.

```bash
git clone https://github.com/<your-account>/log-triage-cli.git
cd log-triage-cli
python -m venv .venv

# Linux / macOS
source .venv/bin/activate
# Windows (PowerShell)
.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

| Package | Purpose | Required? |
|---|---|---|
| `Jinja2` | HTML reports | For `-f html` |
| `colorama` | Colored console output (Windows-safe) | Optional |
| `python-evtx` | Native `.evtx` parsing | For `.evtx` input |
| `requests` | AbuseIPDB and webhooks | For integrations |

> **Faster EVTX parsing:** the Rust-based [`evtx`](https://pypi.org/project/evtx/) package is used
> automatically when installed and is much faster than `python-evtx`. Install **one or the other**:
> on case-insensitive filesystems (Windows, macOS) `evtx` and `Evtx` overwrite each other.
> For very large Windows logs, exporting to XML (see below) is also a fast option.

## Quick start

```bash
# Generate realistic sample logs with embedded attack scenarios
python tools/generate_samples.py

# Analyze them
python main.py samples/auth.log
python main.py samples/windows_security.xml -f both
```

Reports are written to `reports/logtriage_<timestamp>.html` by default.

## CLI usage

```
python main.py LOG_FILE [LOG_FILE ...] [options]
```

| Option | Description |
|---|---|
| `-t, --log-type {auto,linux,windows}` | Log family (default: auto-detect) |
| `-i, --input-format {auto,evtx,xml,csv,text}` | Windows format override (default: by extension/content) |
| `-c, --config PATH` | Configuration file (default: `config.json` next to `main.py`) |
| `--year YEAR` | Year for classic syslog timestamps (default: inferred) |
| `--timezone TZ` | `local`, `UTC`, `+04:00` or IANA name (default: from config) |
| `-f, --format {json,html,both}` | Report format (default: `html`) |
| `-o, --output PATH` | File, directory or base name; `-` prints JSON to stdout |
| `--fail-on {low,medium,high,critical}` | Exit with code `2` if overall risk reaches this level |
| `--no-color`, `-q/--quiet`, `-v/-vv` | Console behavior and log verbosity |
| `--enrich-ips` | Enable AbuseIPDB reputation lookups |
| `--abuseipdb-key KEY` | API key (default: `$ABUSEIPDB_API_KEY`) |
| `--max-lookups N` | Limit reputation lookups (default: 25) |
| `--webhook-url URL` | Send a summary to a webhook |
| `--webhook-style {slack,discord,teams,generic}` | Webhook payload format |

### Examples

```bash
# Analyze the live auth log (Linux)
sudo python main.py /var/log/auth.log

# Several rotations at once (gzip supported), both report formats, custom base name
python main.py /var/log/auth.log /var/log/auth.log.1 /var/log/auth.log.2.gz -f both -o reports/web01

# RHEL / CentOS
python main.py /var/log/secure -t linux --year 2026

# Windows Security log (native EVTX)
python main.py C:\Windows\System32\winevt\Logs\Security.evtx -t windows

# PowerShell CSV export, analyzed in UTC
python main.py security.csv -t windows --timezone UTC

# Pipe JSON into jq
python main.py auth.log -f json -o - -q | jq '.findings[] | select(.severity == "Critical")'

# CI / SOAR gating: non-zero exit code when risk is High or Critical
python main.py auth.log -f json -o reports/ci.json --fail-on high -q || echo "Escalate!"

# Threat-intel enrichment and Slack notification
export ABUSEIPDB_API_KEY=...            # PowerShell: $env:ABUSEIPDB_API_KEY = "..."
python main.py auth.log --enrich-ips --webhook-url https://hooks.slack.com/services/XXX
```

### Exporting Windows logs

Reading the live Security log requires an elevated prompt.

```powershell
# Native EVTX copy
wevtutil epl Security C:\triage\Security.evtx

# XML (fast to parse, no extra dependency)
wevtutil qe Security /f:xml > C:\triage\security.xml

# Text
wevtutil qe Security /f:text > C:\triage\security.txt

# CSV with PowerShell (last 7 days)
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddDays(-7)} |
  Select-Object TimeCreated, Id, ProviderName, MachineName, Message |
  Export-Csv C:\triage\security.csv -NoTypeInformation
```

## Detection rules

| ID | Detection | Default severity | MITRE ATT&CK |
|---|---|---|---|
| BF-001 | Brute-force login attempts (N failures within window) | High / Critical | T1110.001 |
| BF-002 | Password spraying (one source, many accounts) | High / Critical | T1110.003 |
| BF-003 | Successful login after brute-force | Critical | T1110, T1078 |
| OH-001 | Off-hours login / process execution | Medium | T1078 |
| OH-002 | Off-hours privileged activity | High | T1078 |
| PE-001 | Privileged command execution (sudo/pkexec) | Low | T1548.003 |
| PE-002 | Suspicious privileged command | High | T1548, T1059 |
| PE-003 | Switch to privileged account (su) | Medium | T1548 |
| PE-004 | Failed privilege escalation (sudo/su/pkexec denied) | Medium / High | T1548.003 |
| PE-005 | Account added to privileged group | High | T1098 |
| PE-006 | New user account created | Medium | T1136.001 |
| PE-007 | Direct login to root / Administrator | Medium / High | T1078.003 |
| PE-008 | Special privileges assigned to logon (4672) | Low | T1078 |
| PE-009 | Root-equivalent account created (UID 0) | Critical | T1136.001 |
| DE-001 | Security audit log cleared (1102 / 104) | Critical | T1070.001 |
| TI-001 | Source IP with malicious reputation (AbuseIPDB) | High / Critical | n/a |

Windows event IDs used: 4624, 4625, 4771, 4672, 4720, 4728, 4732, 4756, 4688, 1102, 104.
Process-creation detections (4688) need *Audit Process Creation*, plus command-line auditing for
`CommandLine` matching.

## Risk scoring

Each finding scores:

```math
\text{score} = \text{weight}_{\text{rule}} \times \text{multiplier}_{\text{severity}} \times \left(1 + \min\left(1, \frac{\log_{10}(\text{count})}{3}\right)\right)
```

- **Weights** per rule and **severity multipliers** (Low 0.5, Medium 1.0, High 1.5, Critical 2.0)
  are set in `config.json`.
- The volume factor rewards repetition with diminishing returns: 1x for a single event,
  2x at 1,000 events.
- Points are **capped per rule** (`max_points_per_rule`, default 40), so one noisy detector cannot
  dominate. The total is capped at 100.
- Levels: **Low** < 20 ≤ **Medium** < 45 ≤ **High** < 75 ≤ **Critical**.
- Any critical finding raises the overall level to at least `critical_finding_minimum_level`
  (default High).

The report also ranks the **riskiest entities** (users and IPs) by their combined finding scores.

## Configuration

All tunables live in `config.json`:

| Section | Contents |
|---|---|
| `general` | Analysis timezone, evidence lines kept per finding |
| `detection.brute_force` | `failure_threshold`, `time_window_seconds`, `critical_threshold`, `password_spray_min_users`, `success_correlation_window_seconds` |
| `detection.off_hours` | Business hours and days, holidays, monitored categories, Windows logon types |
| `detection.privilege_escalation` | Privileged accounts and groups, suspicious command regexes |
| `detection.ignored_accounts` / `ignored_source_ips` | Noise suppression (service accounts, machine accounts, scanners) |
| `scoring` | Rule weights, severity multipliers, caps, level thresholds |
| `linux.rules` | Ordered regex rules: `id`, `category`, `programs`, `pattern`, optional `severity` |
| `windows` | Event ID to category mapping, CSV/text timestamp formats |
| `integrations` | AbuseIPDB thresholds and quotas, webhook style and minimum risk level |

**Adding a Linux rule.** Rules are indexed by program name, so each line is only tested against
rules for its daemon. Named groups `user`, `target_user`, `ip`, `command` and `group` map to event
fields, and any other named group is kept as an extra field:

```json
{
  "id": "vsftpd_failed_login",
  "category": "auth_failure",
  "programs": ["vsftpd"],
  "pattern": "\\[(?P<user>[^\\]]+)\\] FAIL LOGIN: Client \"(?P<ip>[^\"]+)\""
}
```

Valid categories: `auth_failure`, `auth_success`, `priv_command`, `priv_switch`, `priv_failure`,
`special_privileges`, `group_change`, `account_created`, `process_exec`, `log_cleared`.

## Output

**JSON** (`report_version` 1.0) top-level keys: `tool`, `generated_at`, `input`, `summary`
(risk score and level, counts, time range, throughput), `risk` (breakdown and entities), `findings`
(rule, severity, score, entity, timestamps, MITRE, details, evidence), `statistics` (categories,
hourly activity, top sources and accounts), `parsing`, `context`, `integrations`.

**HTML** is a single self-contained file containing:

- a risk gauge
- summary cards
- a severity distribution bar
- expandable finding cards with evidence
- tables of the riskiest entities and the score breakdown
- an hourly activity chart with off-hours highlighted
- category and top-source tables
- processing details

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Analysis completed (risk below `--fail-on`, if given) |
| 1 | Error (bad arguments, configuration, unreadable input, report write failure) |
| 2 | Analysis completed and risk reached the `--fail-on` level |
| 130 | Interrupted (Ctrl+C) |

## Performance

Measured on a laptop with Python 3.14, using `tools/generate_samples.py --scale 2000`:

| Input | Size | Throughput | Peak memory |
|---|---|---|---|
| Linux `auth.log` (446k lines) | 43 MB | ~105,000 lines/s | ~70 MB |
| Windows XML (300k events) | 167 MB | ~22,000 events/s | ~70 MB |
| Windows `.evtx` via `python-evtx` | n/a | ~470 records/s | flat |

Why it's fast:

- Program-indexed rule lookup.
- Early discard of irrelevant records before any field extraction.
- Per-record C-accelerated XML parsing.
- Failure timestamps stored in compact `array('d')` buffers (8 bytes per attempt).
- Aggregated findings instead of retained events.

## Testing

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

## Security and privacy

- No network access unless `--enrich-ips` or `--webhook-url` is given. Private, loopback and
  documentation-range IPs are never sent to AbuseIPDB.
- Log content is attacker-controlled. HTML output is autoescaped and contains no JavaScript.
- Reports contain usernames, IPs and raw log lines. Handle them as sensitive data.

## Limitations

- Message-text parsing for Windows CSV/text exports assumes **English** event messages. XML and
  EVTX inputs are language-independent.
- Classic syslog has no year. It is inferred automatically; use `--year` for archived logs.
- Detections are heuristics that support analysts. Validate them before acting.

## Contributing

Issues and pull requests are welcome. Please add tests for new rules or parsers and keep
`python -m pytest` green.

## License

[MIT](LICENSE)
