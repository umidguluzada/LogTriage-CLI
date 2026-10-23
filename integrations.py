"""
Optional third-party integrations for LogTriage-CLI.

* :class:`AbuseIPDBClient` / :func:`enrich_with_abuseipdb` - IP reputation
  enrichment of findings via the AbuseIPDB v2 API.
* :class:`WebhookNotifier` - posts a triage summary to Slack, Discord, Microsoft
  Teams (workflow webhooks) or any generic JSON webhook.

Network access only happens when an integration is explicitly enabled on the
command line. ``requests`` is imported lazily so the core tool works without it.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any
from urllib.parse import urlparse

from analyzer import RULES, AnalysisResult, Finding, Severity, TriageEngine

logger = logging.getLogger(__name__)

USER_AGENT = "LogTriage-CLI"


class IntegrationError(Exception):
    """Raised when an integration is misconfigured or cannot be used."""


class RateLimitError(IntegrationError):
    """Raised when a provider reports that the request quota is exhausted."""


def _requests() -> Any:
    try:
        import requests
    except ImportError as exc:
        raise IntegrationError("The 'requests' package is required for API integrations "
                               "(pip install requests).") from exc
    return requests


def is_public_ip(value: str | None) -> bool:
    """Return ``True`` for globally routable IPv4/IPv6 addresses."""
    if not value:
        return False
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# AbuseIPDB
# --------------------------------------------------------------------------- #
class AbuseIPDBClient:
    """Minimal AbuseIPDB v2 ``/check`` client with an in-memory cache."""

    ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str, *, max_age_days: int = 90, timeout: float = 10.0) -> None:
        if not api_key:
            raise IntegrationError("An AbuseIPDB API key is required.")
        requests = _requests()
        self._session = requests.Session()
        self._session.headers.update({"Key": api_key, "Accept": "application/json", "User-Agent": USER_AGENT})
        self._request_error = requests.RequestException
        self.max_age_days = max_age_days
        self.timeout = timeout
        self._cache: dict[str, dict[str, Any]] = {}

    def check(self, ip: str) -> dict[str, Any]:
        """Return normalized reputation data for ``ip``.

        Raises:
            RateLimitError: If the daily quota is exhausted (HTTP 429).
            IntegrationError: On authentication failures or unexpected responses.
        """
        if ip in self._cache:
            return self._cache[ip]
        try:
            response = self._session.get(
                self.ENDPOINT,
                params={"ipAddress": ip, "maxAgeInDays": self.max_age_days},
                timeout=self.timeout,
            )
        except self._request_error as exc:
            raise IntegrationError(f"AbuseIPDB request for {ip} failed: {exc}") from exc

        if response.status_code == 429:
            raise RateLimitError("AbuseIPDB rate limit reached.")
        if response.status_code in (401, 403):
            raise IntegrationError("AbuseIPDB rejected the API key (HTTP %d)." % response.status_code)
        if response.status_code != 200:
            raise IntegrationError(f"AbuseIPDB returned HTTP {response.status_code} for {ip}.")
        try:
            data = response.json().get("data", {})
        except ValueError as exc:
            raise IntegrationError("AbuseIPDB returned an invalid JSON response.") from exc

        intel = {
            "provider": "AbuseIPDB",
            "ip": data.get("ipAddress", ip),
            "abuse_confidence": int(data.get("abuseConfidenceScore") or 0),
            "total_reports": int(data.get("totalReports") or 0),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "usage_type": data.get("usageType"),
            "is_tor": bool(data.get("isTor")),
            "last_reported_at": data.get("lastReportedAt"),
        }
        self._cache[ip] = intel
        return intel


def _candidate_ips(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Map public source IPs to related findings, highest-scoring first."""
    candidates: dict[str, list[Finding]] = {}
    for finding in sorted(findings, key=lambda f: f.score, reverse=True):
        addresses = set(finding.samples.get("source_ips", []))
        if finding.entity_type == "ip":
            addresses.add(finding.entity)
        for address in sorted(addresses):
            if is_public_ip(address):
                candidates.setdefault(address, []).append(finding)
    return candidates


def enrich_with_abuseipdb(
    result: AnalysisResult,
    engine: TriageEngine,
    client: AbuseIPDBClient,
    *,
    max_lookups: int = 25,
    confidence_threshold: int = 75,
) -> dict[str, Any]:
    """Attach reputation data to findings and add ``TI-001`` findings for bad IPs.

    Lookups are prioritized by finding score and limited to ``max_lookups`` to
    respect API quotas. Failures are logged and never abort the triage run.

    Returns:
        A summary dictionary included in the report metadata.
    """
    candidates = _candidate_ips(result.findings)
    summary: dict[str, Any] = {"provider": "AbuseIPDB", "candidates": len(candidates),
                               "lookups": 0, "malicious": [], "errors": []}
    compromise_rules = {"BF-003", "PE-007"}

    for address, related in candidates.items():
        if summary["lookups"] >= max_lookups:
            break
        try:
            intel = client.check(address)
        except RateLimitError as exc:
            logger.warning("%s Remaining lookups skipped.", exc)
            summary["errors"].append(str(exc))
            break
        except IntegrationError as exc:
            logger.warning("%s", exc)
            summary["errors"].append(str(exc))
            if "API key" in str(exc):
                break
            continue
        summary["lookups"] += 1

        for finding in related:
            finding.details.setdefault("threat_intel", {})[address] = intel

        if intel["abuse_confidence"] < confidence_threshold:
            continue
        compromised = any(f.rule_id in compromise_rules for f in related)
        result.findings.append(Finding(
            rule=RULES["TI-001"],
            entity=address,
            entity_type="ip",
            host=None,
            severity=Severity.CRITICAL if compromised else Severity.HIGH,
            first_seen=min(f.first_seen for f in related),
            last_seen=max(f.last_seen for f in related),
            count=1,
            summary=(
                f"{address} has an AbuseIPDB confidence score of {intel['abuse_confidence']}% "
                f"({intel['total_reports']} reports, {intel.get('country') or 'unknown country'}, "
                f"{intel.get('isp') or 'unknown ISP'}) and appears in {len(related)} finding(s)."
            ),
            evidence=[f"Related finding {f.rule_id}: {f.describe()}" for f in related[:5]],
            details={"threat_intel": intel, "related_rules": sorted({f.rule_id for f in related})},
        ))
        summary["malicious"].append(address)

    if summary["lookups"]:
        engine.rescore(result)
    return summary


# --------------------------------------------------------------------------- #
# Webhooks
# --------------------------------------------------------------------------- #
class WebhookNotifier:
    """Sends a concise triage summary to a chat or automation webhook."""

    STYLES = ("slack", "discord", "teams", "generic")

    def __init__(self, url: str, *, style: str = "slack", timeout: float = 10.0) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in ("https", "http") or not parsed.netloc:
            raise IntegrationError(f"Invalid webhook URL: {url!r}")
        if parsed.scheme == "http":
            logger.warning("Webhook URL uses plain HTTP; the report summary will be sent unencrypted.")
        if style not in self.STYLES:
            raise IntegrationError(f"Unknown webhook payload style {style!r}; choose from {self.STYLES}.")
        self.url = url
        self.style = style
        self.timeout = timeout

    @staticmethod
    def build_message(report: dict[str, Any], max_findings: int = 5) -> str:
        """Render a plain-text summary of ``report``."""
        summary = report["summary"]
        sources = ", ".join(report["input"]["files_display"])
        counts = ", ".join(f"{count} {level.lower()}" for level, count in summary["severity_counts"].items() if count)
        lines = [
            f"LogTriage-CLI: {summary['risk_level'].upper()} risk "
            f"(score {summary['risk_score']}/100) for {sources}",
            f"{summary['findings_total']} finding(s){f' ({counts})' if counts else ''} "
            f"from {summary['events_analyzed']:,} security events.",
        ]
        for finding in report["findings"][:max_findings]:
            lines.append(f"- [{finding['severity'].upper()}] {finding['title']} - {finding['entity']}")
        return "\n".join(lines)

    def build_payload(self, report: dict[str, Any]) -> dict[str, Any]:
        text = self.build_message(report)
        if self.style == "discord":
            return {"content": text[:2000], "username": USER_AGENT}
        if self.style == "generic":
            return {"text": text, "summary": report["summary"], "findings": report["findings"][:20]}
        return {"text": text}

    def send(self, report: dict[str, Any]) -> None:
        """POST the summary to the webhook.

        Raises:
            IntegrationError: If the request fails or the endpoint rejects it.
        """
        requests = _requests()
        try:
            response = requests.post(
                self.url, json=self.build_payload(report), timeout=self.timeout,
                headers={"User-Agent": USER_AGENT},
            )
        except requests.RequestException as exc:
            raise IntegrationError(f"Webhook delivery failed: {exc}") from exc
        if response.status_code >= 300:
            raise IntegrationError(f"Webhook endpoint returned HTTP {response.status_code}.")
