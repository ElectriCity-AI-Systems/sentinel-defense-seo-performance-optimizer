#!/usr/bin/env python3
"""Defensive Cloudflare daily-report evaluator for Electri_C_ity Studios.

The bot is intentionally local and observe-first:
- reads an existing Markdown report
- evaluates known watchpoints against fixed thresholds
- writes Markdown and JSON recommendations
- never talks to Cloudflare or any external host
- never applies production changes
"""

from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")
DEFAULT_REPORT = PROJECT_DIR / "cloudflare-monitor/latest/cloudflare-daily-monitor.md"
DEFAULT_OUT_MD = PROJECT_DIR / "reports/latest/sentinel-defense-report.md"
DEFAULT_OUT_JSON = PROJECT_DIR / "reports/latest/sentinel-defense-report.json"
DEFAULT_HISTORY_PATH = PROJECT_DIR / "reports/history/sentinel-defense-history.jsonl"

STATUS_OK = "OK"
STATUS_WARNING = "WARNING"
STATUS_CRITICAL = "CRITICAL"
STATUS_UNKNOWN = "UNKNOWN"
STATUS_WATCH = "WATCH"

CORRELATION_NORMAL = "NORMAL"
CORRELATION_WATCH = "WATCH"
CORRELATION_ACTION_CANDIDATE = "ACTION_CANDIDATE"

ALLOWED_ACTIONS: Dict[str, Dict[str, str]] = {
    "challenge_sitelockspider_root": {
        "name": "challenge_sitelockspider_root",
        "cloudflare_action": "managed_challenge",
        "expression": '(http.user_agent contains "SiteLockSpider") and (http.request.uri.path eq "/")',
        "description": (
            "Temporary defensive managed challenge for SiteLockSpider on homepage when "
            "correlated with 5xx/504 spikes."
        ),
    },
    "challenge_sitelockspider_wp_login": {
        "name": "challenge_sitelockspider_wp_login",
        "cloudflare_action": "managed_challenge",
        "expression": '(http.user_agent contains "SiteLockSpider") and (http.request.uri.path eq "/wp-login.php")',
        "description": (
            "Temporary defensive managed challenge for SiteLockSpider on wp-login.php "
            "when correlated with 503 login spikes."
        ),
    },
    "challenge_xmlrpc_abuse": {
        "name": "challenge_xmlrpc_abuse",
        "cloudflare_action": "managed_challenge",
        "expression": '(http.request.uri.path eq "/xmlrpc.php")',
        "description": "SentinelDefense apply-safe temporary managed challenge for xmlrpc.php abuse.",
    },
    "challenge_fake_secret_scans": {
        "name": "challenge_fake_secret_scans",
        "cloudflare_action": "managed_challenge",
        "expression": (
            '(http.request.uri.path contains ".env" or '
            'http.request.uri.path contains "phpinfo" or '
            'http.request.uri.path contains "secrets" or '
            'http.request.uri.path contains ".aws" or '
            'http.request.uri.path contains "actuator" or '
            'http.request.uri.path contains "dockerfile" or '
            'http.request.uri.path contains "gitlab" or '
            'http.request.uri.path contains "__nextjs_action" or '
            'http.request.uri.path contains "__rsc" or '
            'http.request.uri.path contains "_next")'
        ),
        "description": (
            "SentinelDefense apply-safe temporary managed challenge for fake secret "
            "and framework scans."
        ),
    },
    "challenge_sitelockspider_oembed": {
        "name": "challenge_sitelockspider_oembed",
        "cloudflare_action": "managed_challenge",
        "expression": (
            '(http.user_agent contains "SiteLockSpider") and '
            '(http.request.uri.path eq "/wp-json/oembed/1.0/embed")'
        ),
        "description": (
            "SentinelDefense apply-safe temporary managed challenge for SiteLockSpider "
            "on oEmbed when correlated with 503/404 pressure."
        ),
    },
}

WP_LOGIN_ACTION_REASON = "SiteLockSpider is correlated with critical /wp-login.php 503 responses."
ROOT_ACTION_REASON = "SiteLockSpider is correlated with critical homepage 504 responses."
CONSOLIDATED_ACTION_ID = "sentinel_combined_wordpress_scanner_challenge"
APEX_HOST = "electri-c-ity-studios-24-7.com"
WWW_HOST = "www.electri-c-ity-studios-24-7.com"
LEGACY_CONSOLIDATED_EXPRESSION = (
    '((http.user_agent contains "SiteLockSpider" and http.request.uri.path eq "/wp-login.php") or '
    '(http.user_agent contains "SiteLockSpider" and http.request.uri.path eq "/wp-json/oembed/1.0/embed") or '
    '(http.request.uri.path eq "/xmlrpc.php") or '
    '(http.request.uri.path contains ".env") or '
    '(http.request.uri.path contains "phpinfo") or '
    '(http.request.uri.path contains "secrets"))'
)
HOST_BOUND_FRAMEWORK_SCANNER_EXPRESSION = (
    '((http.host eq "electri-c-ity-studios-24-7.com" or '
    'http.host eq "www.electri-c-ity-studios-24-7.com") and '
    '(http.request.uri.path contains "_next" or '
    'http.request.uri.path contains "__rsc" or '
    'http.request.uri.path contains "__nextjs_action" or '
    'http.request.uri.path contains "api/auth"))'
)
CONSOLIDATED_EXPRESSION = (
    "("
    f"{LEGACY_CONSOLIDATED_EXPRESSION} or "
    f"{HOST_BOUND_FRAMEWORK_SCANNER_EXPRESSION}"
    ")"
)
ALLOWED_ACTIONS[CONSOLIDATED_ACTION_ID] = {
    "name": CONSOLIDATED_ACTION_ID,
    "cloudflare_action": "managed_challenge",
    "expression": CONSOLIDATED_EXPRESSION,
    "description": (
        "SentinelDefense consolidated managed challenge for WordPress scanner pressure: "
        "SiteLockSpider login/oEmbed, xmlrpc, fake secret scans, and apex/www-only "
        "fake framework scanner paths."
    ),
}
LEGACY_FAKE_SECRET_EXPRESSION = (
    '(http.request.uri.path contains ".env") or '
    '(http.request.uri.path contains "phpinfo") or '
    '(http.request.uri.path contains "secrets")'
)
CONSOLIDATABLE_SENTINEL_EXPRESSIONS = {
    '(http.user_agent contains "SiteLockSpider") and (http.request.uri.path eq "/wp-login.php")',
    '(http.request.uri.path eq "/xmlrpc.php")',
    '(http.user_agent contains "SiteLockSpider") and (http.request.uri.path eq "/wp-json/oembed/1.0/embed")',
    LEGACY_FAKE_SECRET_EXPRESSION,
    ALLOWED_ACTIONS["challenge_fake_secret_scans"]["expression"],
    LEGACY_CONSOLIDATED_EXPRESSION,
}


@dataclass(frozen=True)
class MetricRule:
    key: str
    label: str
    aliases: Tuple[str, ...]
    warning: int
    critical: int
    recommendation: str


@dataclass
class MetricResult:
    key: str
    label: str
    value: Optional[int]
    status: str
    warning: int
    critical: int
    recommendation: str
    source_label: Optional[str] = None
    note: str = ""


@dataclass
class CorrelationFinding:
    signal: str
    value: str
    interpretation: str
    recommended_next_action: str


@dataclass
class CorrelationResult:
    correlation_status: str
    operational_interpretation: str
    findings: List[CorrelationFinding]


@dataclass
class CorrelationV2Finding:
    signal_id: str
    status: str
    count: int
    paths: List[str]
    user_agents: List[str]
    countries: List[str]
    explanation: str
    recommendation: str


@dataclass
class SafetyCheck:
    name: str
    passed: bool
    detail: str


@dataclass
class ProtectiveModeResult:
    apply_safe_enabled: bool
    confirm_apply: bool
    cloudflare_api_used: bool
    cloudflare_result_summary: str
    planned_actions: List[Dict[str, object]]
    applied_actions: List[Dict[str, object]]
    skipped_actions: List[Dict[str, object]]
    safety_checks: List[SafetyCheck]


@dataclass
class TrendResult:
    summary: Dict[str, object]
    interpretations: List[str]
    entries_used: List[Dict[str, object]]


RULES: Tuple[MetricRule, ...] = (
    MetricRule(
        key="total_5xx",
        label="5xx gesamt",
        aliases=("5xx gesamt", "5xx total", "total 5xx"),
        warning=300,
        critical=600,
        recommendation=(
            "5xx nach Pfad, User-Agent, Land und Zeitfenster korrelieren. "
            "Keine breite Blockade ohne Beweis."
        ),
    ),
    MetricRule(
        key="wp_login_503",
        label="503 auf /wp-login.php",
        aliases=("503 auf /wp-login.php", "wp-login 503", "503 /wp-login.php"),
        warning=50,
        critical=120,
        recommendation=(
            "Login-POST-Challenge prüfen. Nur verdächtige POST-User-Agents "
            "challengen, normalen GET-Login nicht blockieren."
        ),
    ),
    MetricRule(
        key="root_504",
        label="504 auf /",
        aliases=("504 auf /", "root 504", "504 /"),
        warning=100,
        critical=250,
        recommendation=(
            "Origin-/Cloudflare-Verbindung im Zeitfenster prüfen. "
            "IONOS-/PHP-/WordPress-Logs korrelieren."
        ),
    ),
    MetricRule(
        key="map_404",
        label="404 auf .map",
        aliases=("404 auf .map", "404 .map", "map 404", "source map 404"),
        warning=20,
        critical=80,
        recommendation=(
            "Source-Map-404-Breakdown pruefen: WordPress-Minify/Core-Referenzen und "
            "Scanner-/Framework-Probes getrennt bewerten. Keine Cloudflare-Regel daraus ableiten."
        ),
    ),
    MetricRule(
        key="oembed_503",
        label="503 auf oEmbed",
        aliases=("503 auf oembed", "oembed 503", "503 oembed"),
        warning=50,
        critical=120,
        recommendation=(
            "oEmbed beobachten. Nicht pauschal blocken, da legitime Embed-/REST-Nutzung "
            "möglich ist."
        ),
    ),
    MetricRule(
        key="oembed_404",
        label="404 auf oEmbed",
        aliases=("404 auf oembed", "oembed 404", "404 oembed"),
        warning=20,
        critical=80,
        recommendation=(
            "oEmbed beobachten. Nicht pauschal blocken, da legitime Embed-/REST-Nutzung "
            "möglich ist."
        ),
    ),
    MetricRule(
        key="app_404",
        label="404 auf /app",
        aliases=("404 auf /app", "app 404", "404 /app"),
        warning=1,
        critical=10,
        recommendation=(
            "/app wurde auf 410 gesetzt. Alte 24h-Daten oder Cache prüfen. "
            "Zielwert: 404 auf /app = 0."
        ),
    ),
    MetricRule(
        key="sitelockspider_top_user_agents",
        label="SiteLockSpider in Top User-Agents",
        aliases=(
            "sitelockspider in top user-agents",
            "sitelockspider top user-agents",
            "sitelockspider in top user agents",
            "sitelockspider top ua requests",
        ),
        warning=200,
        critical=600,
        recommendation=(
            "SiteLockSpider mit 5xx-Spikes korrelieren. Top-UA-Volumen allein ist "
            "kein Apply-Kandidat."
        ),
    ),
)


def normalize_label(value: str) -> str:
    cleaned = value.strip().strip("|").strip()
    cleaned = cleaned.replace("`", "")
    cleaned = cleaned.replace("\\", "")
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.casefold()


def parse_int(value: str) -> Optional[int]:
    cleaned = value.replace("`", "").replace("\xa0", " ").strip()
    match = re.search(r"-?\d[\d.,]*", cleaned)
    if not match:
        return None

    token = match.group(0)
    if "," in token and "." in token:
        token = token.replace(",", "")
    elif "," in token:
        token = token.split(",", 1)[0].replace(".", "")
    elif "." in token:
        parts = token.split(".")
        token = "".join(parts) if all(len(part) == 3 for part in parts[1:]) else parts[0]

    try:
        return int(token)
    except ValueError:
        return None


def split_markdown_row(line: str) -> List[str]:
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]

    cells: List[str] = []
    current: List[str] = []
    escaped = False
    for char in stripped:
        if char == "\\" and not escaped:
            escaped = True
            current.append(char)
            continue
        if char == "|" and not escaped:
            cells.append("".join(current).strip())
            current = []
            continue
        escaped = False
        current.append(char)
    cells.append("".join(current).strip())
    return cells


def is_separator_row(cells: Sequence[str]) -> bool:
    return bool(cells) and all(re.fullmatch(r":?-{3,}:?", cell.strip()) for cell in cells)


def iter_markdown_tables(text: str) -> Iterable[Tuple[List[str], List[List[str]]]]:
    lines = text.splitlines()
    in_code_block = False
    i = 0

    while i < len(lines):
        line = lines[i].strip()
        if line.startswith("```"):
            in_code_block = not in_code_block
            i += 1
            continue

        if in_code_block or not line.startswith("|"):
            i += 1
            continue

        if i + 1 >= len(lines):
            i += 1
            continue

        header = split_markdown_row(lines[i])
        separator = split_markdown_row(lines[i + 1])
        if not is_separator_row(separator):
            i += 1
            continue

        rows: List[List[str]] = []
        i += 2
        while i < len(lines):
            row_line = lines[i].strip()
            if not row_line.startswith("|"):
                break
            cells = split_markdown_row(lines[i])
            if len(cells) < len(header):
                cells.extend([""] * (len(header) - len(cells)))
            rows.append(cells[: len(header)])
            i += 1

        yield header, rows


def extract_section(markdown: str, heading: str) -> Optional[str]:
    lines = markdown.splitlines()
    start: Optional[int] = None
    heading_pattern = re.compile(rf"^##\s+{re.escape(heading)}\s*$", re.IGNORECASE)

    for index, line in enumerate(lines):
        if heading_pattern.match(line.strip()):
            start = index + 1
            break

    if start is None:
        return None

    end = len(lines)
    for index in range(start, len(lines)):
        if re.match(r"^##\s+", lines[index].strip()):
            end = index
            break

    return "\n".join(lines[start:end])


def extract_metric_values_from_tables(markdown: str) -> Dict[str, Tuple[int, str]]:
    alias_to_rule: Dict[str, MetricRule] = {}
    for rule in RULES:
        for alias in (rule.label, *rule.aliases):
            alias_to_rule[normalize_label(alias)] = rule

    found: Dict[str, Tuple[int, str]] = {}
    for _header, rows in iter_markdown_tables(markdown):
        for row in rows:
            if not row:
                continue
            source_label = row[0]
            rule = alias_to_rule.get(normalize_label(source_label))
            if rule is None:
                continue

            parsed_value = None
            for cell in row[1:]:
                parsed_value = parse_int(cell)
                if parsed_value is not None:
                    break
            if parsed_value is not None:
                found.setdefault(rule.key, (parsed_value, source_label))
    return found


def extract_metric_values(markdown: str) -> Dict[str, Tuple[int, str]]:
    watchpoints = extract_section(markdown, "Watchpoints")
    if watchpoints:
        found = extract_metric_values_from_tables(watchpoints)
        if found:
            return found
    return extract_metric_values_from_tables(markdown)


def classify(value: Optional[int], warning: int, critical: int) -> str:
    if value is None:
        return STATUS_UNKNOWN
    if value >= critical:
        return STATUS_CRITICAL
    if value >= warning:
        return STATUS_WARNING
    return STATUS_OK


def overall_status(results: Sequence[MetricResult]) -> str:
    statuses = {result.status for result in results}
    if STATUS_CRITICAL in statuses:
        return STATUS_CRITICAL
    if STATUS_WARNING in statuses:
        return STATUS_WARNING
    if STATUS_OK in statuses:
        return STATUS_OK
    return STATUS_UNKNOWN


def evaluate(markdown: str) -> List[MetricResult]:
    extracted = extract_metric_values(markdown)
    results: List[MetricResult] = []

    for rule in RULES:
        value_and_label = extracted.get(rule.key)
        value = value_and_label[0] if value_and_label else None
        source_label = value_and_label[1] if value_and_label else None
        status = classify(value, rule.warning, rule.critical)
        note = "" if value is not None else "Watchpoint nicht im Report gefunden oder nicht numerisch lesbar."
        results.append(
            MetricResult(
                key=rule.key,
                label=rule.label,
                value=value,
                status=status,
                warning=rule.warning,
                critical=rule.critical,
                recommendation=rule.recommendation,
                source_label=source_label,
                note=note,
            )
        )

    return results


def recommendation_priority(status: str) -> int:
    return {
        STATUS_CRITICAL: 0,
        STATUS_WARNING: 1,
        STATUS_UNKNOWN: 2,
        STATUS_OK: 3,
    }.get(status, 4)


def active_recommendations(results: Sequence[MetricResult]) -> List[MetricResult]:
    return sorted(
        [result for result in results if result.status in {STATUS_WARNING, STATUS_CRITICAL, STATUS_UNKNOWN}],
        key=lambda item: (recommendation_priority(item.status), item.label),
    )


def metric_value(results: Sequence[MetricResult], key: str) -> Optional[int]:
    for result in results:
        if result.key == key:
            return result.value
    return None


def format_metric_value(value: Optional[int]) -> str:
    return "unknown" if value is None else str(value)


def correlate(results: Sequence[MetricResult]) -> CorrelationResult:
    sitelock = metric_value(results, "sitelockspider_top_user_agents")
    total_5xx = metric_value(results, "total_5xx")
    wp_login_503 = metric_value(results, "wp_login_503")
    root_504 = metric_value(results, "root_504")

    value_text = (
        f"SiteLockSpider={format_metric_value(sitelock)}; "
        f"5xx gesamt={format_metric_value(total_5xx)}; "
        f"503 auf /wp-login.php={format_metric_value(wp_login_503)}; "
        f"504 auf /={format_metric_value(root_504)}"
    )

    if sitelock is None:
        status = CORRELATION_NORMAL
        interpretation = "SiteLockSpider-Wert ist nicht lesbar; keine Korrelation ableitbar."
        action = "Report-Format pruefen und Watchpoint erneut auswerten."
    elif sitelock < 600:
        status = CORRELATION_NORMAL
        interpretation = "SiteLockSpider liegt unter der Critical-Schwelle."
        action = "Normal weiter beobachten."
    elif wp_login_503 is not None and wp_login_503 >= 120:
        status = CORRELATION_ACTION_CANDIDATE
        interpretation = "SiteLockSpider ist hoch und 503 auf /wp-login.php ist kritisch."
        action = "Gezielte Challenge-Regel fuer /wp-login.php vorbereiten, aber nicht anwenden."
    elif root_504 is not None and root_504 >= 250:
        status = CORRELATION_ACTION_CANDIDATE
        interpretation = "SiteLockSpider ist hoch und 504 auf / ist kritisch."
        action = "Gezielte Challenge-Regel vorbereiten, aber nicht anwenden."
    elif total_5xx is not None and total_5xx >= 600:
        status = CORRELATION_ACTION_CANDIDATE
        interpretation = "SiteLockSpider ist hoch und 5xx gesamt ist kritisch."
        action = "User-Agent-/Zeitfenster-Korrelation pruefen und Challenge simulieren."
    elif total_5xx is not None and total_5xx < 300:
        status = CORRELATION_WATCH
        interpretation = "SiteLockSpider ist hoch, aber 5xx gesamt liegt unter der Warning-Schwelle."
        action = "Noch nicht blocken; weiter korrelieren."
    else:
        status = CORRELATION_WATCH
        interpretation = "SiteLockSpider ist hoch, aber es gibt keine kritische 5xx-/504-Korrelation."
        action = "Weiter beobachten und erst bei klarer Zeitfenster-Korrelation simulieren."

    overall = overall_status(results)
    if status == CORRELATION_WATCH and overall == STATUS_CRITICAL and sitelock is not None and sitelock >= 600:
        operational = "CRITICAL wegen SiteLockSpider-Volumen, aber keine bestätigte Origin-Krise."
    elif status == CORRELATION_ACTION_CANDIDATE:
        operational = (
            "CRITICAL mit moeglicher operativer Relevanz: SiteLockSpider und kritische "
            "5xx-/504-Signale muessen vor jeder Regelanwendung zeitlich bestaetigt werden."
        )
    elif status == CORRELATION_NORMAL:
        operational = "Keine SiteLockSpider-getriebene Origin-Korrelation erkannt."
    else:
        operational = "Erhoehte Signale weiter beobachten; noch keine sichere Handlungskorrelation."

    return CorrelationResult(
        correlation_status=status,
        operational_interpretation=operational,
        findings=[
            CorrelationFinding(
                signal="SiteLockSpider vs 5xx/504",
                value=value_text,
                interpretation=interpretation,
                recommended_next_action=action,
            )
        ],
    )


def simulated_actions(results: Sequence[MetricResult], correlation: CorrelationResult) -> List[str]:
    selected = select_sitelock_action_id(results, correlation)
    if selected:
        action_id, reason = selected
        return [
            f"Hypothetisch geplant: `{action_id}` als managed_challenge. {reason}"
        ]
    if correlation.correlation_status == CORRELATION_ACTION_CANDIDATE:
        return [
            "ACTION_CANDIDATE erkannt, aber keine exakt allowlistete Pfad-Korrelation fuer apply-safe ausgewaehlt."
        ]

    actions: List[str] = []
    for result in active_recommendations(results):
        if result.status == STATUS_UNKNOWN:
            actions.append(
                f"Hypothetisch: Parser/Report-Format fuer `{result.label}` pruefen, bevor daraus Regeln abgeleitet werden."
            )
            continue
        actions.append(f"Hypothetisch: {result.recommendation}")
    return actions


RAW_JSON_FILES = {
    "errors_5xx": "errors-5xx-24h.json",
    "user_agents": "user-agents-24h.json",
    "status": "status-24h.json",
    "notfound_404": "notfound-404-24h.json",
}

ORIGIN_PRESSURE_JSON_FILES = {
    "errors_5xx": "errors-5xx-24h.json",
    "notfound_404": "notfound-404-24h.json",
    "status": "status-24h.json",
    "user_agents": "user-agents-24h.json",
    "top_paths": "top-paths-24h.json",
    "security_actions": "security-actions-24h.json",
}

RAW_GROUP_COUNT_FILES = {
    "errors_5xx": "errors-5xx-24h.json",
    "notfound_404": "notfound-404-24h.json",
    "user_agents": "user-agents-24h.json",
    "top_paths": "top-paths-24h.json",
    "security_actions": "security-actions-24h.json",
}

MONITOR_REQUIRED_FILES = (
    "meta.json",
    "status-24h.json",
    "errors-5xx-24h.json",
    "user-agents-24h.json",
    "notfound-404-24h.json",
    "security-actions-24h.json",
)

ROLLING_DELTA_KEYS = {
    "total_5xx": "total_5xx",
    "wp_login_503": "wp_login_503",
    "root_504": "root_504",
    "map_404": "map_404",
    "oembed_503": "oembed_503",
    "oembed_404": "oembed_404",
    "app_404": "app_404",
    "sitelockspider_top_user_agents": "sitelock_top_user_agent_requests",
}

ROLLING_DETAIL_SOURCE_KEYS = {
    "wp_login_503": "errors_5xx",
    "root_504": "errors_5xx",
    "oembed_503": "errors_5xx",
    "map_404": "notfound_404",
    "oembed_404": "notfound_404",
    "app_404": "notfound_404",
    "sitelockspider_top_user_agents": "user_agents",
}

ROLLING_DETAIL_SOURCE_LIMIT_KEYS = {
    "errors_5xx": "detail_limit",
    "notfound_404": "detail_limit",
    "top_paths": "detail_limit",
    "security_actions": "detail_limit",
    "user_agents": "user_agent_limit",
}

ROLLING_LOW_GROWTH_LIMITS = {
    "total_5xx": 5,
    "sitelockspider_top_user_agents": 5,
}

OLD_WINDOW_REQUIRED_STABLE_MINUTES = 24 * 60

FAKE_SCAN_PATTERNS = (
    "/.env",
    ".env",
    "/secrets",
    "secrets",
    "phpinfo",
    "_next",
    ".aws",
    "actuator",
    "dockerfile",
    "gitlab",
    "api/auth",
    "__rsc",
    "__nextjs_action",
)

SCANNER_PRESSURE_PATH_MARKERS = (
    "/config/",
    "/aws/",
    "/admin.html",
    "/api/trpc",
    "/login/",
    "/bucket",
    "/stripe",
    "/amplify/",
    "/swagger",
    "/_profiler",
    "/horizon",
    "/healthcheck",
    "/sysadmin",
    "/server-info",
    "/php_info",
    "/phpversion",
    "/version.php",
    "/rest/executions",
    "/package-updates",
    "/log-viewer",
    "/metrics",
    "/vagrantfile",
    ".git/",
    ".github/",
)

TIMEOUT_STATUS_CODES = {522, 523, 524, 525, 526, 530}

ORIGIN_PRESSURE_CLASSIFICATIONS = (
    "likely_scanner_pressure",
    "likely_origin_pressure",
    "likely_wordpress_legacy_pressure",
    "likely_cloudflare_timeout",
    "unknown",
)


def decode_path(path: object) -> str:
    value = str(path or "")
    for _ in range(2):
        decoded = urllib.parse.unquote(value)
        if decoded == value:
            break
        value = decoded
    return value or "-"


def safe_cell(value: object, max_len: int = 120) -> str:
    raw = "-" if value is None or value == "" else str(value)
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", raw)
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(
        r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization|credential)\s*[:=]\s*[^\s,;]+",
        lambda match: f"{match.group(1)}=<redacted>",
        text,
    )
    text = re.sub(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+", "Bearer <redacted>", text)
    text = re.sub(r"\b[A-Fa-f0-9]{32,}\b", "<redacted-hex>", text)
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def status_from_count(count: int, warning: int, critical: int, watch: int = 1) -> str:
    if count >= critical:
        return STATUS_CRITICAL
    if count >= warning:
        return STATUS_WARNING
    if count >= watch:
        return STATUS_WATCH
    return STATUS_OK


def parse_status(value: object) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def extract_cf_groups(payload: Dict[str, object]) -> List[Dict[str, object]]:
    data = payload.get("data")
    if not isinstance(data, dict):
        return []
    viewer = data.get("viewer")
    if not isinstance(viewer, dict):
        return []
    zones = viewer.get("zones")
    if not isinstance(zones, list):
        return []

    groups: List[Dict[str, object]] = []
    for zone in zones:
        if not isinstance(zone, dict):
            continue
        zone_groups = zone.get("httpRequestsAdaptiveGroups")
        if isinstance(zone_groups, list):
            groups.extend(item for item in zone_groups if isinstance(item, dict))
    return groups


def read_raw_json_groups(raw_dir: Path) -> Dict[str, List[Dict[str, object]]]:
    raw: Dict[str, List[Dict[str, object]]] = {}
    for source, filename in RAW_JSON_FILES.items():
        path = raw_dir / filename
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw[source] = []
            continue
        raw[source] = normalize_cf_groups(extract_cf_groups(payload), source)
    return raw


def read_json_object(path: Path) -> Dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def parse_utc_timestamp(value: object) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_count(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return int(float(value.strip()))
        except ValueError:
            return 0
    return 0


def rolling_low_growth_limit(metric_key: str) -> int:
    return ROLLING_LOW_GROWTH_LIMITS.get(metric_key, 1)


def rolling_stability_anchor(
    candidates: Sequence[Tuple[str, Optional[Dict[str, object]]]]
) -> Tuple[Optional[Dict[str, object]], Optional[str]]:
    anchor: Optional[Dict[str, object]] = None
    anchor_reason: Optional[str] = None
    anchor_dt: Optional[datetime] = None
    for reason, snapshot in candidates:
        if not snapshot:
            continue
        snapshot_dt = snapshot.get("generated_at_dt")
        if anchor is None:
            anchor = snapshot
            anchor_reason = reason
            anchor_dt = snapshot_dt if isinstance(snapshot_dt, datetime) else None
            continue
        if isinstance(snapshot_dt, datetime):
            if anchor_dt is None or snapshot_dt >= anchor_dt:
                anchor = snapshot
                anchor_reason = reason
                anchor_dt = snapshot_dt
    return anchor, anchor_reason


def rolling_detail_source(metric_key: str) -> Optional[str]:
    return ROLLING_DETAIL_SOURCE_KEYS.get(metric_key)


def rolling_delta_comparability(
    metric_key: str,
    previous_snapshot: Optional[Dict[str, object]],
    current_snapshot: Dict[str, object],
) -> Dict[str, object]:
    source = rolling_detail_source(metric_key)
    if source is None:
        return {"comparable": True, "reason": "status_or_aggregate_metric", "source": None}
    if previous_snapshot is None:
        return {"comparable": False, "reason": "missing_previous_snapshot", "source": source}
    limit_key = ROLLING_DETAIL_SOURCE_LIMIT_KEYS.get(source)
    previous_limits = (
        previous_snapshot.get("monitor_limits")
        if isinstance(previous_snapshot.get("monitor_limits"), dict)
        else {}
    )
    current_limits = (
        current_snapshot.get("monitor_limits")
        if isinstance(current_snapshot.get("monitor_limits"), dict)
        else {}
    )
    previous_limit = previous_limits.get(limit_key) if limit_key else None
    current_limit = current_limits.get(limit_key) if limit_key else None
    if isinstance(previous_limit, int) and previous_limit > 0 and isinstance(current_limit, int) and current_limit > 0:
        if previous_limit != current_limit:
            return {
                "comparable": False,
                "reason": "monitor_limit_changed",
                "source": source,
                "limit_key": limit_key,
                "previous_monitor_limit": previous_limit,
                "current_monitor_limit": current_limit,
            }
        return {
            "comparable": True,
            "reason": "monitor_limit_stable",
            "source": source,
            "limit_key": limit_key,
            "previous_monitor_limit": previous_limit,
            "current_monitor_limit": current_limit,
        }
    previous_counts = (
        previous_snapshot.get("raw_group_counts")
        if isinstance(previous_snapshot.get("raw_group_counts"), dict)
        else {}
    )
    current_counts = (
        current_snapshot.get("raw_group_counts")
        if isinstance(current_snapshot.get("raw_group_counts"), dict)
        else {}
    )
    previous_count = previous_counts.get(source)
    current_count = current_counts.get(source)
    if not isinstance(previous_count, int) or not isinstance(current_count, int):
        return {
            "comparable": False,
            "reason": "missing_raw_group_count",
            "source": source,
            "previous_raw_group_count": previous_count,
            "current_raw_group_count": current_count,
        }
    if previous_count != current_count:
        return {
            "comparable": False,
            "reason": "raw_group_count_changed",
            "source": source,
            "previous_raw_group_count": previous_count,
            "current_raw_group_count": current_count,
        }
    return {
        "comparable": True,
        "reason": "raw_group_count_stable",
        "source": source,
        "previous_raw_group_count": previous_count,
        "current_raw_group_count": current_count,
    }


def successful_monitor_snapshot(path: Path) -> Optional[Dict[str, object]]:
    meta = read_json_object(path / "meta.json")
    metrics = read_json_object(path / "metrics.json")
    if not metrics:
        return None
    for name in ("status-24h.json", "errors-5xx-24h.json", "user-agents-24h.json"):
        payload = read_json_object(path / name)
        if payload.get("errors"):
            return None
    comparison = read_json_object(path / "comparison.json")
    generated = parse_utc_timestamp(metrics.get("generated_at_utc"))
    return {
        "run_id": path.name,
        "path": str(path),
        "generated_at_utc": metrics.get("generated_at_utc"),
        "generated_at_dt": generated,
        "metrics": metrics,
        "deltas": comparison.get("deltas") if isinstance(comparison.get("deltas"), dict) else {},
        "raw_group_counts": raw_group_counts(path),
        "monitor_limits": {
            "detail_limit": parse_count(meta.get("detail_limit")),
            "user_agent_limit": parse_count(meta.get("user_agent_limit")),
        },
    }


def raw_group_counts(path: Path) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for source, filename in RAW_GROUP_COUNT_FILES.items():
        payload = read_json_object(path / filename)
        groups = extract_cf_groups(payload)
        counts[source] = len(groups)
    return counts


def successful_monitor_snapshots(raw_dir: Path) -> List[Dict[str, object]]:
    monitor_root = raw_dir.parent
    snapshots: List[Dict[str, object]] = []
    if not monitor_root.exists():
        return snapshots
    for path in monitor_root.iterdir():
        if not path.is_dir() or not re.fullmatch(r"\d{8}-\d{6}", path.name):
            continue
        snapshot = successful_monitor_snapshot(path)
        if snapshot:
            snapshots.append(snapshot)
    snapshots.sort(key=lambda item: str(item.get("run_id", "")))
    return snapshots


def build_rolling_history_context(raw_dir: Path, results: Sequence[MetricResult]) -> Dict[str, object]:
    all_snapshots = successful_monitor_snapshots(raw_dir)
    evaluated_run_id = raw_dir.name
    snapshots = [item for item in all_snapshots if str(item.get("run_id", "")) <= evaluated_run_id]
    if not snapshots:
        return {
            "status": "NO_SUCCESSFUL_HISTORY",
            "interpretation": "No successful rolling snapshots are available for multi-run stability analysis.",
            "evaluated_run": evaluated_run_id,
            "successful_snapshot_count": 0,
            "elevated_metrics": [],
            "old_window_required_stable_minutes": OLD_WINDOW_REQUIRED_STABLE_MINUTES,
            "old_window_blockers": [
                {
                    "reason": "no_successful_history",
                    "detail": "No successful monitor snapshots are available to prove 24h low-growth evidence.",
                }
            ],
            "ok_remainder_eligible": False,
        }

    latest = snapshots[-1]
    latest_dt = latest.get("generated_at_dt") if isinstance(latest.get("generated_at_dt"), datetime) else None
    elevated_metrics: List[Dict[str, object]] = []
    old_window_blockers: List[Dict[str, object]] = []
    any_recent_significant_growth = False
    all_long_stable = True

    for result in results:
        if result.status not in {STATUS_WARNING, STATUS_CRITICAL}:
            continue
        delta_key = ROLLING_DELTA_KEYS.get(result.key, result.key)
        metric_key = delta_key if delta_key != "sitelock_top_user_agent_requests" else "sitelock_top_user_agent_requests"
        limit = rolling_low_growth_limit(result.key)
        metric_snapshots: List[Dict[str, object]] = []
        last_significant: Optional[Dict[str, object]] = None
        last_incomparable: Optional[Dict[str, object]] = None
        first_with_delta: Optional[Dict[str, object]] = None
        previous_snapshot: Optional[Dict[str, object]] = None

        for snapshot in snapshots:
            metrics = snapshot.get("metrics") if isinstance(snapshot.get("metrics"), dict) else {}
            deltas = snapshot.get("deltas") if isinstance(snapshot.get("deltas"), dict) else {}
            if metric_key not in metrics and result.key in metrics:
                metric_key = result.key
            raw_delta = deltas.get(delta_key)
            has_delta = raw_delta is not None
            delta = parse_count(raw_delta)
            if has_delta and first_with_delta is None:
                first_with_delta = snapshot
            comparability = rolling_delta_comparability(result.key, previous_snapshot, snapshot) if has_delta else {
                "comparable": False,
                "reason": "missing_delta",
                "source": rolling_detail_source(result.key),
            }
            delta_comparable = bool(comparability.get("comparable"))
            if has_delta and not delta_comparable:
                last_incomparable = snapshot
            if has_delta and delta_comparable and delta > limit:
                last_significant = snapshot
            metric_snapshots.append(
                {
                    "run_id": snapshot.get("run_id"),
                    "generated_at_utc": snapshot.get("generated_at_utc"),
                    "value": metrics.get(metric_key),
                    "delta": delta if has_delta else None,
                    "delta_comparable": delta_comparable,
                    "delta_comparability_reason": comparability.get("reason"),
                    "raw_group_count_source": comparability.get("source"),
                    "previous_raw_group_count": comparability.get("previous_raw_group_count"),
                    "current_raw_group_count": comparability.get("current_raw_group_count"),
                    "limit_key": comparability.get("limit_key"),
                    "previous_monitor_limit": comparability.get("previous_monitor_limit"),
                    "current_monitor_limit": comparability.get("current_monitor_limit"),
                }
            )
            previous_snapshot = snapshot

        stable_since, stable_since_reason = rolling_stability_anchor(
            (
                ("comparison_incompatible", last_incomparable),
                ("significant_growth", last_significant),
                ("first_delta", first_with_delta),
                ("first_successful_snapshot", snapshots[0]),
            )
        )
        if stable_since is None:
            stable_since = snapshots[0]
            stable_since_reason = "first_successful_snapshot"
        stable_since_dt = (
            stable_since.get("generated_at_dt") if isinstance(stable_since.get("generated_at_dt"), datetime) else None
        )
        stable_minutes = None
        if latest_dt and stable_since_dt:
            stable_minutes = round((latest_dt - stable_since_dt).total_seconds() / 60.0, 2)
        recent = metric_snapshots[-8:]
        recent_deltas = [
            item.get("delta")
            for item in recent
            if isinstance(item.get("delta"), int) and item.get("delta_comparable") is True
        ]
        max_recent_delta = max(recent_deltas) if recent_deltas else None
        latest_metric_snapshot = recent[-1] if recent else {}
        latest_delta_comparable = latest_metric_snapshot.get("delta_comparable") is True
        latest_delta_comparability_reason = latest_metric_snapshot.get("delta_comparability_reason")
        recent_significant = bool(max_recent_delta is not None and max_recent_delta > limit)
        any_recent_significant_growth = any_recent_significant_growth or recent_significant
        remaining_stable_minutes = (
            round(max(OLD_WINDOW_REQUIRED_STABLE_MINUTES - stable_minutes, 0), 2)
            if stable_minutes is not None
            else None
        )
        stable_long_enough = bool(
            stable_minutes is not None and stable_minutes >= OLD_WINDOW_REQUIRED_STABLE_MINUTES
        )
        all_long_stable = all_long_stable and stable_long_enough
        if latest_metric_snapshot and not latest_delta_comparable:
            old_window_blockers.append(
                {
                    "key": result.key,
                    "label": result.label,
                    "reason": "comparison_incompatible_requires_new_evidence",
                    "value_24h": result.value,
                    "latest_delta": latest_metric_snapshot.get("delta"),
                    "latest_delta_comparable": latest_delta_comparable,
                    "delta_comparability_reason": latest_delta_comparability_reason,
                    "raw_group_count_source": latest_metric_snapshot.get("raw_group_count_source"),
                    "previous_raw_group_count": latest_metric_snapshot.get("previous_raw_group_count"),
                    "current_raw_group_count": latest_metric_snapshot.get("current_raw_group_count"),
                    "limit_key": latest_metric_snapshot.get("limit_key"),
                    "previous_monitor_limit": latest_metric_snapshot.get("previous_monitor_limit"),
                    "current_monitor_limit": latest_metric_snapshot.get("current_monitor_limit"),
                    "max_recent_delta": max_recent_delta,
                    "low_growth_limit": limit,
                    "last_significant_growth_at_utc": last_significant.get("generated_at_utc") if last_significant else None,
                    "stable_since_utc": stable_since.get("generated_at_utc"),
                    "stable_since_reason": stable_since_reason,
                    "stable_minutes": stable_minutes,
                    "remaining_stable_minutes_for_old_window": remaining_stable_minutes,
                }
            )
        elif recent_significant:
            old_window_blockers.append(
                {
                    "key": result.key,
                    "label": result.label,
                    "reason": "recent_significant_growth",
                    "value_24h": result.value,
                    "latest_delta": latest_metric_snapshot.get("delta"),
                    "latest_delta_comparable": latest_delta_comparable,
                    "max_recent_delta": max_recent_delta,
                    "low_growth_limit": limit,
                    "last_significant_growth_at_utc": last_significant.get("generated_at_utc") if last_significant else None,
                    "stable_since_utc": stable_since.get("generated_at_utc"),
                    "stable_since_reason": stable_since_reason,
                    "stable_minutes": stable_minutes,
                    "remaining_stable_minutes_for_old_window": remaining_stable_minutes,
                }
            )
        elif not stable_long_enough:
            old_window_blockers.append(
                {
                    "key": result.key,
                    "label": result.label,
                    "reason": "low_growth_but_not_24h",
                    "value_24h": result.value,
                    "latest_delta": latest_metric_snapshot.get("delta"),
                    "latest_delta_comparable": latest_delta_comparable,
                    "max_recent_delta": max_recent_delta,
                    "low_growth_limit": limit,
                    "last_significant_growth_at_utc": last_significant.get("generated_at_utc") if last_significant else None,
                    "stable_since_utc": stable_since.get("generated_at_utc"),
                    "stable_since_reason": stable_since_reason,
                    "stable_minutes": stable_minutes,
                    "remaining_stable_minutes_for_old_window": remaining_stable_minutes,
                }
            )

        elevated_metrics.append(
            {
                "key": result.key,
                "label": result.label,
                "status": result.status,
                "value_24h": result.value,
                "delta_key": delta_key,
                "low_growth_limit": limit,
                "latest_delta": latest_metric_snapshot.get("delta") if latest_metric_snapshot else None,
                "latest_delta_comparable": latest_delta_comparable if latest_metric_snapshot else None,
                "latest_delta_comparability_reason": latest_delta_comparability_reason,
                "raw_group_count_source": latest_metric_snapshot.get("raw_group_count_source") if latest_metric_snapshot else None,
                "previous_raw_group_count": latest_metric_snapshot.get("previous_raw_group_count") if latest_metric_snapshot else None,
                "current_raw_group_count": latest_metric_snapshot.get("current_raw_group_count") if latest_metric_snapshot else None,
                "limit_key": latest_metric_snapshot.get("limit_key") if latest_metric_snapshot else None,
                "previous_monitor_limit": latest_metric_snapshot.get("previous_monitor_limit") if latest_metric_snapshot else None,
                "current_monitor_limit": latest_metric_snapshot.get("current_monitor_limit") if latest_metric_snapshot else None,
                "max_recent_delta": max_recent_delta,
                "last_significant_growth_run": last_significant.get("run_id") if last_significant else None,
                "last_significant_growth_at_utc": last_significant.get("generated_at_utc") if last_significant else None,
                "stable_since_utc": stable_since.get("generated_at_utc"),
                "stable_since_reason": stable_since_reason,
                "stable_minutes": stable_minutes,
                "required_stable_minutes_for_old_window": OLD_WINDOW_REQUIRED_STABLE_MINUTES,
                "remaining_stable_minutes_for_old_window": remaining_stable_minutes,
                "stable_long_enough_for_old_window": stable_long_enough,
                "recent_snapshots": recent,
            }
        )

    if not elevated_metrics:
        status = "NO_ELEVATED_WATCHPOINTS"
        interpretation = "No elevated watchpoints require rolling-history analysis."
    elif any_recent_significant_growth:
        status = "RECENT_SIGNIFICANT_GROWTH"
        interpretation = "At least one elevated watchpoint still has significant recent rolling-snapshot growth."
    elif all_long_stable:
        status = "OLD_WINDOW_REMAINDER_CANDIDATE"
        interpretation = "Elevated watchpoints have been low-growth for at least 24h of successful snapshots."
    else:
        status = "LOW_GROWTH_BUT_NOT_OLD_ENOUGH"
        interpretation = "Recent successful snapshots show low growth, but not enough elapsed evidence to call the 24h totals old-window leftovers."

    return {
        "status": status,
        "interpretation": interpretation,
        "evaluated_run": evaluated_run_id,
        "first_successful_run": snapshots[0].get("run_id"),
        "latest_successful_run": latest.get("run_id"),
        "successful_snapshot_count": len(snapshots),
        "elevated_metrics": elevated_metrics,
        "old_window_required_stable_minutes": OLD_WINDOW_REQUIRED_STABLE_MINUTES,
        "old_window_blockers": old_window_blockers,
        "ok_remainder_eligible": bool(elevated_metrics and all_long_stable and not any_recent_significant_growth),
        "status_policy": (
            "This multi-run context can support an old-window remainder classification only after at least "
            "24h of low-growth successful snapshots for every elevated watchpoint."
        ),
    }


def build_rolling_window_context(report_path: Path, results: Sequence[MetricResult]) -> Dict[str, object]:
    raw_dir = report_path.parent
    meta = read_json_object(raw_dir / "meta.json")
    metrics = read_json_object(raw_dir / "metrics.json")
    comparison = read_json_object(raw_dir / "comparison.json")
    deltas = comparison.get("deltas") if isinstance(comparison.get("deltas"), dict) else {}
    history_context = build_rolling_history_context(raw_dir, results)
    history_metrics = (
        history_context.get("elevated_metrics")
        if isinstance(history_context.get("elevated_metrics"), list)
        else []
    )
    history_metrics_by_key = {
        item.get("key"): item
        for item in history_metrics
        if isinstance(item, dict) and item.get("key")
    }

    previous_generated = comparison.get("previous_generated_at_utc")
    current_generated = comparison.get("current_generated_at_utc") or meta.get("generated_at_utc")
    previous_dt = parse_utc_timestamp(previous_generated)
    current_dt = parse_utc_timestamp(current_generated)
    minutes_between = None
    if previous_dt and current_dt:
        minutes_between = round((current_dt - previous_dt).total_seconds() / 60.0, 2)

    elevated: List[Dict[str, object]] = []
    missing_delta = False
    high_growth = False
    incompatible_delta = False
    for result in results:
        if result.status not in {STATUS_WARNING, STATUS_CRITICAL}:
            continue
        delta_key = ROLLING_DELTA_KEYS.get(result.key, result.key)
        raw_delta = deltas.get(delta_key)
        delta = parse_count(raw_delta)
        has_delta = raw_delta is not None
        limit = rolling_low_growth_limit(result.key)
        history_metric = history_metrics_by_key.get(result.key, {})
        latest_delta_comparable = history_metric.get("latest_delta_comparable")
        latest_delta_comparability_reason = history_metric.get("latest_delta_comparability_reason")
        if not has_delta:
            missing_delta = True
            interpretation = "No comparison delta is available for this elevated 24h metric."
        elif latest_delta_comparable is False:
            incompatible_delta = True
            interpretation = (
                "Delta is not directly comparable because the monitor raw-detail grouping coverage changed "
                "between snapshots."
            )
        elif delta <= 0:
            interpretation = "No new growth since the previous rolling-window snapshot."
        elif delta <= limit:
            interpretation = "Only minimal new growth since the previous rolling-window snapshot."
        else:
            high_growth = True
            interpretation = "New growth is visible since the previous rolling-window snapshot."
        elevated.append(
            {
                "key": result.key,
                "label": result.label,
                "status": result.status,
                "value_24h": result.value,
                "delta_key": delta_key,
                "delta_since_previous": delta if has_delta else None,
                "delta_comparable": latest_delta_comparable,
                "delta_comparability_reason": latest_delta_comparability_reason,
                "raw_group_count_source": history_metric.get("raw_group_count_source"),
                "previous_raw_group_count": history_metric.get("previous_raw_group_count"),
                "current_raw_group_count": history_metric.get("current_raw_group_count"),
                "low_growth_limit": limit,
                "interpretation": interpretation,
            }
        )

    if not elevated:
        status = "NO_ELEVATED_WATCHPOINTS"
        interpretation = "All evaluated website watchpoints are below warning thresholds."
    elif not comparison:
        status = "NO_COMPARISON"
        interpretation = "Rolling-window comparison is unavailable; elevated 24h values remain authoritative."
    elif missing_delta:
        status = "INCOMPLETE_COMPARISON"
        interpretation = "Some elevated watchpoints lack comparison deltas; elevated 24h values remain authoritative."
    elif incompatible_delta:
        status = "INCOMPATIBLE_COMPARISON"
        interpretation = (
            "Some elevated watchpoint deltas are not comparable because monitor raw-detail grouping coverage "
            "changed between snapshots; elevated 24h values remain authoritative."
        )
    elif high_growth:
        status = "NEW_GROWTH_PRESENT"
        interpretation = "At least one elevated 24h watchpoint is still growing between snapshots."
    else:
        status = "ROLLING_WINDOW_REMAINDER_POSSIBLE"
        interpretation = (
            "Elevated 24h watchpoints show no or minimal new growth between snapshots. This indicates possible "
            "old rolling-window remainder data, but the raw 24h threshold status is not downgraded automatically."
        )

    if status == "ROLLING_WINDOW_REMAINDER_POSSIBLE":
        history_status = history_context.get("status")
        if history_status == "RECENT_SIGNIFICANT_GROWTH":
            status = "RECENT_SIGNIFICANT_GROWTH"
            interpretation = (
                "The latest snapshot delta is small, but multi-snapshot history still shows recent significant "
                "growth for at least one elevated watchpoint."
            )
        elif history_status == "LOW_GROWTH_BUT_NOT_OLD_ENOUGH":
            status = "LOW_GROWTH_BUT_NOT_OLD_ENOUGH"
            interpretation = (
                "Recent successful snapshots show low growth, but there is not yet enough elapsed evidence to "
                "treat elevated 24h totals as old-window leftovers."
            )
        elif history_status == "OLD_WINDOW_REMAINDER_CANDIDATE":
            status = "OLD_WINDOW_REMAINDER_CANDIDATE"
            interpretation = (
                "Multi-snapshot history supports treating elevated 24h totals as old-window remainder candidates."
            )

    return {
        "status": status,
        "interpretation": interpretation,
        "ok_eligible": not elevated or bool(history_context.get("ok_remainder_eligible")),
        "status_policy": (
            "Website overall_status follows raw 24h thresholds. It may become OK only when metrics are below "
            "thresholds, or after a separately proven old-window remainder policy is implemented and evidenced."
        ),
        "source_directory": str(raw_dir),
        "window": {
            "generated_at_utc": meta.get("generated_at_utc"),
            "since_24h_utc": meta.get("since_24h_utc"),
        },
        "comparison": {
            "available": bool(comparison),
            "previous_generated_at_utc": previous_generated,
            "current_generated_at_utc": current_generated,
            "minutes_between": minutes_between,
        },
        "history": history_context,
        "ok_blockers": history_context.get("old_window_blockers", []),
        "metrics_snapshot": {
            key: metrics.get(key)
            for key in (
                "total_5xx",
                "wp_login_503",
                "root_504",
                "oembed_503",
                "oembed_404",
                "app_404",
                "sitelock_top_user_agent_requests",
            )
            if key in metrics
        },
        "elevated_watchpoints": elevated,
    }


def monitor_timestamp(name: str) -> Optional[datetime]:
    if not re.fullmatch(r"\d{8}-\d{6}", name):
        return None
    try:
        return datetime.strptime(name, "%Y%m%d-%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def json_error_summaries(path: Path) -> List[Dict[str, object]]:
    payload = read_json_object(path)
    errors = payload.get("errors") if isinstance(payload.get("errors"), list) else []
    summaries: List[Dict[str, object]] = []
    for error in errors[:3]:
        if not isinstance(error, dict):
            continue
        extensions = error.get("extensions") if isinstance(error.get("extensions"), dict) else {}
        summaries.append(
            {
                "file": path.name,
                "message": safe_cell(error.get("message"), 180),
                "code": safe_cell(extensions.get("code"), 80),
                "timestamp": safe_cell(extensions.get("timestamp"), 80),
            }
        )
    return summaries


def monitor_run_summary(path: Path) -> Dict[str, object]:
    meta = read_json_object(path / "meta.json")
    missing = [name for name in MONITOR_REQUIRED_FILES if not (path / name).exists()]
    errors: List[Dict[str, object]] = []
    for name in MONITOR_REQUIRED_FILES:
        candidate = path / name
        if candidate.exists():
            errors.extend(json_error_summaries(candidate))

    metrics_exists = (path / "metrics.json").exists()
    report_exists = (path / "cloudflare-daily-monitor.md").exists()
    if errors:
        status = "FAILED_GRAPHQL"
    elif missing or not metrics_exists or not report_exists:
        status = "INCOMPLETE"
    else:
        status = "SUCCESS"

    timestamp = monitor_timestamp(path.name)
    return {
        "run_id": path.name,
        "path": str(path),
        "status": status,
        "generated_at_utc": meta.get("generated_at_utc") or (timestamp.isoformat().replace("+00:00", "Z") if timestamp else None),
        "since_24h_utc": meta.get("since_24h_utc"),
        "metrics_exists": metrics_exists,
        "report_exists": report_exists,
        "missing_files": missing,
        "error_count": len(errors),
        "errors": errors[:6],
    }


def build_monitor_attempt_context(report_path: Path) -> Dict[str, object]:
    current_run_dir = report_path.parent.resolve()
    monitor_root = current_run_dir.parent
    latest_path = monitor_root / "latest"
    latest_target = latest_path.resolve() if latest_path.exists() else None

    run_dirs = [
        path
        for path in monitor_root.iterdir()
        if path.is_dir() and monitor_timestamp(path.name) is not None
    ] if monitor_root.exists() else []
    run_dirs.sort(key=lambda path: path.name)

    current_index = next((index for index, path in enumerate(run_dirs) if path.resolve() == current_run_dir), None)
    newer_dirs = run_dirs[current_index + 1 :] if current_index is not None else [
        path for path in run_dirs if path.name > current_run_dir.name
    ]
    newer_summaries = [monitor_run_summary(path) for path in newer_dirs[-5:]]
    current_summary = monitor_run_summary(current_run_dir)
    newest_summary = monitor_run_summary(run_dirs[-1]) if run_dirs else current_summary

    newer_failed = [item for item in newer_summaries if item.get("status") != "SUCCESS"]
    newer_success = [item for item in newer_summaries if item.get("status") == "SUCCESS"]
    latest_points_to_current = bool(latest_target and latest_target == current_run_dir)

    if newer_failed and not newer_success:
        status = "STALE_SUCCESS_NEWER_FAILED_ATTEMPTS"
        interpretation = (
            "The evaluated website report is the last successful monitor snapshot, but newer Cloudflare "
            "GraphQL attempts failed before producing metrics."
        )
    elif newer_success and not latest_points_to_current:
        status = "LATEST_POINTER_STALE"
        interpretation = "A newer successful monitor run exists, but cloudflare-monitor/latest does not point to it."
    elif current_summary.get("status") != "SUCCESS":
        status = "CURRENT_ATTEMPT_INCOMPLETE"
        interpretation = "The evaluated monitor run did not produce a complete successful raw-data set."
    else:
        status = "CURRENT_SUCCESS"
        interpretation = "The evaluated website report is based on the current successful monitor snapshot."

    return {
        "status": status,
        "interpretation": interpretation,
        "evaluated_run": current_summary,
        "newest_attempt": newest_summary,
        "newer_attempt_count": len(newer_dirs),
        "newer_failed_attempt_count": len(newer_failed),
        "newer_success_attempt_count": len(newer_success),
        "newer_attempts": newer_summaries,
        "latest_symlink_target": str(latest_target) if latest_target else None,
        "latest_points_to_evaluated_run": latest_points_to_current,
        "status_policy": (
            "Failed newer monitor attempts do not make stale metrics OK. They are reported as freshness "
            "context until a complete successful monitor snapshot is available."
        ),
    }


def normalize_cf_groups(groups: Sequence[Dict[str, object]], source: str) -> List[Dict[str, object]]:
    normalized: List[Dict[str, object]] = []
    for group in groups:
        dimensions = group.get("dimensions")
        if not isinstance(dimensions, dict):
            dimensions = {}
        count = group.get("count", 0)
        try:
            count_int = int(count)
        except (TypeError, ValueError):
            count_int = 0
        status = parse_status(dimensions.get("edgeResponseStatus"))
        normalized.append(
            {
                "source": source,
                "count": max(count_int, 0),
                "path": decode_path(dimensions.get("clientRequestPath")),
                "status": status,
                "country": safe_cell(dimensions.get("clientCountryName"), 80),
                "user_agent": safe_cell(dimensions.get("userAgent"), 120),
            }
        )
    return normalized


def normalize_cf_groups_detailed(groups: Sequence[Dict[str, object]], source: str) -> List[Dict[str, object]]:
    normalized: List[Dict[str, object]] = []
    for group in groups:
        dimensions = group.get("dimensions")
        if not isinstance(dimensions, dict):
            dimensions = {}
        count = group.get("count", 0)
        try:
            count_int = int(count)
        except (TypeError, ValueError):
            count_int = 0

        normalized.append(
            {
                "source": source,
                "count": max(count_int, 0),
                "path": decode_path(dimensions.get("clientRequestPath")),
                "status": parse_status(dimensions.get("edgeResponseStatus")),
                "country": safe_cell(dimensions.get("clientCountryName"), 80),
                "user_agent": safe_cell(dimensions.get("userAgent"), 160),
                "cache_status": safe_cell(dimensions.get("cacheStatus"), 80).casefold(),
                "host": safe_cell(dimensions.get("clientRequestHTTPHost"), 180).casefold(),
                "security_action": safe_cell(dimensions.get("securityAction"), 80).casefold(),
                "security_source": safe_cell(dimensions.get("securitySource"), 80).casefold(),
            }
        )
    return normalized


def read_origin_pressure_raw(raw_dir: Path) -> Dict[str, List[Dict[str, object]]]:
    raw: Dict[str, List[Dict[str, object]]] = {}
    for source, filename in ORIGIN_PRESSURE_JSON_FILES.items():
        path = raw_dir / filename
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw[source] = []
            continue
        raw[source] = normalize_cf_groups_detailed(extract_cf_groups(payload), source)
    return raw


def row_count(rows: Iterable[Dict[str, object]]) -> int:
    return sum(int(row.get("count", 0)) for row in rows)


def is_5xx_status(status: object) -> bool:
    return isinstance(status, int) and 500 <= status <= 599


def top_counter_items(counter: Counter, key_name: str, limit: int = 5) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for value, count in counter.most_common(limit):
        rows.append({key_name: value, "count": int(count)})
    return rows


def origin_classification_items(counter: Counter, total: int) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for classification in ORIGIN_PRESSURE_CLASSIFICATIONS:
        count = int(counter.get(classification, 0))
        rows.append(
            {
                "classification": classification,
                "count": count,
                "share_of_5xx_total_percent": round((count / total) * 100, 2) if total else None,
            }
        )
    extras = [
        item
        for item in top_counter_items(counter, "classification", limit=20)
        if item.get("classification") not in ORIGIN_PRESSURE_CLASSIFICATIONS
    ]
    for item in extras:
        count = int(item.get("count", 0))
        rows.append(
            {
                "classification": item.get("classification"),
                "count": count,
                "share_of_5xx_total_percent": round((count / total) * 100, 2) if total else None,
            }
        )
    rows.sort(key=lambda item: int(item.get("count", 0)), reverse=True)
    return rows


def cache_status_interpretation(counter: Counter) -> str:
    total = sum(int(value) for value in counter.values())
    if not total:
        return "No detailed cache-status rows are available for 5xx classification."
    hit_count = int(counter.get("hit", 0))
    dynamic_count = int(counter.get("dynamic", 0))
    miss_count = int(counter.get("miss", 0))
    if hit_count:
        return (
            f"{hit_count} detailed 5xx rows are cache-hit shaped; verify whether Cloudflare cache served "
            "stored error responses before treating the rest as origin pressure."
        )
    if dynamic_count or miss_count:
        return (
            "No cache-hit 5xx rows are visible in the detailed snapshot; observed 5xx are dynamic/miss shaped, "
            "which points away from Cloudflare cache-hit errors and toward origin/timeout handling."
        )
    return "Detailed 5xx cache statuses are present but do not match hit/dynamic/miss buckets cleanly."


def build_ok_readiness(
    *,
    results: Sequence[MetricResult],
    correlation_v2_findings: Sequence[CorrelationV2Finding],
    origin_pressure_breakdown: Dict[str, object],
    source_map_404_breakdown: Dict[str, object],
    rolling_window_context: Dict[str, object],
) -> Dict[str, object]:
    direct_status_blockers = [
        {
            "key": result.key,
            "label": result.label,
            "status": result.status,
            "value": result.value,
            "warning": result.warning,
            "critical": result.critical,
            "status_effect": "overall_status_input",
            "reason": result.recommendation if result.status != STATUS_UNKNOWN else result.note,
        }
        for result in results
        if result.status != STATUS_OK
    ]
    history = (
        rolling_window_context.get("history")
        if isinstance(rolling_window_context.get("history"), dict)
        else {}
    )
    low_growth_blockers = (
        history.get("old_window_blockers")
        if isinstance(history.get("old_window_blockers"), list)
        else []
    )

    detail_blockers: List[Dict[str, object]] = []
    origin_unknown = int(origin_pressure_breakdown.get("unclassified_5xx_from_status_aggregate") or 0)
    if origin_unknown:
        detail_blockers.append(
            {
                "key": "origin_5xx_aggregate_detail_gap",
                "label": "5xx aggregate-only detail gap",
                "status": "BLOCKING_EVIDENCE_GAP",
                "value": origin_unknown,
                "status_effect": "ok_readiness_prerequisite",
                "reason": (
                    "status-24h has 5xx requests that are not present in errors-5xx-24h path/cache detail; "
                    "status-only classification is diagnostic and not OK evidence."
                ),
                "status_only_classification": origin_pressure_breakdown.get("status_only_gap_classification", []),
            }
        )
    map_unknown = int(source_map_404_breakdown.get("unclassified_map_404_from_metric") or 0)
    if map_unknown:
        detail_blockers.append(
            {
                "key": "source_map_404_aggregate_detail_gap",
                "label": "Source-map 404 aggregate-only detail gap",
                "status": "BLOCKING_EVIDENCE_GAP",
                "value": map_unknown,
                "status_effect": "ok_readiness_prerequisite",
                "reason": ".map 404 metric has requests without detailed path classification.",
            }
        )

    diagnostic_nonblocking = [
        {
            "signal_id": finding.signal_id,
            "status": finding.status,
            "count": finding.count,
            "status_effect": "diagnostic_only",
            "reason": (
                "Correlation Layer v2 does not directly calculate website overall_status; "
                "use it to explain drivers and action review only."
            ),
            "recommendation": finding.recommendation,
        }
        for finding in correlation_v2_findings
        if finding.status != STATUS_OK
    ]
    ready = not direct_status_blockers and not low_growth_blockers and not detail_blockers
    return {
        "status": "OK_READY" if ready else "NOT_OK_READY",
        "policy": (
            "Website can be OK only when direct metric status is OK, no rolling-window low-growth blockers "
            "remain, and aggregate-only diagnostic gaps no longer require conservative interpretation."
        ),
        "direct_status_blockers": direct_status_blockers,
        "low_growth_blockers": low_growth_blockers,
        "aggregate_detail_blockers": detail_blockers,
        "diagnostic_nonblocking_findings": diagnostic_nonblocking,
        "summary": {
            "direct_status_blocker_count": len(direct_status_blockers),
            "low_growth_blocker_count": len(low_growth_blockers),
            "aggregate_detail_blocker_count": len(detail_blockers),
            "diagnostic_nonblocking_count": len(diagnostic_nonblocking),
        },
    }


def counter_cell(counter: Counter, limit: int = 4) -> str:
    if not counter:
        return "-"
    values = [f"{safe_cell(value, 80)}:{count}" for value, count in counter.most_common(limit)]
    return markdown_list(values, limit=limit)


def user_agent_group(user_agent: object) -> str:
    value = safe_cell(user_agent, 160)
    lowered = value.casefold()
    if not lowered or lowered == "-":
        return "empty_user_agent"
    if "sitelockspider" in lowered:
        return "SiteLockSpider"
    if lowered == "node":
        return "node"
    if "go-http-client" in lowered:
        return "go-http-client"
    scanner_markers = (
        "bot",
        "spider",
        "crawl",
        "scan",
        "curl",
        "wget",
        "python",
        "aiohttp",
        "httpclient",
        "zgrab",
        "masscan",
    )
    if any(marker in lowered for marker in scanner_markers):
        return "scanner_or_bot"
    if lowered.startswith("mozilla/"):
        return "browser_like"
    return safe_cell(value, 60)


def is_scanner_user_agent_group(group: str) -> bool:
    lowered = group.casefold()
    return lowered in {
        "sitelockspider",
        "node",
        "go-http-client",
        "scanner_or_bot",
        "empty_user_agent",
    }


def user_agent_groups_for_error(
    error_row: Dict[str, object],
    user_agent_rows: Sequence[Dict[str, object]],
    limit: int = 4,
) -> List[Dict[str, object]]:
    path = str(error_row.get("path", ""))
    status = error_row.get("status")
    country = str(error_row.get("country", ""))
    match_sets = (
        [
            row
            for row in user_agent_rows
            if row.get("path") == path and row.get("status") == status and str(row.get("country", "")) == country
        ],
        [row for row in user_agent_rows if row.get("path") == path and row.get("status") == status],
        [row for row in user_agent_rows if row.get("path") == path],
    )
    for matches in match_sets:
        counter: Counter = Counter()
        for row in matches:
            counter[user_agent_group(row.get("user_agent"))] += int(row.get("count", 0))
        if counter:
            return top_counter_items(counter, "group", limit=limit)
    return []


def top_path_request_totals(rows: Sequence[Dict[str, object]]) -> Counter:
    counter: Counter = Counter()
    for row in rows:
        path = str(row.get("path", ""))
        if path and path != "-":
            counter[path] += int(row.get("count", 0))
    return counter


def security_actions_by_path(rows: Sequence[Dict[str, object]]) -> Dict[str, Counter]:
    by_path: Dict[str, Counter] = {}
    for row in rows:
        path = str(row.get("path", ""))
        if not path or path == "-":
            continue
        action = safe_cell(row.get("security_action"), 80)
        source = safe_cell(row.get("security_source"), 80)
        status = safe_cell(row.get("status"), 40)
        label = f"{action}/{source}/{status}"
        by_path.setdefault(path, Counter())[label] += int(row.get("count", 0))
    return by_path


def is_scanner_pressure_path(path: str) -> bool:
    lowered = decode_path(path).casefold()
    return is_fake_nextjs_or_secret_path(lowered) or lowered == "/xmlrpc.php" or any(
        marker in lowered for marker in SCANNER_PRESSURE_PATH_MARKERS
    )


def sentinel_combined_rule_coverage(
    path: str,
    hosts: Iterable[object],
    user_agent_groups: Iterable[str],
) -> Dict[str, object]:
    lowered_path = decode_path(path).casefold()
    host_values = {str(host).casefold() for host in hosts if str(host or "-") != "-"}
    ua_values = {group.casefold() for group in user_agent_groups}
    apex_hosts = {APEX_HOST.casefold(), WWW_HOST.casefold()}

    if lowered_path == "/xmlrpc.php":
        return {
            "scope": "covered",
            "covered_by_sentinel_combined_rule": True,
            "actual_5xx_traffic_covered": True,
            "reason": "Combined rule covers exact path /xmlrpc.php.",
        }
    if any(marker in lowered_path for marker in (".env", "phpinfo", "secrets")):
        return {
            "scope": "covered",
            "covered_by_sentinel_combined_rule": True,
            "actual_5xx_traffic_covered": True,
            "reason": "Combined rule covers fake secret/env/phpinfo path markers.",
        }
    if any(marker in lowered_path for marker in ("_next", "__rsc", "__nextjs_action", "api/auth")):
        host_bound = bool(host_values) and host_values.issubset(apex_hosts)
        return {
            "scope": "covered" if host_bound else "conditional_apex_www_host",
            "covered_by_sentinel_combined_rule": True,
            "actual_5xx_traffic_covered": host_bound,
            "reason": (
                "Combined rule covers fake framework paths only on apex/www hostnames."
                if host_bound
                else "Combined rule has a host-bound fake framework branch; current host evidence is incomplete or outside apex/www."
            ),
        }
    if lowered_path == "/wp-login.php":
        actual = "sitelockspider" in ua_values
        return {
            "scope": "covered" if actual else "conditional_sitelockspider",
            "covered_by_sentinel_combined_rule": True,
            "actual_5xx_traffic_covered": actual,
            "reason": (
                "Combined rule covers SiteLockSpider on /wp-login.php."
                if actual
                else "Combined rule covers /wp-login.php only when user-agent contains SiteLockSpider."
            ),
        }
    if is_oembed_path(lowered_path):
        actual = "sitelockspider" in ua_values
        return {
            "scope": "covered" if actual else "conditional_sitelockspider",
            "covered_by_sentinel_combined_rule": True,
            "actual_5xx_traffic_covered": actual,
            "reason": (
                "Combined rule covers SiteLockSpider on oEmbed."
                if actual
                else "Combined rule covers oEmbed only when user-agent contains SiteLockSpider."
            ),
        }
    return {
        "scope": "not_covered",
        "covered_by_sentinel_combined_rule": False,
        "actual_5xx_traffic_covered": False,
        "reason": "Path is not in the current Sentinel combined rule expression.",
    }


def classify_5xx_pressure(row: Dict[str, object], user_agent_groups: Sequence[str]) -> Tuple[str, str]:
    path = str(row.get("path", ""))
    status = row.get("status")
    cache_status = str(row.get("cache_status", "")).casefold()

    if (is_legacy_wp_path(path) or path == "/wp-login.php" or is_oembed_path(path)) and (
        "SiteLockSpider" in user_agent_groups or status == 503 or cache_status == "dynamic"
    ):
        return (
            "likely_wordpress_legacy_pressure",
            "Legacy WordPress path produced 5xx, often with SiteLockSpider or dynamic origin handling.",
        )
    if path == "/" and (status in {500, 503} or cache_status == "dynamic"):
        return (
            "likely_origin_pressure",
            "Public WordPress/root path produced dynamic origin-facing 5xx; actor signal is tracked separately.",
        )
    if is_scanner_pressure_path(path):
        return (
            "likely_scanner_pressure",
            "Path matches fake secret/framework/config/xmlrpc scanner patterns.",
        )
    scanner_actor_groups = [
        group
        for group in user_agent_groups
        if group.casefold() not in {"sitelockspider", "empty_user_agent"} and is_scanner_user_agent_group(group)
    ]
    if scanner_actor_groups:
        return (
            "likely_scanner_pressure",
            "5xx row has scanner-like user-agent evidence in user-agents-24h.json.",
        )
    if status in TIMEOUT_STATUS_CODES or status == 504:
        return (
            "likely_cloudflare_timeout",
            "Gateway-timeout style status indicates Cloudflare waited on or could not reach origin cleanly.",
        )
    if is_legacy_wp_path(path) or path == "/wp-login.php" or is_oembed_path(path):
        return (
            "likely_wordpress_legacy_pressure",
            "WordPress endpoint produced 5xx without enough scanner evidence.",
        )
    if status in {500, 502, 503} or cache_status in {"dynamic", "miss"}:
        return (
            "likely_origin_pressure",
            "Origin-facing 5xx on dynamic/miss cache handling without a specific scanner or WordPress-legacy signature.",
        )
    return "unknown", "Insufficient path/cache/user-agent evidence to classify the 5xx cause."


def classify_5xx_request_shape(row: Dict[str, object], user_agent_groups: Sequence[str]) -> Tuple[str, str]:
    path = str(row.get("path", ""))
    if is_scanner_pressure_path(path):
        return "scanner_or_probe_shape", "Path matches fake secret/framework/config/probe scanner patterns."
    if is_legacy_wp_path(path) or path == "/wp-login.php" or is_oembed_path(path):
        return "wordpress_or_legacy_shape", "Path is a WordPress or legacy endpoint."
    if path == "/" or path.startswith("/wp-content/") or path.startswith("/wp-admin/"):
        return "wordpress_or_legacy_shape", "Path belongs to the WordPress/public site surface."
    return "generic_origin_shape", "Path is not scanner-shaped or a known WordPress legacy endpoint."


def classify_5xx_actor_signal(user_agent_groups: Sequence[str]) -> Tuple[str, str]:
    normalized = {group.casefold() for group in user_agent_groups}
    if "sitelockspider" in normalized:
        return "sitelockspider_actor", "User-agent grouping includes SiteLockSpider."
    if "browser_like" in normalized:
        return "browser_like_actor", "User-agent grouping is browser-like."
    if "nginx-ssl early hints" in normalized:
        return "nginx_early_hints_actor", "User-agent grouping is nginx-ssl early hints."
    if "empty_user_agent" in normalized:
        return "empty_user_agent_actor", "User-agent grouping is empty or unavailable."
    scanner_groups = sorted(group for group in user_agent_groups if is_scanner_user_agent_group(group))
    if scanner_groups:
        return "scanner_or_bot_actor", "User-agent grouping is scanner/bot-like: " + ", ".join(scanner_groups[:3])
    if user_agent_groups:
        return "other_user_agent_actor", "User-agent grouping is present but not scanner-specific."
    return "unknown_actor_signal", "No matching user-agent detail row is available for this 5xx group."


def classify_5xx_failure_mode(row: Dict[str, object]) -> Tuple[str, str]:
    status = row.get("status")
    cache_status = str(row.get("cache_status", "")).casefold()
    if status == 504:
        return "cloudflare_to_origin_timeout", "504 indicates Cloudflare waited on or could not complete origin handling."
    if status in TIMEOUT_STATUS_CODES:
        return "cloudflare_edge_or_origin_connectivity", "Cloudflare-specific 5xx status indicates edge/origin connectivity handling."
    if status in {500, 502, 503}:
        return "origin_php_or_upstream_error", "500/502/503 on dynamic or miss traffic points at origin/PHP/upstream handling."
    if cache_status == "hit":
        return "cloudflare_cached_error", "5xx row is cache-hit shaped."
    return "unknown_failure_mode", "Insufficient status/cache evidence to classify failure mode."


def classify_status_only_5xx_gap(status: object) -> Tuple[str, str]:
    if status == 504:
        return (
            "likely_cloudflare_timeout",
            "Only status-24h aggregate detail is available; 504 is timeout/Cloudflare-to-origin shaped.",
        )
    if status in TIMEOUT_STATUS_CODES:
        return (
            "likely_cloudflare_timeout",
            "Only status-24h aggregate detail is available; the status is Cloudflare edge/origin connectivity shaped.",
        )
    if status in {500, 502, 503}:
        return (
            "likely_origin_pressure",
            "Only status-24h aggregate detail is available; the status points at origin-side error handling.",
        )
    return "unknown", "Only status-24h aggregate detail is available and the status has no safer classification."


def build_origin_pressure_breakdown(
    report_path: Path,
    results: Sequence[MetricResult],
) -> Dict[str, object]:
    raw_dir = report_path.parent
    raw = read_origin_pressure_raw(raw_dir)
    errors = [row for row in raw.get("errors_5xx", []) if is_5xx_status(row.get("status"))]
    user_agent_5xx_rows = [
        row for row in raw.get("user_agents", []) if is_5xx_status(row.get("status"))
    ]
    status_counter: Counter = Counter()
    for row in raw.get("status", []):
        status = row.get("status")
        if is_5xx_status(status):
            status_counter[status] += int(row.get("count", 0))
    if not status_counter:
        for row in errors:
            status_counter[row.get("status")] += int(row.get("count", 0))

    report_total_5xx = metric_value(results, "total_5xx")
    status_total_5xx = sum(status_counter.values()) if status_counter else None
    authoritative_total_5xx = status_total_5xx if status_total_5xx is not None else report_total_5xx

    top_path_totals = top_path_request_totals(raw.get("top_paths", []))
    path_security_actions = security_actions_by_path(raw.get("security_actions", []))
    country_counter: Counter = Counter()
    cache_counter: Counter = Counter()
    user_agent_group_counter: Counter = Counter()
    detail_status_counter: Counter = Counter()
    request_shape_counter: Counter = Counter()
    actor_signal_counter: Counter = Counter()
    failure_mode_counter: Counter = Counter()
    user_agent_groups_by_path: Dict[str, Counter] = {}
    classification_counter: Counter = Counter()
    path_groups: Dict[str, Dict[str, object]] = {}

    for row in user_agent_5xx_rows:
        count = int(row.get("count", 0))
        group_name = user_agent_group(row.get("user_agent"))
        user_agent_group_counter[group_name] += count
        path = str(row.get("path", ""))
        if path and path != "-":
            user_agent_groups_by_path.setdefault(path, Counter())[group_name] += count

    observed_error_count = row_count(errors)
    detail_coverage_percent = (
        round((observed_error_count / int(authoritative_total_5xx)) * 100, 2)
        if authoritative_total_5xx
        else None
    )
    for row in errors:
        count = int(row.get("count", 0))
        path = str(row.get("path", "-"))
        host = str(row.get("host", "-"))
        status = row.get("status")
        country = str(row.get("country", "-"))
        cache_status = str(row.get("cache_status", "-"))
        ua_groups = user_agent_groups_for_error(row, user_agent_5xx_rows)
        ua_group_names = [str(item.get("group", "")) for item in ua_groups if item.get("group")]
        classification, reason = classify_5xx_pressure(row, ua_group_names)
        request_shape, request_shape_reason = classify_5xx_request_shape(row, ua_group_names)
        actor_signal, actor_signal_reason = classify_5xx_actor_signal(ua_group_names)
        failure_mode, failure_mode_reason = classify_5xx_failure_mode(row)
        coverage = sentinel_combined_rule_coverage(path, [host], ua_group_names)

        classification_counter[classification] += count
        request_shape_counter[request_shape] += count
        actor_signal_counter[actor_signal] += count
        failure_mode_counter[failure_mode] += count
        country_counter[country] += count
        cache_counter[cache_status] += count
        detail_status_counter[status] += count

        group = path_groups.setdefault(
            path,
            {
                "count": 0,
                "hosts": Counter(),
                "statuses": Counter(),
                "countries": Counter(),
                "cache_status": Counter(),
                "classifications": Counter(),
                "classification_reasons": Counter(),
                "request_shapes": Counter(),
                "request_shape_reasons": Counter(),
                "actor_signals": Counter(),
                "actor_signal_reasons": Counter(),
                "failure_modes": Counter(),
                "failure_mode_reasons": Counter(),
                "coverage_scopes": Counter(),
                "coverage_reasons": Counter(),
                "actual_covered_count": 0,
            },
        )
        group["count"] = int(group["count"]) + count
        group["hosts"][host] += count
        group["statuses"][status] += count
        group["countries"][country] += count
        group["cache_status"][cache_status] += count
        group["classifications"][classification] += count
        group["classification_reasons"][reason] += count
        group["request_shapes"][request_shape] += count
        group["request_shape_reasons"][request_shape_reason] += count
        group["actor_signals"][actor_signal] += count
        group["actor_signal_reasons"][actor_signal_reason] += count
        group["failure_modes"][failure_mode] += count
        group["failure_mode_reasons"][failure_mode_reason] += count
        group["coverage_scopes"][coverage.get("scope")] += count
        group["coverage_reasons"][coverage.get("reason")] += count
        if coverage.get("actual_5xx_traffic_covered"):
            group["actual_covered_count"] = int(group["actual_covered_count"]) + count

    unclassified_from_status = 0
    if authoritative_total_5xx is not None:
        unclassified_from_status = max(int(authoritative_total_5xx) - observed_error_count, 0)
        if unclassified_from_status:
            classification_counter["unknown"] += unclassified_from_status
    unknown_share_percent = (
        round((unclassified_from_status / int(authoritative_total_5xx)) * 100, 2)
        if authoritative_total_5xx
        else None
    )
    status_detail_gap: List[Dict[str, object]] = []
    status_only_gap_counter: Counter = Counter()
    for status, status_count in status_counter.most_common():
        detailed_count = int(detail_status_counter.get(status, 0))
        gap_count = max(int(status_count) - detailed_count, 0)
        gap_classification, gap_reason = classify_status_only_5xx_gap(status)
        if gap_count:
            status_only_gap_counter[gap_classification] += gap_count
        status_detail_gap.append(
            {
                "status": status,
                "status_24h_count": int(status_count),
                "detailed_count": detailed_count,
                "unclassified_count": gap_count,
                "detail_coverage_percent": round((detailed_count / int(status_count)) * 100, 2)
                if status_count
                else None,
                "status_only_classification": gap_classification,
                "status_only_reason": gap_reason,
            }
        )
    detail_rows_likely_limited = bool(unclassified_from_status and len(errors) >= 30)
    if detail_rows_likely_limited:
        detail_completeness_status = "DETAIL_ROWS_LIMITED"
        largest_gap = next((item for item in status_detail_gap if int(item.get("unclassified_count", 0)) > 0), None)
        largest_gap_text = (
            f" Largest status gap: {largest_gap.get('status')} has "
            f"{largest_gap.get('unclassified_count')} aggregate-only requests."
            if largest_gap
            else ""
        )
        diagnostic_gap = (
            f"errors-5xx-24h.json contains {len(errors)} grouped rows covering "
            f"{observed_error_count} of {authoritative_total_5xx} status-24h 5xx requests. "
            "The remaining aggregate 5xx count cannot be path/cache classified from this snapshot."
            + largest_gap_text
        )
    elif unclassified_from_status:
        detail_completeness_status = "DETAIL_ROWS_INCOMPLETE"
        diagnostic_gap = (
            f"Detailed grouped rows cover {observed_error_count} of {authoritative_total_5xx} "
            "status-24h 5xx requests."
        )
    else:
        detail_completeness_status = "DETAIL_ROWS_COVER_STATUS_TOTAL"
        diagnostic_gap = "Detailed grouped 5xx rows cover the status-24h 5xx total."

    top_paths: List[Dict[str, object]] = []
    for path, group in sorted(path_groups.items(), key=lambda item: int(item[1].get("count", 0)), reverse=True)[:10]:
        classifications = group["classifications"]
        coverage_scopes = group["coverage_scopes"]
        ua_counter = user_agent_groups_by_path.get(path, Counter())
        dominant_classification = classifications.most_common(1)[0][0] if classifications else "unknown"
        dominant_reason = group["classification_reasons"].most_common(1)[0][0] if group["classification_reasons"] else "-"
        request_shapes = group["request_shapes"]
        actor_signals = group["actor_signals"]
        failure_modes = group["failure_modes"]
        dominant_request_shape = request_shapes.most_common(1)[0][0] if request_shapes else "unknown"
        dominant_request_shape_reason = (
            group["request_shape_reasons"].most_common(1)[0][0] if group["request_shape_reasons"] else "-"
        )
        dominant_actor_signal = actor_signals.most_common(1)[0][0] if actor_signals else "unknown"
        dominant_actor_signal_reason = (
            group["actor_signal_reasons"].most_common(1)[0][0] if group["actor_signal_reasons"] else "-"
        )
        dominant_failure_mode = failure_modes.most_common(1)[0][0] if failure_modes else "unknown"
        dominant_failure_mode_reason = (
            group["failure_mode_reasons"].most_common(1)[0][0] if group["failure_mode_reasons"] else "-"
        )
        coverage_scope = coverage_scopes.most_common(1)[0][0] if coverage_scopes else "not_covered"
        coverage_reason = group["coverage_reasons"].most_common(1)[0][0] if group["coverage_reasons"] else "-"
        top_paths.append(
            {
                "path": path,
                "count": int(group["count"]),
                "hostnames": [item["host"] for item in top_counter_items(group["hosts"], "host", limit=3)],
                "statuses": top_counter_items(group["statuses"], "status", limit=5),
                "countries": top_counter_items(group["countries"], "country", limit=5),
                "cache_status": top_counter_items(group["cache_status"], "cache_status", limit=5),
                "user_agent_groups": top_counter_items(ua_counter, "group", limit=5),
                "classification": dominant_classification,
                "classification_counts": top_counter_items(group["classifications"], "classification", limit=5),
                "classification_reason": dominant_reason,
                "request_shape": dominant_request_shape,
                "request_shape_counts": top_counter_items(group["request_shapes"], "request_shape", limit=5),
                "request_shape_reason": dominant_request_shape_reason,
                "actor_signal": dominant_actor_signal,
                "actor_signal_counts": top_counter_items(group["actor_signals"], "actor_signal", limit=5),
                "actor_signal_reason": dominant_actor_signal_reason,
                "failure_mode": dominant_failure_mode,
                "failure_mode_counts": top_counter_items(group["failure_modes"], "failure_mode", limit=5),
                "failure_mode_reason": dominant_failure_mode_reason,
                "combined_rule_scope": coverage_scope,
                "covered_by_sentinel_combined_rule": coverage_scope != "not_covered",
                "actual_5xx_traffic_covered_by_combined_rule": int(group["actual_covered_count"]) > 0,
                "actual_covered_count": int(group["actual_covered_count"]),
                "combined_rule_reason": coverage_reason,
                "security_actions_24h": top_counter_items(
                    path_security_actions.get(path, Counter()), "action", limit=5
                ),
                "top_paths_24h_request_count": int(top_path_totals[path]) if path in top_path_totals else None,
            }
        )

    total_for_share = authoritative_total_5xx or sum(classification_counter.values()) or 0
    classification_counts = origin_classification_items(classification_counter, int(total_for_share))
    status_inclusive_classification_counter = Counter(classification_counter)
    if unclassified_from_status:
        status_inclusive_classification_counter["unknown"] -= unclassified_from_status
        if status_inclusive_classification_counter["unknown"] <= 0:
            del status_inclusive_classification_counter["unknown"]
        status_inclusive_classification_counter.update(status_only_gap_counter)
    status_inclusive_classification_counts = origin_classification_items(
        status_inclusive_classification_counter, int(total_for_share)
    )

    dominant = max(classification_counts, key=lambda item: int(item.get("count", 0))) if classification_counts else {}
    dominant_name = dominant.get("classification", "unknown")
    if dominant_name == "unknown" and unclassified_from_status:
        interpretation = (
            "Website remains CRITICAL because status-24h shows more 5xx than the path/cache detail rows can "
            "attribute; the missing detailed rows stay unknown until deeper raw detail or full low-growth 24h "
            "evidence proves otherwise."
        )
    elif dominant_name == "likely_cloudflare_timeout":
        interpretation = (
            "Top detailed 5xx rows are dominated by timeout-style responses, pointing at Cloudflare-to-origin "
            "waiting/reachability rather than a cache hit problem."
        )
    elif dominant_name == "likely_wordpress_legacy_pressure":
        interpretation = (
            "Top detailed 5xx rows are concentrated on legacy WordPress paths, suggesting WordPress/PHP or "
            "legacy-route origin handling is still involved."
        )
    elif dominant_name == "likely_scanner_pressure":
        interpretation = (
            "Top detailed 5xx rows are mostly scanner-shaped, but the overall status is not downgraded without "
            "24h low-growth evidence."
        )
    else:
        interpretation = (
            "Top detailed 5xx rows indicate origin-facing pressure, but no single more specific driver dominates."
        )

    return {
        "status": "DIAGNOSTIC_ONLY",
        "source_directory": str(raw_dir),
        "source_files": {
            source: {
                "file": filename,
                "exists": (raw_dir / filename).exists(),
                "row_count": len(raw.get(source, [])),
                "request_count": row_count(raw.get(source, [])),
            }
            for source, filename in ORIGIN_PRESSURE_JSON_FILES.items()
        },
        "report_total_5xx": report_total_5xx,
        "status_24h_total_5xx": int(status_total_5xx) if status_total_5xx is not None else None,
        "observed_5xx_detail_count": observed_error_count,
        "detail_coverage_percent": detail_coverage_percent,
        "unclassified_5xx_from_status_aggregate": unclassified_from_status,
        "unknown_share_percent": unknown_share_percent,
        "detail_completeness_status": detail_completeness_status,
        "diagnostic_gap": diagnostic_gap,
        "classification_scope": (
            "Detailed path/cache/country classification uses errors-5xx-24h.json top grouped rows. "
            "status-24h.json remains authoritative for the total 5xx count."
        ),
        "status_inclusive_classification_scope": (
            "Diagnostic-only rollup: detailed row classifications plus conservative status-only mapping for "
            "aggregate 5xx not present in errors-5xx-24h.json. This improves cause direction but is not proof "
            "that the aggregate-only rows are resolved or OK."
        ),
        "interpretation": interpretation,
        "status_policy": (
            "Diagnostic only. This section does not change thresholds or make the website OK; "
            "RECENT_SIGNIFICANT_GROWTH or missing 24h low-growth evidence remains CRITICAL."
        ),
        "top_5xx_paths": top_paths,
        "top_5xx_status_codes": top_counter_items(status_counter, "status", limit=10),
        "status_detail_gap": status_detail_gap,
        "status_only_gap_classification": top_counter_items(
            status_only_gap_counter, "classification", limit=10
        ),
        "top_5xx_countries": top_counter_items(country_counter, "country", limit=10),
        "top_5xx_cache_status": top_counter_items(cache_counter, "cache_status", limit=10),
        "cache_status_interpretation": cache_status_interpretation(cache_counter),
        "top_5xx_user_agent_groups": top_counter_items(user_agent_group_counter, "group", limit=10),
        "top_5xx_classification": classification_counts,
        "top_5xx_status_inclusive_classification": status_inclusive_classification_counts,
        "top_5xx_request_shapes": top_counter_items(request_shape_counter, "request_shape", limit=10),
        "top_5xx_actor_signals": top_counter_items(actor_signal_counter, "actor_signal", limit=10),
        "top_5xx_failure_modes": top_counter_items(failure_mode_counter, "failure_mode", limit=10),
        "sentinel_combined_rule_coverage": [
            {
                "path": item.get("path"),
                "count": item.get("count"),
                "combined_rule_scope": item.get("combined_rule_scope"),
                "covered_by_sentinel_combined_rule": item.get("covered_by_sentinel_combined_rule"),
                "actual_5xx_traffic_covered_by_combined_rule": item.get(
                    "actual_5xx_traffic_covered_by_combined_rule"
                ),
                "actual_covered_count": item.get("actual_covered_count"),
                "reason": item.get("combined_rule_reason"),
                "security_actions_24h": item.get("security_actions_24h"),
            }
            for item in top_paths
        ],
    }


def is_source_map_path(path: object) -> bool:
    return ".map" in decode_path(path).casefold()


def classify_source_map_404(path: str, user_agent_groups: Sequence[str]) -> Tuple[str, str]:
    lowered = decode_path(path).casefold()
    if "wpo-minify" in lowered or "/wp-content/cache/" in lowered:
        return (
            "likely_wordpress_minify_source_map_reference",
            "WordPress cache/minify asset source-map path is requested by browser-like traffic.",
        )
    if "/wp-includes/" in lowered or "/wp-admin/" in lowered:
        return (
            "likely_wordpress_core_source_map_reference",
            "WordPress core/admin source-map path is requested and missing.",
        )
    if "_next" in lowered or any(marker in lowered for marker in ("/app.js.map", "/main.js.map", "/runtime.js.map", "/chunks.js.map")):
        return (
            "likely_scanner_or_framework_probe",
            "Path is a fake framework/generic JavaScript source-map probe on a WordPress host.",
        )
    if any(is_scanner_user_agent_group(group) for group in user_agent_groups):
        return (
            "likely_scanner_or_framework_probe",
            "404 source-map row has scanner-like user-agent evidence.",
        )
    if lowered.endswith(".map"):
        return (
            "likely_static_asset_source_map_reference",
            "A source-map file is referenced but not present in the current published asset set.",
        )
    return "unknown", "Insufficient path and user-agent evidence to classify this source-map 404."


def build_source_map_404_breakdown(
    report_path: Path,
    results: Sequence[MetricResult],
) -> Dict[str, object]:
    raw_dir = report_path.parent
    raw = read_origin_pressure_raw(raw_dir)
    notfound_rows = [row for row in raw.get("notfound_404", []) if is_source_map_path(row.get("path"))]
    user_agent_rows = [
        row
        for row in raw.get("user_agents", [])
        if row.get("status") == 404 and is_source_map_path(row.get("path"))
    ]
    metric_total = metric_value(results, "map_404")
    observed_count = row_count(notfound_rows)
    authoritative_total = metric_total if metric_total is not None else observed_count
    unknown_count = max(int(authoritative_total) - observed_count, 0) if authoritative_total is not None else 0
    coverage_percent = (
        round((observed_count / int(authoritative_total)) * 100, 2)
        if authoritative_total
        else None
    )
    unknown_share_percent = (
        round((unknown_count / int(authoritative_total)) * 100, 2)
        if authoritative_total
        else None
    )

    path_groups: Dict[str, Dict[str, object]] = {}
    classification_counter: Counter = Counter()
    cache_counter: Counter = Counter()
    user_agent_group_counter: Counter = Counter()
    country_counter: Counter = Counter()
    user_agent_groups_by_path: Dict[str, Counter] = {}

    for row in user_agent_rows:
        count = int(row.get("count", 0))
        group_name = user_agent_group(row.get("user_agent"))
        path = str(row.get("path", ""))
        user_agent_group_counter[group_name] += count
        if path and path != "-":
            user_agent_groups_by_path.setdefault(path, Counter())[group_name] += count

    for row in notfound_rows:
        count = int(row.get("count", 0))
        path = str(row.get("path", "-"))
        host = str(row.get("host", "-"))
        country = str(row.get("country", "-"))
        cache_status = str(row.get("cache_status", "-"))
        ua_counter = user_agent_groups_by_path.get(path, Counter())
        ua_groups = [str(group) for group, _count in ua_counter.most_common(5)]
        classification, reason = classify_source_map_404(path, ua_groups)
        coverage = sentinel_combined_rule_coverage(path, [host], ua_groups)

        classification_counter[classification] += count
        cache_counter[cache_status] += count
        country_counter[country] += count

        group = path_groups.setdefault(
            path,
            {
                "count": 0,
                "hosts": Counter(),
                "countries": Counter(),
                "cache_status": Counter(),
                "user_agent_groups": Counter(),
                "classifications": Counter(),
                "classification_reasons": Counter(),
                "coverage_scopes": Counter(),
                "coverage_reasons": Counter(),
            },
        )
        group["count"] = int(group["count"]) + count
        group["hosts"][host] += count
        group["countries"][country] += count
        group["cache_status"][cache_status] += count
        group["classifications"][classification] += count
        group["classification_reasons"][reason] += count
        group["coverage_scopes"][coverage.get("scope")] += count
        group["coverage_reasons"][coverage.get("reason")] += count
        for group_name, group_count in ua_counter.items():
            group["user_agent_groups"][group_name] += int(group_count)

    if unknown_count:
        classification_counter["unknown"] += unknown_count

    top_paths: List[Dict[str, object]] = []
    for path, group in sorted(path_groups.items(), key=lambda item: int(item[1].get("count", 0)), reverse=True)[:10]:
        classifications = group["classifications"]
        dominant_classification = classifications.most_common(1)[0][0] if classifications else "unknown"
        dominant_reason = group["classification_reasons"].most_common(1)[0][0] if group["classification_reasons"] else "-"
        coverage_scope = group["coverage_scopes"].most_common(1)[0][0] if group["coverage_scopes"] else "not_covered"
        coverage_reason = group["coverage_reasons"].most_common(1)[0][0] if group["coverage_reasons"] else "-"
        top_paths.append(
            {
                "path": path,
                "count": int(group["count"]),
                "hostnames": [item["host"] for item in top_counter_items(group["hosts"], "host", limit=3)],
                "countries": top_counter_items(group["countries"], "country", limit=5),
                "cache_status": top_counter_items(group["cache_status"], "cache_status", limit=5),
                "user_agent_groups": top_counter_items(group["user_agent_groups"], "group", limit=5),
                "classification": dominant_classification,
                "classification_counts": top_counter_items(group["classifications"], "classification", limit=5),
                "classification_reason": dominant_reason,
                "combined_rule_scope": coverage_scope,
                "covered_by_sentinel_combined_rule": coverage_scope != "not_covered",
                "combined_rule_reason": coverage_reason,
            }
        )

    total_for_share = int(authoritative_total or sum(classification_counter.values()) or 0)
    classification_counts = []
    for item in top_counter_items(classification_counter, "classification", limit=10):
        count = int(item.get("count", 0))
        classification_counts.append(
            {
                "classification": item.get("classification"),
                "count": count,
                "share_of_map_404_total_percent": round((count / total_for_share) * 100, 2) if total_for_share else None,
            }
        )

    if not notfound_rows:
        interpretation = "No source-map 404 detail rows are visible in notfound-404-24h.json."
    elif classification_counter.get("likely_wordpress_minify_source_map_reference", 0):
        interpretation = (
            "Source-map 404s include WordPress cache/minify assets requested by browser-like traffic; "
            "this points to stale asset sourceMappingURL references rather than origin 5xx pressure."
        )
    elif classification_counter.get("likely_scanner_or_framework_probe", 0):
        interpretation = "Source-map 404s are dominated by scanner or fake framework probes."
    else:
        interpretation = "Source-map 404s are visible, but no single detailed driver dominates."

    detail_status = "DETAIL_ROWS_COVER_METRIC" if unknown_count == 0 else "DETAIL_ROWS_LIMITED"
    return {
        "status": "DIAGNOSTIC_ONLY",
        "source_directory": str(raw_dir),
        "map_404_total": int(authoritative_total or 0),
        "observed_map_404_detail_count": observed_count,
        "detail_coverage_percent": coverage_percent,
        "unclassified_map_404_from_metric": unknown_count,
        "unknown_share_percent": unknown_share_percent,
        "detail_completeness_status": detail_status,
        "interpretation": interpretation,
        "status_policy": (
            "Diagnostic only. This section does not change thresholds or make the website OK; "
            "source-map 404 remains WARNING until the 24h value is below threshold or old-window evidence is complete."
        ),
        "top_map_404_paths": top_paths,
        "top_map_404_cache_status": top_counter_items(cache_counter, "cache_status", limit=10),
        "top_map_404_countries": top_counter_items(country_counter, "country", limit=10),
        "top_map_404_user_agent_groups": top_counter_items(user_agent_group_counter, "group", limit=10),
        "top_map_404_classification": classification_counts,
    }


# --- 404 Path Priority Breakdown ---

PATH_PRIORITY_SCANNER_MARKERS = (
    "/vendor/phpunit",
    "/phpunit",
    "/.env",
    "/_profiler",
    "/config/",
    "/aws/",
    "/actuator",
    "/dockerfile",
    "/gitlab",
    "/.git/",
    "/.github/",
    "/server-info",
    "/swagger",
    "/vagrantfile",
    "/metrics",
    "/healthcheck",
    "/horizon",
    "/sysadmin",
    "/rest/executions",
    "/package-updates",
    "/log-viewer",
    "/stripe",
    "/bucket",
    "/amplify/",
    "/login/",
    "/api/trpc",
    "/admin.html",
    "/version.php",
    "/php_info",
    "/phpversion",
    "_next",
    "__rsc",
    "__nextjs_action",
    "api/auth",
    ".php.suspected",
    "/db.php",
    "/up.php",
    "/apikey.php",
    "/apismtp.php",
    "/wp-content/plugins/fix/",
    "/wp-content/themes/seotheme/",
    "/wp-content/plugins/apikey/",
    "/wp-content/plugins/content/apismtp/",
)

PATH_PRIORITY_HISTORICAL_PATHS = {
    "/": {404, 503},
    "/robots.txt": {429},
}


CLASSIFICATION_PRIORITY = (
    "action_candidate",
    "intentional_gone",
    "scanner_noise",
    "historical_temporary",
    "oembed_head_400",
    "unknown",
)


def classify_notfound_path(path: str, status: object, method: str = "") -> Tuple[str, str]:
    lowered_path = decode_path(path).casefold()
    status_int = parse_status(status) or 0
    method_upper = str(method).upper()

    if any(marker in lowered_path for marker in PATH_PRIORITY_SCANNER_MARKERS):
        return "scanner_noise", "Scanner/Framework-Probe, keine produktive Relevanz."

    if "/hello-world" in lowered_path:
        return "intentional_gone", "WordPress Default-Post bewusst entfernt; 410 ist korrekt."

    if "/page/2/" in lowered_path and status_int == 404:
        return "action_candidate", "Potentiell echte Archivseite; interne Verlinkung pruefen."

    if lowered_path in PATH_PRIORITY_HISTORICAL_PATHS and status_int in PATH_PRIORITY_HISTORICAL_PATHS[lowered_path]:
        return "historical_temporary", "Historisch temporärer Fehler; live aktuell wahrscheinlich OK."

    if is_oembed_path(lowered_path) and status_int == 400 and method_upper == "HEAD":
        return "oembed_head_400", "oEmbed HEAD 400 ist kein automatischer HIGH-Kandidat."

    return "unknown", "Keine spezifische Klassifizierung vorhanden."


def check_internal_link_to_page2(timeout: int = 10) -> Dict[str, object]:
    result: Dict[str, object] = {
        "linked": False,
        "found_on_pages": [],
        "checked_urls": [],
        "error": None,
    }
    urls_to_check = [
        "https://www.electri-c-ity-studios-24-7.com/",
        "https://electri-c-ity-studios-24-7.com/",
    ]
    for url in urls_to_check:
        result["checked_urls"].append(url)
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "SentinelDefense-Bot/1.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                html = resp.read().decode("utf-8", errors="replace")
                patterns = ('href="/page/2/"', "href='/page/2/'", 'href="\\"/page/2/\\""')
                if any(p in html for p in patterns):
                    result["linked"] = True
                    result["found_on_pages"].append(url)
        except Exception as exc:
            if not result["error"]:
                result["error"] = str(exc)
    return result


def build_notfound_404_path_breakdown(
    report_path: Path,
    results: Sequence[MetricResult],
) -> Dict[str, object]:
    raw_dir = report_path.parent
    raw = read_origin_pressure_raw(raw_dir)

    relevant_rows: List[Dict[str, object]] = []
    for row in raw.get("notfound_404", []):
        row = dict(row)
        if row.get("status") is None:
            row["status"] = 404
        if row.get("status") in {404, 410}:
            relevant_rows.append(row)
    for row in raw.get("errors_5xx", []):
        if row.get("status") in {503, 504}:
            relevant_rows.append(row)
    for row in raw.get("user_agents", []):
        if row.get("status") in {429, 404, 410, 503, 504}:
            relevant_rows.append(row)

    path_groups: Dict[str, Dict[str, object]] = {}
    classification_counter: Counter = Counter()
    status_counter: Counter = Counter()
    total_count = 0

    for row in relevant_rows:
        count = int(row.get("count", 0))
        path = str(row.get("path", "-"))
        status = row.get("status")
        method = str(row.get("method", ""))
        classification, reason = classify_notfound_path(path, status, method)

        classification_counter[classification] += count
        status_counter[status] += count
        total_count += count

        group = path_groups.setdefault(
            path,
            {
                "count": 0,
                "statuses": Counter(),
                "classifications": Counter(),
                "classification_reasons": Counter(),
            },
        )
        group["count"] = int(group["count"]) + count
        group["statuses"][status] += count
        group["classifications"][classification] += count
        group["classification_reasons"][reason] += count

    top_paths: List[Dict[str, object]] = []
    for path, group in sorted(path_groups.items(), key=lambda item: int(item[1].get("count", 0)), reverse=True)[:20]:
        classifications = group["classifications"]
        if classifications:
            dominant_classification = min(
                (cls for cls in classifications if cls in CLASSIFICATION_PRIORITY),
                key=lambda cls: CLASSIFICATION_PRIORITY.index(cls),
            )
        else:
            dominant_classification = "unknown"
        reason_counter = group["classification_reasons"]
        dominant_reason = "-"
        if reason_counter:
            for reason, _count in reason_counter.most_common():
                if dominant_classification in str(reason).lower() or dominant_classification == "unknown":
                    dominant_reason = reason
                    break
            if dominant_reason == "-":
                dominant_reason = reason_counter.most_common(1)[0][0]
        top_paths.append(
            {
                "path": path,
                "count": int(group["count"]),
                "statuses": top_counter_items(group["statuses"], "status", limit=5),
                "classification": dominant_classification,
                "classification_reason": dominant_reason,
            }
        )

    classification_counts = []
    for item in top_counter_items(classification_counter, "classification", limit=10):
        count = int(item.get("count", 0))
        classification_counts.append(
            {
                "classification": item.get("classification"),
                "count": count,
                "share_of_total_percent": round((count / total_count) * 100, 2) if total_count else None,
            }
        )

    page2_check = check_internal_link_to_page2()

    return {
        "status": "DIAGNOSTIC_ONLY",
        "source_directory": str(raw_dir),
        "total_relevant_requests": total_count,
        "detail_completeness_status": "DETAIL_ROWS_COVER_METRIC",
        "top_paths": top_paths,
        "classification_counts": classification_counts,
        "page2_internal_link_check": page2_check,
        "interpretation": (
            "404/410/429/503 Pfade wurden nach Prioritaet klassifiziert. "
            "Scanner-Rauschen und bewusst entfernte Inhalte sind als solche markiert."
        ),
    }


def markdown_notfound_404_path_breakdown(breakdown: Dict[str, object]) -> str:
    lines = [
        "## 404 Path Priority Breakdown",
        "",
        (
            "Diese Diagnose klassifiziert 404-/410-/429-/503-Pfade nach operativer Relevanz. "
            "Es werden keine Cloudflare-Regeln oder Redirects automatisch gesetzt."
        ),
        "",
        f"- Relevante Requests gesamt: `{breakdown.get('total_relevant_requests')}`",
        "",
        "### Klassifizierung",
        "",
        "| Kategorie | Anzahl | Anteil |",
        "|---|---|---:|",
    ]
    for item in breakdown.get("classification_counts", []):
        classification = safe_cell(item.get("classification"), 40)
        count = safe_cell(item.get("count"), 20)
        share = safe_cell(item.get("share_of_total_percent"), 20)
        lines.append(f"| {classification} | {count} | {share}% |")

    lines.extend(["", "### Top Pfade", "", "| Pfad | Anzahl | Status | Klassifizierung |", "|---|---|---|---|"])
    for item in breakdown.get("top_paths", []):
        path = safe_cell(item.get("path"), 60)
        count = safe_cell(item.get("count"), 10)
        statuses = ", ".join(str(s.get("status")) for s in item.get("statuses", []))
        classification = safe_cell(item.get("classification"), 30)
        lines.append(f"| {path} | {count} | {statuses} | {classification} |")

    page2 = breakdown.get("page2_internal_link_check")
    if page2:
        lines.extend(["", "### /page/2/ Live-Check"])
        if page2.get("linked"):
            lines.append(
                "- `/page/2/` ist **intern verlinkt** auf: " + ", ".join(page2.get("found_on_pages", []))
            )
            lines.append(
                "- Empfehlung: 301 Redirect auf `/` oder WordPress Blog-Archivpagination pruefen."
            )
        else:
            lines.append("- `/page/2/` ist aktuell **nicht intern verlinkt**.")
        if page2.get("error"):
            lines.append(f"- Hinweis: Live-Check fehlgeschlagen: `{safe_cell(page2['error'], 120)}`")

    hello_rows = [p for p in breakdown.get("top_paths", []) if "/hello-world" in str(p.get("path", "")).casefold()]
    if hello_rows:
        lines.extend(["", "### /hello-world/ Hinweis"])
        lines.append(
            "- `/hello-world/` mit 410 ist **bewusst entfernter WordPress-Default**. "
            "Keine automatische Massnahme erforderlich."
        )

    return "\n".join(lines) + "\n"


def top_values(rows: Sequence[Dict[str, object]], field: str, limit: int = 5) -> List[str]:
    counter: Counter[str] = Counter()
    for row in rows:
        value = safe_cell(row.get(field), 120)
        if value and value != "-":
            counter[value] += int(row.get("count", 0))
    return [value for value, _count in counter.most_common(limit)]


def is_sitelock(row: Dict[str, object]) -> bool:
    return "sitelockspider" in str(row.get("user_agent", "")).casefold()


def status_in(row: Dict[str, object], statuses: Iterable[int]) -> bool:
    return row.get("status") in set(statuses)


def origin_error_rows(rows: Sequence[Dict[str, object]]) -> List[Dict[str, object]]:
    return [
        row
        for row in rows
        if isinstance(row.get("status"), int) and int(row.get("status", 0)) >= 500
    ]


def fake_scan_status(rows: Sequence[Dict[str, object]]) -> Tuple[str, int, str]:
    error_rows = origin_error_rows(rows)
    error_count = row_count(error_rows)
    total_count = row_count(rows)
    if error_count:
        return (
            status_from_count(error_count, warning=25, critical=100),
            error_count,
            "Fake scanner paths produced 5xx origin-pressure signals.",
        )
    if total_count:
        return (
            STATUS_WATCH,
            total_count,
            "Fake scanner paths are visible, but current rows are blocked/not-found/rate-limited noise rather than 5xx.",
        )
    return STATUS_OK, 0, "No fake NextJS, secret, env, AWS, Docker, actuator, or API-auth scan rows are visible."


def is_oembed_path(path: str) -> bool:
    return "/wp-json/oembed/1.0/embed" in path.casefold()


def is_legacy_wp_path(path: str) -> bool:
    lowered = path.casefold()
    if lowered in {"/", "/wp-login.php"} or is_oembed_path(lowered) or lowered == "/xmlrpc.php":
        return False
    return any(
        marker in lowered
        for marker in (
            "/page/",
            "/hello-world",
            "/wp-admin",
            "/wp-content",
            "/wp-includes",
            "/wp-json",
            "/index.php",
        )
    )


def is_fake_nextjs_or_secret_path(path: str) -> bool:
    lowered = decode_path(path).casefold()
    return any(pattern in lowered for pattern in FAKE_SCAN_PATTERNS)


def make_v2_finding(
    *,
    signal_id: str,
    status: str,
    rows: Sequence[Dict[str, object]],
    count: int,
    explanation: str,
    recommendation: str,
) -> CorrelationV2Finding:
    return CorrelationV2Finding(
        signal_id=signal_id,
        status=status,
        count=count,
        paths=top_values(rows, "path"),
        user_agents=top_values(rows, "user_agent"),
        countries=top_values(rows, "country"),
        explanation=explanation,
        recommendation=recommendation,
    )


def status_5xx_total_from_raw(raw: Dict[str, List[Dict[str, object]]]) -> Optional[int]:
    total = 0
    seen = False
    for row in raw.get("status", []):
        status = row.get("status")
        if isinstance(status, int) and 500 <= status <= 599:
            total += int(row.get("count", 0))
            seen = True
    return total if seen else None


def correlate_v2(report_path: Path, results: Sequence[MetricResult]) -> List[CorrelationV2Finding]:
    raw = read_raw_json_groups(report_path.parent)
    errors = raw.get("errors_5xx", [])
    user_agents = raw.get("user_agents", [])
    notfound = raw.get("notfound_404", [])
    total_5xx = metric_value(results, "total_5xx")
    if total_5xx is None:
        total_5xx = status_5xx_total_from_raw(raw)

    sitelock_wp_login_rows = [
        row
        for row in user_agents
        if is_sitelock(row) and row.get("path") == "/wp-login.php" and row.get("status") == 503
    ]
    sitelock_oembed_rows = [
        row
        for row in user_agents
        if is_sitelock(row) and is_oembed_path(str(row.get("path"))) and row.get("status") in {503, 404}
    ]
    sitelock_frontpage_rows = [
        row
        for row in user_agents
        if is_sitelock(row) and row.get("path") == "/" and row.get("status") in {503, 504}
    ]
    sitelock_legacy_rows = [
        row
        for row in user_agents
        if is_sitelock(row)
        and is_legacy_wp_path(str(row.get("path")))
        and isinstance(row.get("status"), int)
        and int(row["status"]) >= 400
    ]

    xmlrpc_rows = [
        row
        for row in errors
        if row.get("path") == "/xmlrpc.php" and row.get("status") in {502, 503}
    ] + [
        row for row in notfound if row.get("path") == "/xmlrpc.php"
    ] + [
        row for row in user_agents if row.get("path") == "/xmlrpc.php" and row.get("status") == 429
    ]

    oembed_pressure_rows = [
        row
        for row in errors
        if is_oembed_path(str(row.get("path"))) and row.get("status") == 503
    ] + [
        row for row in notfound if is_oembed_path(str(row.get("path")))
    ]
    oembed_ua_rows = [
        row for row in user_agents if is_oembed_path(str(row.get("path"))) and row.get("status") in {503, 404}
    ]

    fake_scan_rows = [
        row for row in errors if is_fake_nextjs_or_secret_path(str(row.get("path")))
    ] + [
        row for row in notfound if is_fake_nextjs_or_secret_path(str(row.get("path")))
    ] + [
        row
        for row in user_agents
        if is_fake_nextjs_or_secret_path(str(row.get("path"))) and row.get("status") in {403, 429}
    ]
    fake_scan_status_value, fake_scan_count, fake_scan_explanation = fake_scan_status(fake_scan_rows)

    generic_rows = list(errors)
    specific_counts = [
        row_count(sitelock_wp_login_rows),
        row_count(sitelock_oembed_rows),
        row_count(sitelock_frontpage_rows),
        row_count(sitelock_legacy_rows),
        row_count(xmlrpc_rows),
        row_count(oembed_pressure_rows),
        row_count(fake_scan_rows),
    ]
    dominant_threshold = max(300, int((total_5xx or 0) * 0.25))
    has_dominant = bool(specific_counts and max(specific_counts) >= dominant_threshold)
    if total_5xx is None:
        generic_status = STATUS_OK
        generic_count = 0
        generic_explanation = "5xx-Gesamtwert ist nicht lesbar; generische Origin-Pressure kann nicht bewertet werden."
    elif total_5xx >= 600 and not has_dominant:
        generic_status = STATUS_CRITICAL
        generic_count = total_5xx
        generic_explanation = (
            "5xx bleibt kritisch, aber die sichtbaren Rohdaten verteilen sich auf mehrere Treiber "
            "statt auf eine einzelne dominante SiteLockSpider-Korrelation."
        )
    elif total_5xx >= 300:
        generic_status = STATUS_WARNING
        generic_count = total_5xx
        generic_explanation = "5xx ist erhoeht; einzelne Treiber sind sichtbar, aber Apply-Safe bleibt unveraendert."
    else:
        generic_status = STATUS_OK
        generic_count = total_5xx
        generic_explanation = "5xx ist nicht erhoeht."

    findings = [
        make_v2_finding(
            signal_id="sitelock_wp_login",
            status=status_from_count(row_count(sitelock_wp_login_rows), warning=25, critical=120),
            rows=sitelock_wp_login_rows,
            count=row_count(sitelock_wp_login_rows),
            explanation="Prueft, ob SiteLockSpider nach der wp-login-Regel weiter viele 503 auf /wp-login.php erzeugt.",
            recommendation="wp-login-Regel beobachten; keine neue Apply-Regel ableiten.",
        ),
        make_v2_finding(
            signal_id="sitelock_oembed",
            status=status_from_count(row_count(sitelock_oembed_rows), warning=20, critical=120),
            rows=sitelock_oembed_rows,
            count=row_count(sitelock_oembed_rows),
            explanation="SiteLockSpider ist auf oEmbed sichtbar und erzeugt 503/404-Signale.",
            recommendation="oEmbed-Zugriffe zeitlich beobachten; nicht pauschal blocken.",
        ),
        make_v2_finding(
            signal_id="sitelock_frontpage",
            status=status_from_count(row_count(sitelock_frontpage_rows), warning=25, critical=120),
            rows=sitelock_frontpage_rows,
            count=row_count(sitelock_frontpage_rows),
            explanation="Prueft SiteLockSpider auf der Startseite gegen 503/504-Signale.",
            recommendation="Root-Fallback nur als bestehende Safety-Option betrachten; keine neue Regel.",
        ),
        make_v2_finding(
            signal_id="sitelock_legacy_paths",
            status=status_from_count(row_count(sitelock_legacy_rows), warning=50, critical=120),
            rows=sitelock_legacy_rows,
            count=row_count(sitelock_legacy_rows),
            explanation="SiteLockSpider trifft alte WordPress-/Legacy-Pfade ausserhalb von wp-login und oEmbed.",
            recommendation="Legacy-Pfade und Cache/Origin-Verhalten pruefen; keine breite User-Agent-Regel.",
        ),
        make_v2_finding(
            signal_id="xmlrpc_abuse",
            status=status_from_count(row_count(xmlrpc_rows), warning=25, critical=100),
            rows=xmlrpc_rows,
            count=row_count(xmlrpc_rows),
            explanation="/xmlrpc.php erzeugt 502/503/404/429-Signale und kann Origin-Druck erklaeren.",
            recommendation="XML-RPC-Verwendung fachlich pruefen; nur defensive, eng begrenzte Massnahmen erwägen.",
        ),
        make_v2_finding(
            signal_id="oembed_pressure",
            status=status_from_count(row_count(oembed_pressure_rows), warning=50, critical=120),
            rows=oembed_pressure_rows + oembed_ua_rows,
            count=row_count(oembed_pressure_rows),
            explanation="oEmbed erzeugt insgesamt 503/404-Druck und ist aktuell ein sichtbarer 5xx-Treiber.",
            recommendation="oEmbed-Endpoint und WordPress-REST-Verhalten pruefen; legitime Embed-Nutzung nicht brechen.",
        ),
        make_v2_finding(
            signal_id="fake_nextjs_or_secret_scans",
            status=fake_scan_status_value,
            rows=fake_scan_rows,
            count=fake_scan_count,
            explanation=fake_scan_explanation,
            recommendation="Als Scannerrauschen defensiv beobachten; keine Secrets ausgeben und keine Gegenaktion.",
        ),
        make_v2_finding(
            signal_id="generic_origin_pressure",
            status=generic_status,
            rows=generic_rows,
            count=generic_count,
            explanation=generic_explanation,
            recommendation="Origin-/PHP-/WordPress-Logs lokal korrelieren; Apply-Safe nicht aggressiver machen.",
        ),
    ]
    return findings


class CloudflareSafeClient:
    """Minimal Cloudflare Rulesets API client using only the standard library."""

    BASE_URL = "https://api.cloudflare.com/client/v4"

    def __init__(self, token: str) -> None:
        self._token = token

    def _request(self, method: str, path: str, payload: Optional[Dict[str, object]] = None) -> Dict[str, object]:
        body = None
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")

        request = urllib.request.Request(
            f"{self.BASE_URL}{path}",
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = {"success": False, "errors": [{"message": raw or str(exc)}], "result": None}
            parsed.setdefault("success", False)
            return parsed
        except urllib.error.URLError as exc:
            return {"success": False, "errors": [{"message": str(exc)}], "result": None}

        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"success": False, "errors": [{"message": "Cloudflare returned non-JSON response"}], "result": None}

    def get_custom_firewall_entrypoint(self, zone_id: str) -> Dict[str, object]:
        return self._request(
            "GET",
            f"/zones/{zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint",
        )

    def update_custom_firewall_entrypoint(
        self,
        zone_id: str,
        payload: Dict[str, object],
        ruleset_id: Optional[str] = None,
    ) -> Dict[str, object]:
        if ruleset_id:
            return self._request("PUT", f"/zones/{zone_id}/rulesets/{ruleset_id}", payload)
        return self._request(
            "PUT",
            f"/zones/{zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint",
            payload,
        )


def select_sitelock_action_id(results: Sequence[MetricResult], correlation: CorrelationResult) -> Optional[Tuple[str, str]]:
    if correlation.correlation_status != CORRELATION_ACTION_CANDIDATE:
        return None

    sitelock = metric_value(results, "sitelockspider_top_user_agents")
    wp_login_503 = metric_value(results, "wp_login_503")
    root_504 = metric_value(results, "root_504")

    if sitelock is not None and sitelock >= 600 and wp_login_503 is not None and wp_login_503 >= 120:
        return "challenge_sitelockspider_wp_login", WP_LOGIN_ACTION_REASON
    if sitelock is not None and sitelock >= 600 and root_504 is not None and root_504 >= 250:
        return "challenge_sitelockspider_root", ROOT_ACTION_REASON
    return None


def planned_sitelock_action(action_id: str, action_ttl_hours: int, reason: str) -> Dict[str, object]:
    allowed = ALLOWED_ACTIONS[action_id]
    return {
        "action_id": allowed["name"],
        "expression": allowed["expression"],
        "cloudflare_action": allowed["cloudflare_action"],
        "ttl_hours": action_ttl_hours,
        "reason": reason,
        "description": allowed["description"],
        "safety_checks": [],
    }


def planned_active_defense_action(
    action_id: str,
    action_ttl_hours: int,
    reason: str,
    source_signal_id: str,
) -> Dict[str, object]:
    action = planned_sitelock_action(action_id, action_ttl_hours, reason)
    action["source_signal_id"] = source_signal_id
    return action


def v2_finding_map(findings: Sequence[CorrelationV2Finding]) -> Dict[str, CorrelationV2Finding]:
    return {finding.signal_id: finding for finding in findings}


def v2_status_in(finding: Optional[CorrelationV2Finding], statuses: Sequence[str]) -> bool:
    return finding is not None and finding.status in set(statuses)


def select_active_defense_actions(
    *,
    results: Sequence[MetricResult],
    correlation: CorrelationResult,
    correlation_v2_findings: Sequence[CorrelationV2Finding],
    action_ttl_hours: int,
    max_actions: int,
) -> List[Dict[str, object]]:
    selected: List[Dict[str, object]] = []
    by_signal = v2_finding_map(correlation_v2_findings)

    fake_secret = by_signal.get("fake_nextjs_or_secret_scans")
    if v2_status_in(fake_secret, (STATUS_CRITICAL, STATUS_WARNING)):
        selected.append(
            planned_active_defense_action(
                "challenge_fake_secret_scans",
                action_ttl_hours,
                "fake_nextjs_or_secret_scans is WARNING/CRITICAL in Correlation Layer v2.",
                "fake_nextjs_or_secret_scans",
            )
        )

    xmlrpc = by_signal.get("xmlrpc_abuse")
    if v2_status_in(xmlrpc, (STATUS_CRITICAL, STATUS_WARNING)):
        selected.append(
            planned_active_defense_action(
                "challenge_xmlrpc_abuse",
                action_ttl_hours,
                "xmlrpc_abuse is WARNING/CRITICAL in Correlation Layer v2.",
                "xmlrpc_abuse",
            )
        )

    sitelock_oembed = by_signal.get("sitelock_oembed")
    if v2_status_in(sitelock_oembed, (STATUS_CRITICAL,)):
        selected.append(
            planned_active_defense_action(
                "challenge_sitelockspider_oembed",
                action_ttl_hours,
                "sitelock_oembed is CRITICAL in Correlation Layer v2.",
                "sitelock_oembed",
            )
        )

    sitelock_fallback = select_sitelock_action_id(results, correlation)
    if sitelock_fallback:
        action_id, reason = sitelock_fallback
        selected.append(planned_active_defense_action(action_id, action_ttl_hours, reason, "correlation_layer_v1"))

    deduped: List[Dict[str, object]] = []
    seen = set()
    for action in selected:
        action_id = str(action.get("action_id", ""))
        if action_id in seen:
            continue
        seen.add(action_id)
        action_checks = validate_allowed_action(action)
        action["safety_checks"] = safety_checks_to_json(action_checks)
        deduped.append(action)
        if len(deduped) >= max(0, max_actions):
            break
    return deduped


def validate_allowed_action(action: Dict[str, object]) -> List[SafetyCheck]:
    expression = str(action.get("expression", ""))
    cloudflare_action = str(action.get("cloudflare_action", ""))
    action_id = str(action.get("action_id", ""))
    allowed = ALLOWED_ACTIONS.get(action_id)
    lower_expression = expression.casefold()
    allowed_expressions = {item["expression"] for item in ALLOWED_ACTIONS.values()}

    checks = [
        SafetyCheck(
            "action_is_allowlisted",
            allowed is not None
            and action_id == allowed["name"]
            and expression == allowed["expression"]
            and cloudflare_action == allowed["cloudflare_action"],
            "Only exact SentinelDefense Active Defense v1 managed_challenge actions are allowlisted.",
        ),
        SafetyCheck(
            "cloudflare_action_is_managed_challenge",
            cloudflare_action == "managed_challenge",
            "Only managed_challenge is allowed; block is not allowed.",
        ),
        SafetyCheck(
            "scope_is_narrow_path_or_sitelock_user_agent",
            (
                'http.user_agent contains "SiteLockSpider"' in expression
                or 'http.request.uri.path eq "/xmlrpc.php"' in expression
                or 'http.request.uri.path contains ".env"' in expression
            ),
            "Expression must be a narrow allowlisted path scope or SiteLockSpider path scope.",
        ),
        SafetyCheck(
            "expression_is_exact_allowlisted",
            expression in allowed_expressions,
            "Expression must exactly match one allowlisted Active Defense v1 scope.",
        ),
        SafetyCheck(
            "no_country_rule",
            "country" not in lower_expression and "geoip" not in lower_expression,
            "Country/geography rules are not allowed.",
        ),
        SafetyCheck(
            "no_ip_rule",
            "ip." not in lower_expression and "ip.src" not in lower_expression,
            "IP-based rules are not allowed.",
        ),
        SafetyCheck(
            "no_asn_rule",
            "asn" not in lower_expression,
            "ASN rules are not allowed.",
        ),
        SafetyCheck(
            "no_global_block_rule",
            cloudflare_action != "block",
            "Global or targeted block actions are not allowed in apply-safe.",
        ),
        SafetyCheck(
            "no_global_wordpress_rest_rule",
            'http.request.uri.path contains "/wp-json"' not in lower_expression
            and 'http.request.uri.path eq "/wp-json"' not in lower_expression,
            "Global WordPress REST rules are not allowed.",
        ),
    ]
    return checks


def safety_checks_to_json(checks: Sequence[SafetyCheck]) -> List[Dict[str, object]]:
    return [{"name": check.name, "passed": check.passed, "detail": check.detail} for check in checks]


def sanitize_existing_rule(rule: Dict[str, object]) -> Dict[str, object]:
    return {key: value for key, value in rule.items() if key not in {"version", "last_updated"}}


def write_json(path: Path, payload: Dict[str, object]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def build_ruleset_update_payload(
    ruleset: Dict[str, object],
    new_rules: Sequence[Dict[str, object]],
) -> Dict[str, object]:
    existing_rules = ruleset.get("rules") if isinstance(ruleset.get("rules"), list) else []
    return {
        "name": ruleset.get("name", "default"),
        "description": ruleset.get("description", "") or "",
        "rules": [sanitize_existing_rule(rule) for rule in existing_rules] + list(new_rules),
    }


def find_existing_sentinel_rule(ruleset: Dict[str, object], expression: str) -> Optional[Dict[str, object]]:
    rules = ruleset.get("rules") if isinstance(ruleset.get("rules"), list) else []
    for rule in rules:
        description = str(rule.get("description", ""))
        if "SentinelDefense" in description and rule.get("expression") == expression:
            return rule
    return None


def extract_created_rule(response: Dict[str, object], expression: str) -> Optional[Dict[str, object]]:
    result = response.get("result")
    if not isinstance(result, dict):
        return None
    rules = result.get("rules")
    if not isinstance(rules, list):
        return None
    sentinel_rules = [
        rule
        for rule in rules
        if rule.get("expression") == expression and "SentinelDefense" in str(rule.get("description", ""))
    ]
    return sentinel_rules[-1] if sentinel_rules else None


def rule_description(rule: Dict[str, object]) -> str:
    return safe_cell(rule.get("description", "-"), 180)


def rule_expression(rule: Dict[str, object]) -> str:
    return str(rule.get("expression", "")).strip()


def is_sentinel_rule(rule: Dict[str, object]) -> bool:
    return "SentinelDefense" in str(rule.get("description", ""))


def is_consolidatable_sentinel_rule(rule: Dict[str, object]) -> bool:
    return is_sentinel_rule(rule) and rule_expression(rule) in CONSOLIDATABLE_SENTINEL_EXPRESSIONS


def is_current_combined_sentinel_rule(rule: Dict[str, object]) -> bool:
    combined = ALLOWED_ACTIONS[CONSOLIDATED_ACTION_ID]
    return is_sentinel_rule(rule) and rule_expression(rule) == combined["expression"]


def is_legacy_combined_sentinel_rule(rule: Dict[str, object]) -> bool:
    return is_sentinel_rule(rule) and rule_expression(rule) == LEGACY_CONSOLIDATED_EXPRESSION


def is_combined_sentinel_rule(rule: Dict[str, object]) -> bool:
    return is_current_combined_sentinel_rule(rule) or is_legacy_combined_sentinel_rule(rule)


def summarized_rule(rule: Dict[str, object], index: int) -> Dict[str, object]:
    return {
        "index": index,
        "id": safe_cell(rule.get("id", "-"), 80),
        "description": rule_description(rule),
        "expression": safe_cell(rule.get("expression", "-"), 360),
        "action": safe_cell(rule.get("action", "-"), 80),
    }


def create_consolidated_rule(timestamp: str) -> Dict[str, object]:
    allowed = ALLOWED_ACTIONS[CONSOLIDATED_ACTION_ID]
    return {
        "ref": allowed["name"],
        "description": f"{allowed['description']} SentinelDefense consolidation {timestamp}",
        "expression": allowed["expression"],
        "action": allowed["cloudflare_action"],
        "enabled": True,
    }


def validate_consolidated_rule() -> List[SafetyCheck]:
    action = planned_sitelock_action(
        CONSOLIDATED_ACTION_ID,
        24,
        "Consolidate exact allowlisted SentinelDefense scanner rules into one managed_challenge rule.",
    )
    checks = validate_allowed_action(action)
    expression = str(action["expression"]).casefold()
    checks.extend(
        [
            SafetyCheck(
                "consolidated_action_is_managed_challenge",
                action["cloudflare_action"] == "managed_challenge",
                "Consolidated rule must use managed_challenge.",
            ),
            SafetyCheck(
                "consolidated_rule_has_no_block",
                "block" not in str(action["cloudflare_action"]).casefold(),
                "Hard block actions are not allowed.",
            ),
            SafetyCheck(
                "consolidated_rule_has_no_ip_country_asn",
                all(marker not in expression for marker in ("ip.", "ip.src", "country", "geoip", "asn")),
                "IP, ASN, and country predicates are not allowed.",
            ),
            SafetyCheck(
                "fake_framework_paths_are_host_bound",
                (
                    f'http.host eq "{APEX_HOST}"' in action["expression"]
                    and f'http.host eq "{WWW_HOST}"' in action["expression"]
                    and 'http.request.uri.path contains "_next"' in action["expression"]
                    and 'http.request.uri.path contains "__rsc"' in action["expression"]
                    and 'http.request.uri.path contains "__nextjs_action"' in action["expression"]
                    and 'http.request.uri.path contains "api/auth"' in action["expression"]
                ),
                "Fake framework/Auth scanner paths must be scoped to apex/www hostnames only.",
            ),
            SafetyCheck(
                "no_global_api_challenge",
                'http.request.uri.path contains "/api"' not in expression
                and 'http.request.uri.path eq "/api"' not in expression,
                "Global /api challenges are not allowed; only the exact api/auth scanner substring is allowed.",
            ),
        ]
    )
    return checks


def build_consolidation_plan(ruleset: Dict[str, object], timestamp: str) -> Dict[str, object]:
    rules = ruleset.get("rules") if isinstance(ruleset.get("rules"), list) else []
    current_count = len(rules)
    sentinel_rules = [summarized_rule(rule, index) for index, rule in enumerate(rules) if is_sentinel_rule(rule)]
    old_rules = [
        (index, rule)
        for index, rule in enumerate(rules)
        if isinstance(rule, dict) and is_consolidatable_sentinel_rule(rule)
    ]
    combined_rules = [
        (index, rule)
        for index, rule in enumerate(rules)
        if isinstance(rule, dict) and is_combined_sentinel_rule(rule)
    ]
    current_combined_rules = [
        (index, rule)
        for index, rule in enumerate(rules)
        if isinstance(rule, dict) and is_current_combined_sentinel_rule(rule)
    ]
    legacy_combined_rules = [
        (index, rule)
        for index, rule in enumerate(rules)
        if isinstance(rule, dict) and is_legacy_combined_sentinel_rule(rule)
    ]
    foreign_rules = [
        summarized_rule(rule, index)
        for index, rule in enumerate(rules)
        if isinstance(rule, dict) and not is_sentinel_rule(rule)
    ]

    combined_exists = bool(combined_rules)
    current_combined_exists = bool(current_combined_rules)
    combined_rule_needs_update = bool(legacy_combined_rules) and not current_combined_exists
    combined_rule = create_consolidated_rule(timestamp)
    new_rules: List[Dict[str, object]] = []
    for _index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        if is_consolidatable_sentinel_rule(rule):
            continue
        new_rules.append(sanitize_existing_rule(rule))
    if old_rules and not current_combined_exists:
        new_rules.append(combined_rule)

    result_count = len(new_rules)
    rules_to_replace = [summarized_rule(rule, index) for index, rule in old_rules]
    safety_checks = validate_consolidated_rule()
    safety_checks.extend(
        [
            SafetyCheck(
                "has_old_sentinel_rules",
                bool(old_rules),
                f"Consolidatable old SentinelDefense rules found: {len(old_rules)}.",
            ),
            SafetyCheck(
                "does_not_modify_foreign_rules",
                True,
                f"Foreign rules preserved unchanged by plan: {len(foreign_rules)}.",
            ),
            SafetyCheck(
                "result_count_lte_current_count",
                result_count <= current_count,
                f"Current rules={current_count}; planned result={result_count}.",
            ),
            SafetyCheck(
                "result_count_lte_5",
                result_count <= 5,
                f"Planned result={result_count}; Cloudflare phase limit is 5.",
            ),
            SafetyCheck(
                "combined_rule_not_duplicated",
                len(combined_rules) <= 1 and (current_combined_exists or bool(old_rules)),
                f"Existing combined SentinelDefense rules={len(combined_rules)}.",
            ),
            SafetyCheck(
                "combined_rule_update_is_exact_allowlisted",
                not combined_rule_needs_update or all(
                    rule_expression(rule) == LEGACY_CONSOLIDATED_EXPRESSION for _index, rule in legacy_combined_rules
                ),
                "Existing combined SentinelDefense rule may only be replaced when its legacy expression is exact allowlisted.",
            ),
        ]
    )
    can_apply = bool(old_rules) and all(check.passed for check in safety_checks)
    return {
        "current_rule_count": current_count,
        "result_rule_count": result_count,
        "sentinel_rules": sentinel_rules,
        "foreign_rule_count": len(foreign_rules),
        "foreign_rules": [{"index": item["index"], "description": item["description"]} for item in foreign_rules],
        "combined_rule_exists": combined_exists,
        "combined_rule_current": current_combined_exists,
        "combined_rule_needs_update": combined_rule_needs_update,
        "combined_rule": {
            "action_id": CONSOLIDATED_ACTION_ID,
            "cloudflare_action": ALLOWED_ACTIONS[CONSOLIDATED_ACTION_ID]["cloudflare_action"],
            "expression": ALLOWED_ACTIONS[CONSOLIDATED_ACTION_ID]["expression"],
            "description": ALLOWED_ACTIONS[CONSOLIDATED_ACTION_ID]["description"],
        },
        "rules_to_replace": rules_to_replace,
        "new_rules": new_rules,
        "can_apply": can_apply,
        "safety_checks": safety_checks,
    }


def write_rollback_file(path: Path, timestamp: str, applied_actions: Sequence[Dict[str, object]]) -> None:
    lines = [
        "# Sentinel Defense Last Rollback",
        "",
        f"- timestamp: {timestamp}",
        "- Hinweis: Remove these rules manually in Cloudflare WAF Custom Rules if needed.",
        "",
        "In dieser Version ist kein automatischer Delete implementiert.",
        "",
        "| Action ID | Created Rule ID | Expression |",
        "|---|---|---|",
    ]
    for action in applied_actions:
        lines.append(
            f"| `{action.get('action_id', 'unknown')}` | `{action.get('created_rule_id', 'unknown')}` | "
            f"`{action.get('expression', 'unknown')}` |"
        )
    content = "\n".join(lines)
    path.write_text(content + "\n", encoding="utf-8")


def write_consolidation_rollback_file(path: Path, timestamp: str, plan: Dict[str, object]) -> None:
    combined = plan.get("combined_rule") if isinstance(plan.get("combined_rule"), dict) else {}
    lines = [
        "# Sentinel Defense Consolidation Rollback",
        "",
        f"- timestamp: {timestamp}",
        "- Hinweis: Rollback ist manuell in Cloudflare WAF Custom Rules durchzuführen.",
        "- Entferne die kombinierte Regel nur nach manueller Prüfung.",
        "- Lege ersetzte SentinelDefense-Regeln bei Bedarf manuell mit den unten dokumentierten Expressions neu an.",
        "",
        "## Kombinierte Regel",
        "",
        f"- action_id: `{combined.get('action_id', '-')}`",
        f"- expression: `{combined.get('expression', '-')}`",
        "",
        "## Ersetzte SentinelDefense-Regeln",
        "",
        "| Action/Index | Description | Expression |",
        "|---|---|---|",
    ]
    rules_to_replace = plan.get("rules_to_replace") if isinstance(plan.get("rules_to_replace"), list) else []
    if not rules_to_replace:
        lines.append("| - | - | - |")
    else:
        for rule in rules_to_replace:
            if not isinstance(rule, dict):
                continue
            lines.append(
                f"| `{rule.get('index', '-')}` | {str(rule.get('description', '-')).replace('|', '\\|')} | "
                f"`{rule.get('expression', '-')}` |"
            )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def consolidation_checks_to_json(checks: Sequence[SafetyCheck]) -> List[Dict[str, object]]:
    return safety_checks_to_json(checks)


def markdown_consolidation_rule_table(rules: Sequence[Dict[str, object]], empty_text: str) -> str:
    if not rules:
        return f"- {empty_text}"
    lines = ["| Index | Description | Action | Expression |", "|---:|---|---|---|"]
    for rule in rules:
        lines.append(
            f"| {rule.get('index', '-')} | {str(rule.get('description', '-')).replace('|', '\\|')} | "
            f"`{rule.get('action', '-')}` | `{rule.get('expression', '-')}` |"
        )
    return "\n".join(lines)


def markdown_consolidation_foreign_rules(rules: Sequence[Dict[str, object]]) -> str:
    if not rules:
        return "- Keine fremden Regeln erkannt."
    lines = ["| Index | Description |", "|---:|---|"]
    for rule in rules:
        lines.append(f"| {rule.get('index', '-')} | {str(rule.get('description', '-')).replace('|', '\\|')} |")
    return "\n".join(lines)


def render_consolidation_markdown(report: Dict[str, object]) -> str:
    plan = report.get("plan") if isinstance(report.get("plan"), dict) else {}
    combined = plan.get("combined_rule") if isinstance(plan.get("combined_rule"), dict) else {}
    safety_checks = plan.get("safety_checks") if isinstance(plan.get("safety_checks"), list) else []
    sentinel_rules = plan.get("sentinel_rules") if isinstance(plan.get("sentinel_rules"), list) else []
    foreign_rules = plan.get("foreign_rules") if isinstance(plan.get("foreign_rules"), list) else []
    rules_to_replace = plan.get("rules_to_replace") if isinstance(plan.get("rules_to_replace"), list) else []

    lines = [
        "# Sentinel Defense Rule Consolidation Report",
        "",
        f"- Generated: `{report.get('generated_at_utc', '-')}`",
        f"- Mode: `{report.get('mode', '-')}`",
        f"- Cloudflare API Used: `{str(report.get('cloudflare_api_used', False)).lower()}`",
        f"- Cloudflare Mutation: `{str(report.get('cloudflare_mutation', False)).lower()}`",
        f"- Can Apply: `{str(plan.get('can_apply', False)).lower()}`",
        f"- Current Rule Count: `{plan.get('current_rule_count', 0)}`",
        f"- Planned Result Rule Count: `{plan.get('result_rule_count', 0)}`",
        "",
    ]
    if report.get("error"):
        lines.extend(["## Fehler", "", f"- {report.get('error')}", ""])

    lines.extend(
        [
            "## Erkannte SentinelDefense-Regeln",
            "",
            markdown_consolidation_rule_table(sentinel_rules, "Keine SentinelDefense-Regeln erkannt."),
            "",
            "## Fremde Regeln",
            "",
            f"- Anzahl: `{plan.get('foreign_rule_count', 0)}`",
            "",
            markdown_consolidation_foreign_rules(foreign_rules),
            "",
            "## Geplante Kombinierte Regel",
            "",
            f"- Combined Rule Exists: `{str(plan.get('combined_rule_exists', False)).lower()}`",
            f"- Combined Rule Current: `{str(plan.get('combined_rule_current', False)).lower()}`",
            f"- Combined Rule Needs Update: `{str(plan.get('combined_rule_needs_update', False)).lower()}`",
            f"- Action ID: `{combined.get('action_id', '-')}`",
            f"- Cloudflare Action: `{combined.get('cloudflare_action', '-')}`",
            f"- Description: {combined.get('description', '-')}",
            f"- Expression: `{combined.get('expression', '-')}`",
            "",
            "## Regeln, Die Ersetzt Wuerden",
            "",
            markdown_consolidation_rule_table(rules_to_replace, "Keine ersetzbaren alten SentinelDefense-Regeln erkannt."),
            "",
            "## Sicherheitschecks",
            "",
            markdown_safety_checks(
                [
                    SafetyCheck(
                        str(check.get("name", "unknown")),
                        bool(check.get("passed")),
                        str(check.get("detail", "")),
                    )
                    for check in safety_checks
                    if isinstance(check, dict)
                ]
            ),
            "",
            "## Ergebnis",
            "",
            f"- Ergebnisanzahl nach Plan: `{plan.get('result_rule_count', 0)}`",
            f"- Backup: `{report.get('backup_path', '-')}`",
            f"- Rollback-Hinweis: `{report.get('rollback_hint_path', '-')}`",
            "",
        ]
    )
    return "\n".join(lines)


def write_consolidation_reports(out_md_path: Path, out_json_path: Path, report: Dict[str, object]) -> None:
    out_md_path.parent.mkdir(parents=True, exist_ok=True)
    out_json_path.parent.mkdir(parents=True, exist_ok=True)
    out_json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    out_md_path.write_text(render_consolidation_markdown(report), encoding="utf-8")


def build_empty_consolidation_plan() -> Dict[str, object]:
    checks = [
        SafetyCheck("cloudflare_token_present", False, "CLOUDFLARE_API_TOKEN is required; value is never reported."),
        SafetyCheck("cloudflare_zone_id_present", False, "--cloudflare-zone-id is required."),
    ]
    return {
        "current_rule_count": 0,
        "result_rule_count": 0,
        "sentinel_rules": [],
        "foreign_rule_count": 0,
        "foreign_rules": [],
        "combined_rule_exists": False,
        "combined_rule_current": False,
        "combined_rule_needs_update": False,
        "combined_rule": {
            "action_id": CONSOLIDATED_ACTION_ID,
            "cloudflare_action": ALLOWED_ACTIONS[CONSOLIDATED_ACTION_ID]["cloudflare_action"],
            "expression": ALLOWED_ACTIONS[CONSOLIDATED_ACTION_ID]["expression"],
            "description": ALLOWED_ACTIONS[CONSOLIDATED_ACTION_ID]["description"],
        },
        "rules_to_replace": [],
        "can_apply": False,
        "safety_checks": consolidation_checks_to_json(checks),
    }


def run_consolidation_mode(args: argparse.Namespace, out_md_path: Path, out_json_path: Path) -> int:
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    mode = args.mode
    apply_mode = mode == "consolidate-apply-safe"
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    zone_id = args.cloudflare_zone_id.strip()
    backup_path: Optional[Path] = None
    rollback_path: Optional[Path] = None

    report: Dict[str, object] = {
        "schema_version": "1.0",
        "generated_at_utc": generated_at,
        "mode": mode,
        "cloudflare_api_used": False,
        "cloudflare_mutation": False,
        "backup_path": None,
        "rollback_hint_path": None,
        "error": "",
        "plan": build_empty_consolidation_plan(),
        "skipped_actions": [],
        "applied_actions": [],
    }

    missing = []
    if not token:
        missing.append("CLOUDFLARE_API_TOKEN")
    if not zone_id:
        missing.append("--cloudflare-zone-id")
    if apply_mode and not args.confirm_apply:
        missing.append("--confirm-apply")
    if missing:
        report["error"] = "Missing required consolidation prerequisite(s): " + ", ".join(missing)
        report["skipped_actions"] = [{"reason": report["error"]}]
        write_consolidation_reports(out_md_path, out_json_path, report)
        print(report["error"])
        print(f"markdown={out_md_path}")
        print(f"json={out_json_path}")
        return 2 if apply_mode else 0

    client = CloudflareSafeClient(token)
    entrypoint = client.get_custom_firewall_entrypoint(zone_id)
    report["cloudflare_api_used"] = True
    if apply_mode:
        backup_path = out_md_path.parent / f"cloudflare-ruleset-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        write_json(backup_path, entrypoint)
        report["backup_path"] = str(backup_path)

    if not entrypoint.get("success") or not isinstance(entrypoint.get("result"), dict):
        report["error"] = "Cloudflare ruleset entrypoint missing or unreadable; no consolidation applied."
        report["skipped_actions"] = [{"reason": report["error"]}]
        write_consolidation_reports(out_md_path, out_json_path, report)
        print(report["error"])
        print(f"markdown={out_md_path}")
        print(f"json={out_json_path}")
        return 1

    ruleset = entrypoint["result"]
    plan = build_consolidation_plan(ruleset, generated_at)
    plan["safety_checks"] = consolidation_checks_to_json(plan.get("safety_checks", []))
    report["plan"] = {key: value for key, value in plan.items() if key != "new_rules"}

    if mode == "consolidate-simulate":
        report["skipped_actions"] = [{"reason": "Simulation only; no Cloudflare update sent."}]
        write_consolidation_reports(out_md_path, out_json_path, report)
        print(f"consolidation_can_apply={plan.get('can_apply')}")
        print(f"current_rule_count={plan.get('current_rule_count')}")
        print(f"planned_result_rule_count={plan.get('result_rule_count')}")
        print("cloudflare_mutation=False")
        print(f"markdown={out_md_path}")
        print(f"json={out_json_path}")
        return 0

    if not plan.get("can_apply"):
        report["error"] = "Consolidation safety checks failed or no old SentinelDefense rules were found; no update sent."
        report["skipped_actions"] = [{"reason": report["error"]}]
        write_consolidation_reports(out_md_path, out_json_path, report)
        print(report["error"])
        print(f"markdown={out_md_path}")
        print(f"json={out_json_path}")
        return 1

    payload = {
        "name": ruleset.get("name", "default"),
        "description": ruleset.get("description", "") or "",
        "rules": plan["new_rules"],
    }
    update_response = client.update_custom_firewall_entrypoint(
        zone_id,
        payload,
        args.cloudflare_ruleset_id.strip() or None,
    )
    update_path = out_md_path.parent / f"cloudflare-ruleset-consolidation-update-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    write_json(update_path, update_response)

    if not update_response.get("success"):
        report["error"] = "Cloudflare consolidation update failed; see local API response file."
        report["skipped_actions"] = [{"reason": report["error"], "update_response": str(update_path)}]
        write_consolidation_reports(out_md_path, out_json_path, report)
        print(report["error"])
        print(f"markdown={out_md_path}")
        print(f"json={out_json_path}")
        return 1

    rollback_path = out_md_path.parent / "sentinel-defense-last-rollback.md"
    write_consolidation_rollback_file(rollback_path, generated_at, plan)
    report["cloudflare_mutation"] = True
    report["rollback_hint_path"] = str(rollback_path)
    report["applied_actions"] = [
        {
            "action_id": CONSOLIDATED_ACTION_ID,
            "cloudflare_action": ALLOWED_ACTIONS[CONSOLIDATED_ACTION_ID]["cloudflare_action"],
            "expression": ALLOWED_ACTIONS[CONSOLIDATED_ACTION_ID]["expression"],
            "replaced_rule_count": len(plan.get("rules_to_replace", [])),
            "update_response": str(update_path),
            "backup": str(backup_path) if backup_path else None,
            "rollback_hint": str(rollback_path),
        }
    ]
    write_consolidation_reports(out_md_path, out_json_path, report)
    print("consolidation_applied=True")
    print(f"backup={backup_path}")
    print(f"rollback_hint={rollback_path}")
    print(f"markdown={out_md_path}")
    print(f"json={out_json_path}")
    return 0


def evaluate_protective_mode(
    *,
    mode: str,
    confirm_apply: bool,
    cloudflare_zone_id: Optional[str],
    cloudflare_ruleset_id: Optional[str],
    max_actions: int,
    action_ttl_hours: int,
    results: Sequence[MetricResult],
    correlation: CorrelationResult,
    correlation_v2_findings: Sequence[CorrelationV2Finding],
    generated_at: str,
    output_dir: Path,
) -> ProtectiveModeResult:
    apply_safe_enabled = mode == "apply-safe"
    planned_actions: List[Dict[str, object]] = []
    applied_actions: List[Dict[str, object]] = []
    skipped_actions: List[Dict[str, object]] = []
    safety_checks: List[SafetyCheck] = []
    cloudflare_api_used = False
    cloudflare_result_summary = "Cloudflare API not used."

    selection_limit = min(max(max_actions, 0), 2)
    if mode in {"simulate", "apply-safe"}:
        planned_actions = select_active_defense_actions(
            results=results,
            correlation=correlation,
            correlation_v2_findings=correlation_v2_findings,
            action_ttl_hours=action_ttl_hours,
            max_actions=selection_limit,
        )
        for action in planned_actions:
            safety_checks.extend(
                SafetyCheck(str(check["name"]), bool(check["passed"]), str(check["detail"]))
                for check in action.get("safety_checks", [])
                if isinstance(check, dict)
            )

    token = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    token_present = bool(token)
    zone_present = bool(cloudflare_zone_id)
    safety_checks.extend(
        [
            SafetyCheck("mode_is_apply_safe", apply_safe_enabled, "apply-safe is required for Cloudflare changes."),
            SafetyCheck("confirm_apply", confirm_apply, "--confirm-apply is required for apply-safe."),
            SafetyCheck(
                "active_defense_selected_actions_lte_2",
                len(planned_actions) <= 2,
                f"Current selected actions={len(planned_actions)}.",
            ),
            SafetyCheck("max_actions_lte_2", max_actions <= 2, f"Current max_actions={max_actions}."),
            SafetyCheck(
                "cloudflare_token_present",
                (not apply_safe_enabled) or token_present,
                "CLOUDFLARE_API_TOKEN is required only for apply-safe; value is never reported.",
            ),
            SafetyCheck(
                "cloudflare_zone_id_present",
                (not apply_safe_enabled) or zone_present,
                "--cloudflare-zone-id is required for apply-safe.",
            ),
        ]
    )

    if mode == "observe":
        skipped_actions.append({"reason": "No action applied: mode=observe"})
        return ProtectiveModeResult(
            apply_safe_enabled=False,
            confirm_apply=confirm_apply,
            cloudflare_api_used=False,
            cloudflare_result_summary=cloudflare_result_summary,
            planned_actions=[],
            applied_actions=applied_actions,
            skipped_actions=skipped_actions,
            safety_checks=safety_checks,
        )

    if mode == "simulate":
        if not planned_actions:
            skipped_actions.append({"reason": "No active defense action planned from current allowlisted signals."})
        return ProtectiveModeResult(
            apply_safe_enabled=False,
            confirm_apply=confirm_apply,
            cloudflare_api_used=False,
            cloudflare_result_summary=cloudflare_result_summary,
            planned_actions=planned_actions,
            applied_actions=applied_actions,
            skipped_actions=skipped_actions,
            safety_checks=safety_checks,
        )

    if not apply_safe_enabled:
        skipped_actions.append({"reason": f"No action applied: unsupported mode={mode}"})
        return ProtectiveModeResult(
            apply_safe_enabled=False,
            confirm_apply=confirm_apply,
            cloudflare_api_used=False,
            cloudflare_result_summary=cloudflare_result_summary,
            planned_actions=planned_actions,
            applied_actions=applied_actions,
            skipped_actions=skipped_actions,
            safety_checks=safety_checks,
        )

    if not confirm_apply:
        skipped_actions.append({"reason": "No action applied: --confirm-apply is required for apply-safe."})

    if max_actions > 2:
        skipped_actions.append({"reason": f"No action applied: max_actions must be <= 2; got {max_actions}."})
    if not token_present:
        skipped_actions.append({"reason": "No action applied: CLOUDFLARE_API_TOKEN is missing."})
    if not cloudflare_zone_id:
        skipped_actions.append({"reason": "No action applied: --cloudflare-zone-id is required."})

    if not planned_actions:
        skipped_actions.append({"reason": "No action applied: no allowlisted Active Defense v1 action selected."})
        return ProtectiveModeResult(
            apply_safe_enabled=True,
            confirm_apply=confirm_apply,
            cloudflare_api_used=False,
            cloudflare_result_summary=cloudflare_result_summary,
            planned_actions=planned_actions,
            applied_actions=applied_actions,
            skipped_actions=skipped_actions,
            safety_checks=safety_checks,
        )

    if not all(check.passed for check in safety_checks):
        return ProtectiveModeResult(
            apply_safe_enabled=True,
            confirm_apply=confirm_apply,
            cloudflare_api_used=False,
            cloudflare_result_summary=cloudflare_result_summary,
            planned_actions=planned_actions,
            applied_actions=applied_actions,
            skipped_actions=skipped_actions,
            safety_checks=safety_checks,
        )

    if skipped_actions:
        return ProtectiveModeResult(
            apply_safe_enabled=True,
            confirm_apply=confirm_apply,
            cloudflare_api_used=False,
            cloudflare_result_summary="Cloudflare prerequisites missing; API not used.",
            planned_actions=planned_actions,
            applied_actions=applied_actions,
            skipped_actions=skipped_actions,
            safety_checks=safety_checks,
        )

    client = CloudflareSafeClient(token)
    cloudflare_api_used = True
    entrypoint = client.get_custom_firewall_entrypoint(str(cloudflare_zone_id))
    backup_path = output_dir / f"cloudflare-ruleset-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    write_json(backup_path, entrypoint)

    if not entrypoint.get("success") or not isinstance(entrypoint.get("result"), dict):
        skipped_actions.append(
            {
                "reason": "No action applied: entrypoint ruleset missing; manual setup required.",
                "backup": str(backup_path),
            }
        )
        return ProtectiveModeResult(
            apply_safe_enabled=True,
            confirm_apply=confirm_apply,
            cloudflare_api_used=True,
            cloudflare_result_summary="Entrypoint ruleset missing or unreadable; no update sent.",
            planned_actions=planned_actions,
            applied_actions=applied_actions,
            skipped_actions=skipped_actions,
            safety_checks=safety_checks,
        )

    ruleset = entrypoint["result"]
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    new_rules: List[Dict[str, object]] = []
    actions_to_create: List[Dict[str, object]] = []
    for action in planned_actions:
        expression = str(action["expression"])
        existing_rule = find_existing_sentinel_rule(ruleset, expression)
        if existing_rule:
            skipped_actions.append(
                {
                    "reason": "Rule already exists; no duplicate created.",
                    "action_id": action.get("action_id"),
                    "existing_rule_id": existing_rule.get("id"),
                    "backup": str(backup_path),
                }
            )
            continue
        allowed = ALLOWED_ACTIONS[str(action["action_id"])]
        new_rules.append(
            {
                "ref": allowed["name"],
                "description": (
                    f"{allowed['description']} SentinelDefense apply-safe {timestamp}; "
                    f"ttl_hours={action_ttl_hours}"
                ),
                "expression": expression,
                "action": allowed["cloudflare_action"],
                "enabled": True,
            }
        )
        actions_to_create.append(action)

    if not new_rules:
        return ProtectiveModeResult(
            apply_safe_enabled=True,
            confirm_apply=confirm_apply,
            cloudflare_api_used=True,
            cloudflare_result_summary="Existing SentinelDefense rules found; no duplicates created.",
            planned_actions=planned_actions,
            applied_actions=applied_actions,
            skipped_actions=skipped_actions,
            safety_checks=safety_checks,
        )

    payload = build_ruleset_update_payload(ruleset, new_rules)
    update_response = client.update_custom_firewall_entrypoint(
        str(cloudflare_zone_id),
        payload,
        cloudflare_ruleset_id,
    )
    update_path = output_dir / f"cloudflare-ruleset-update-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    write_json(update_path, update_response)

    if not update_response.get("success"):
        skipped_actions.append(
            {
                "reason": "No action applied: Cloudflare update failed.",
                "backup": str(backup_path),
                "update_response": str(update_path),
            }
        )
        return ProtectiveModeResult(
            apply_safe_enabled=True,
            confirm_apply=confirm_apply,
            cloudflare_api_used=True,
            cloudflare_result_summary="Cloudflare update failed; see local API response file.",
            planned_actions=planned_actions,
            applied_actions=applied_actions,
            skipped_actions=skipped_actions,
            safety_checks=safety_checks,
        )

    rollback_path = output_dir / "sentinel-defense-last-rollback.md"
    for action in actions_to_create:
        expression = str(action["expression"])
        created_rule = extract_created_rule(update_response, expression) or {}
        applied_actions.append(
            {
                "action_id": action["action_id"],
                "cloudflare_action": action["cloudflare_action"],
                "expression": expression,
                "created_rule_id": created_rule.get("id"),
                "backup": str(backup_path),
                "update_response": str(update_path),
                "rollback_hint": str(rollback_path),
            }
        )
    write_rollback_file(rollback_path, timestamp, applied_actions)
    return ProtectiveModeResult(
        apply_safe_enabled=True,
        confirm_apply=confirm_apply,
        cloudflare_api_used=True,
        cloudflare_result_summary=f"Applied {len(applied_actions)} allowlisted SentinelDefense managed_challenge rule(s).",
        planned_actions=planned_actions,
        applied_actions=applied_actions,
        skipped_actions=skipped_actions,
        safety_checks=safety_checks,
    )


def history_metric_value(record: Dict[str, object], key: str, label: str) -> Optional[int]:
    value = record.get(key)
    if value is None:
        value = record.get(label)
    metrics = record.get("metrics")
    if value is None and isinstance(metrics, dict):
        value = metrics.get(key)
        if value is None:
            value = metrics.get(label)
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    return None


def average(values: Sequence[int]) -> Optional[float]:
    if not values:
        return None
    return round(sum(values) / len(values), 2)


def is_strictly_increasing(values: Sequence[int]) -> bool:
    if len(values) < 3:
        return False
    return all(left < right for left, right in zip(values, values[1:]))


def metric_values_from_history(entries: Sequence[Dict[str, object]], key: str, label: str) -> List[int]:
    values: List[int] = []
    for entry in entries:
        value = history_metric_value(entry, key, label)
        if value is not None:
            values.append(value)
    return values


def load_history(path: Path, limit: int = 200) -> Tuple[List[Dict[str, object]], List[str]]:
    warnings: List[str] = []
    if not path.exists():
        return [], warnings

    entries: List[Dict[str, object]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return [], [f"History konnte nicht gelesen werden: {exc}"]

    for line_number, line in enumerate(lines[-limit:], start=max(1, len(lines) - limit + 1)):
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            warnings.append(f"History-Zeile {line_number} ist kein valides JSON: {exc}")
            continue
        if isinstance(parsed, dict):
            entries.append(parsed)
    return entries, warnings


def build_history_record(
    *,
    timestamp: str,
    mode: str,
    overall: str,
    correlation: CorrelationResult,
    results: Sequence[MetricResult],
    protective: ProtectiveModeResult,
) -> Dict[str, object]:
    values = {result.key: result.value for result in results}
    labels = {result.label: result.value for result in results}
    return {
        "timestamp": timestamp,
        "mode": mode,
        "overall_status": overall,
        "correlation_status": correlation.correlation_status,
        "operational_interpretation": correlation.operational_interpretation,
        "5xx gesamt": values.get("total_5xx"),
        "503 auf /wp-login.php": values.get("wp_login_503"),
        "504 auf /": values.get("root_504"),
        "404 auf .map": values.get("map_404"),
        "503 auf oEmbed": values.get("oembed_503"),
        "404 auf oEmbed": values.get("oembed_404"),
        "404 auf /app": values.get("app_404"),
        "SiteLockSpider in Top User-Agents": values.get("sitelockspider_top_user_agents"),
        "metrics": {
            **values,
            **labels,
        },
        "planned_actions_count": len(protective.planned_actions),
        "applied_actions_count": len(protective.applied_actions),
        "skipped_actions_count": len(protective.skipped_actions),
        "cloudflare_api_used": protective.cloudflare_api_used,
    }


def summarize_trend(entries: Sequence[Dict[str, object]], max_entries: int = 14) -> TrendResult:
    recent = list(entries[-max_entries:])
    runs = len(recent)

    sitelock_values = metric_values_from_history(
        recent, "sitelockspider_top_user_agents", "SiteLockSpider in Top User-Agents"
    )
    total_5xx_values = metric_values_from_history(recent, "total_5xx", "5xx gesamt")
    root_504_values = metric_values_from_history(recent, "root_504", "504 auf /")
    app_404_values = metric_values_from_history(recent, "app_404", "404 auf /app")
    wp_login_503_values = metric_values_from_history(recent, "wp_login_503", "503 auf /wp-login.php")

    avg_sitelock = average(sitelock_values)
    avg_total_5xx = average(total_5xx_values)
    avg_root_504 = average(root_504_values)

    summary: Dict[str, object] = {
        "runs": runs,
        "overall_critical_count": sum(1 for entry in recent if entry.get("overall_status") == STATUS_CRITICAL),
        "correlation_watch_count": sum(1 for entry in recent if entry.get("correlation_status") == CORRELATION_WATCH),
        "correlation_action_candidate_count": sum(
            1 for entry in recent if entry.get("correlation_status") == CORRELATION_ACTION_CANDIDATE
        ),
        "avg_sitelockspider": avg_sitelock,
        "avg_total_5xx": avg_total_5xx,
        "avg_root_504": avg_root_504,
        "max_sitelockspider": max(sitelock_values) if sitelock_values else None,
        "max_total_5xx": max(total_5xx_values) if total_5xx_values else None,
    }

    interpretations: List[str] = []
    if avg_sitelock is not None and avg_sitelock >= 600 and avg_total_5xx is not None and avg_total_5xx < 300:
        interpretations.append(
            "SiteLockSpider ist dauerhaft sichtbar, aber bisher nicht eindeutig ursächlich für Origin-Probleme."
        )

    last_sitelock = sitelock_values[-3:]
    last_5xx = total_5xx_values[-3:]
    last_504 = root_504_values[-3:]
    if (
        average(last_sitelock) is not None
        and average(last_sitelock) >= 600
        and (is_strictly_increasing(last_5xx) or is_strictly_increasing(last_504))
    ):
        interpretations.append("Mögliche wiederkehrende Korrelation zwischen SiteLockSpider und Origin-Last.")

    if app_404_values and all(value == 0 for value in app_404_values):
        interpretations.append("/app-Fix bestätigt.")

    if wp_login_503_values and all(value == 0 for value in wp_login_503_values):
        interpretations.append("Login-Schutz stabil.")

    if not interpretations:
        interpretations.append("Noch kein stabiler Mehrlauf-Trend ableitbar.")

    return TrendResult(summary=summary, interpretations=interpretations, entries_used=recent)


def append_history(path: Path, record: Dict[str, object]) -> Optional[str]:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    except OSError as exc:
        return f"History konnte nicht geschrieben werden: {exc}"
    return None


def markdown_status_table(results: Sequence[MetricResult]) -> str:
    lines = [
        "| Metrik | Wert | Status | Warning | Critical | Empfehlung |",
        "|---|---:|---|---:|---:|---|",
    ]
    for result in results:
        value = "n/a" if result.value is None else str(result.value)
        recommendation = result.recommendation.replace("|", "\\|")
        lines.append(
            f"| {result.label} | {value} | `{result.status}` | {result.warning} | {result.critical} | {recommendation} |"
        )
    return "\n".join(lines)


def markdown_correlation_table(correlation: CorrelationResult) -> str:
    lines = [
        "| Signal | Wert | Interpretation | Empfohlene nächste Aktion |",
        "|---|---|---|---|",
    ]
    for finding in correlation.findings:
        lines.append(
            "| "
            + " | ".join(
                [
                    finding.signal.replace("|", "\\|"),
                    finding.value.replace("|", "\\|"),
                    finding.interpretation.replace("|", "\\|"),
                    finding.recommended_next_action.replace("|", "\\|"),
                ]
            )
            + " |"
        )
    return "\n".join(lines)


def markdown_list(values: Sequence[str], limit: int = 4) -> str:
    if not values:
        return "-"
    escaped = [value.replace("|", "\\|") for value in values[:limit]]
    if len(values) > limit:
        escaped.append("...")
    return ", ".join(escaped)


def markdown_correlation_v2_table(findings: Sequence[CorrelationV2Finding]) -> str:
    lines = [
        "| Signal | Status | Count | Paths | User-Agents | Countries | Empfehlung |",
        "|---|---|---:|---|---|---|---|",
    ]
    for finding in findings:
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{finding.signal_id}`",
                    f"`{finding.status}`",
                    str(finding.count),
                    markdown_list(finding.paths),
                    markdown_list(finding.user_agents, limit=3),
                    markdown_list(finding.countries),
                    finding.recommendation.replace("|", "\\|"),
                ]
            )
            + " |"
        )
    return "\n".join(lines)


def markdown_count_items(items: object, key: str, limit: int = 4) -> str:
    if not isinstance(items, list) or not items:
        return "-"
    values = []
    for item in items[:limit]:
        if not isinstance(item, dict):
            continue
        values.append(f"{safe_cell(item.get(key), 80)}:{safe_cell(item.get('count'), 40)}")
    return markdown_list(values, limit=limit)


def markdown_simple_count_table(rows: object, key: str, label: str) -> str:
    if not isinstance(rows, list) or not rows:
        return "- Keine Daten verfuegbar."
    lines = [f"| {label} | Count |", "|---|---:|"]
    for row in rows:
        if not isinstance(row, dict):
            continue
        lines.append(f"| {safe_cell(row.get(key), 140).replace('|', '\\|')} | {safe_cell(row.get('count'), 40)} |")
    return "\n".join(lines)


def markdown_origin_pressure_breakdown(breakdown: Dict[str, object]) -> str:
    lines = [
        "## 5xx Origin Pressure Breakdown",
        "",
        (
            "Diese Diagnose nutzt nur vorhandene lokale JSON-Rohdaten und aendert keine Cloudflare-Regeln "
            "oder Schwellenwerte."
        ),
        "",
        f"- Status: `{safe_cell(breakdown.get('status'), 80)}`",
        f"- Interpretation: {safe_cell(breakdown.get('interpretation'), 520)}",
        f"- Policy: {safe_cell(breakdown.get('status_policy'), 520)}",
        f"- Source Directory: `{safe_cell(breakdown.get('source_directory'), 220)}`",
        f"- 5xx aus status-24h: `{safe_cell(breakdown.get('status_24h_total_5xx'), 40)}`; "
        f"detaillierte 5xx-Zeilen: `{safe_cell(breakdown.get('observed_5xx_detail_count'), 40)}`; "
        f"Coverage: `{safe_cell(breakdown.get('detail_coverage_percent'), 40)}%`; "
        f"nur aggregiert/unknown: `{safe_cell(breakdown.get('unclassified_5xx_from_status_aggregate'), 40)}` "
        f"(`{safe_cell(breakdown.get('unknown_share_percent'), 40)}%`)",
        f"- Detail Completeness: `{safe_cell(breakdown.get('detail_completeness_status'), 100)}`",
        f"- Diagnostic Gap: {safe_cell(breakdown.get('diagnostic_gap'), 520)}",
        f"- Scope: {safe_cell(breakdown.get('classification_scope'), 520)}",
        f"- Status-inclusive Scope: {safe_cell(breakdown.get('status_inclusive_classification_scope'), 520)}",
        f"- Cache Interpretation: {safe_cell(breakdown.get('cache_status_interpretation'), 520)}",
        "",
        "### Top 5xx Paths",
        "",
    ]

    top_paths = breakdown.get("top_5xx_paths")
    if not isinstance(top_paths, list) or not top_paths:
        lines.append("- Keine 5xx-Pfadzeilen in errors-5xx-24h.json gefunden.")
    else:
        lines.extend(
            [
                "| Count | Path | Status | Country | Cache | UA-Gruppen | Request Shape | Actor Signal | Failure Mode | Classification | Sentinel Combined |",
                "|---:|---|---|---|---|---|---|---|---|---|---|",
            ]
        )
        for item in top_paths:
            if not isinstance(item, dict):
                continue
            combined = (
                f"{safe_cell(item.get('combined_rule_scope'), 80)}; "
                f"actual={str(bool(item.get('actual_5xx_traffic_covered_by_combined_rule'))).lower()}"
            )
            lines.append(
                "| "
                + " | ".join(
                    [
                        safe_cell(item.get("count"), 40),
                        safe_cell(item.get("path"), 180).replace("|", "\\|"),
                        markdown_count_items(item.get("statuses"), "status"),
                        markdown_count_items(item.get("countries"), "country"),
                        markdown_count_items(item.get("cache_status"), "cache_status"),
                        markdown_count_items(item.get("user_agent_groups"), "group"),
                        safe_cell(item.get("request_shape"), 100),
                        safe_cell(item.get("actor_signal"), 100),
                        safe_cell(item.get("failure_mode"), 120),
                        safe_cell(item.get("classification"), 100),
                        safe_cell(combined, 140),
                    ]
                )
                + " |"
            )

    lines.extend(
        [
            "",
            "### Top 5xx Status Codes",
            "",
            markdown_simple_count_table(breakdown.get("top_5xx_status_codes"), "status", "Status"),
            "",
            "### 5xx Detail Gap By Status",
            "",
        ]
    )

    status_gap = breakdown.get("status_detail_gap")
    if not isinstance(status_gap, list) or not status_gap:
        lines.append("- Keine statusweise Detail-Gap-Auswertung verfuegbar.")
    else:
        lines.extend(
            [
                "| Status | status-24h | Detailed | Aggregate-only | Coverage | Status-only Classification | Reason |",
                "|---:|---:|---:|---:|---:|---|---|",
            ]
        )
        for item in status_gap:
            if not isinstance(item, dict):
                continue
            lines.append(
                "| "
                + " | ".join(
                    [
                        safe_cell(item.get("status"), 40),
                        safe_cell(item.get("status_24h_count"), 40),
                        safe_cell(item.get("detailed_count"), 40),
                        safe_cell(item.get("unclassified_count"), 40),
                        f"{safe_cell(item.get('detail_coverage_percent'), 40)}%",
                        safe_cell(item.get("status_only_classification"), 100),
                        safe_cell(item.get("status_only_reason"), 260).replace("|", "\\|"),
                    ]
                )
                + " |"
            )

    lines.extend(
        [
            "",
            "### 5xx Status-only Gap Classification",
            "",
            markdown_simple_count_table(
                breakdown.get("status_only_gap_classification"), "classification", "Classification"
            ),
            "",
            "### Top 5xx Countries",
            "",
            markdown_simple_count_table(breakdown.get("top_5xx_countries"), "country", "Country"),
            "",
            "### Top 5xx Cache Status",
            "",
            markdown_simple_count_table(breakdown.get("top_5xx_cache_status"), "cache_status", "Cache Status"),
            "",
            "### Top 5xx User-Agent-Gruppen",
            "",
            markdown_simple_count_table(breakdown.get("top_5xx_user_agent_groups"), "group", "User-Agent-Gruppe"),
            "",
            "### Top 5xx Classification",
            "",
            markdown_simple_count_table(
                breakdown.get("top_5xx_classification"), "classification", "Classification"
            ),
            "",
            "### Top 5xx Status-inclusive Classification",
            "",
            markdown_simple_count_table(
                breakdown.get("top_5xx_status_inclusive_classification"), "classification", "Classification"
            ),
            "",
            "### Top 5xx Request Shapes",
            "",
            markdown_simple_count_table(
                breakdown.get("top_5xx_request_shapes"), "request_shape", "Request Shape"
            ),
            "",
            "### Top 5xx Actor Signals",
            "",
            markdown_simple_count_table(
                breakdown.get("top_5xx_actor_signals"), "actor_signal", "Actor Signal"
            ),
            "",
            "### Top 5xx Failure Modes",
            "",
            markdown_simple_count_table(
                breakdown.get("top_5xx_failure_modes"), "failure_mode", "Failure Mode"
            ),
            "",
            "### Sentinel Combined Rule Coverage",
            "",
        ]
    )

    coverage = breakdown.get("sentinel_combined_rule_coverage")
    if not isinstance(coverage, list) or not coverage:
        lines.append("- Keine Coverage-Daten verfuegbar.")
    else:
        lines.extend(
            [
                "| Path | Count | Combined Scope | Actual 5xx Covered | Security Actions 24h | Reason |",
                "|---|---:|---|---:|---|---|",
            ]
        )
        for item in coverage:
            if not isinstance(item, dict):
                continue
            lines.append(
                "| "
                + " | ".join(
                    [
                        safe_cell(item.get("path"), 180).replace("|", "\\|"),
                        safe_cell(item.get("count"), 40),
                        safe_cell(item.get("combined_rule_scope"), 100),
                        str(bool(item.get("actual_5xx_traffic_covered_by_combined_rule"))).lower(),
                        markdown_count_items(item.get("security_actions_24h"), "action"),
                        safe_cell(item.get("reason"), 260).replace("|", "\\|"),
                    ]
                )
                + " |"
            )
    return "\n".join(lines)


def markdown_origin_timeout_action_checklist(breakdown: Dict[str, Any]) -> str:
    """
    Erzeugt eine diagnostische Checkliste für Origin-Timeouts, falls relevante Fehler erkannt wurden.
    Diese Sektion dient rein der Diagnose und führt keine automatischen Aktionen aus.
    """
    timeout_statuses = {"504", "522", "524", "530"}
    has_timeout = False

    # 1. Check top status codes
    top_status_codes = breakdown.get("top_5xx_status_codes")
    if isinstance(top_status_codes, list):
        for sc in top_status_codes:
            if str(sc.get("status")) in timeout_statuses:
                has_timeout = True
                break

    # 2. Check status-only gap classifications
    gap_classifications = breakdown.get("status_only_gap_classification")
    if not has_timeout and isinstance(gap_classifications, list):
        for c in gap_classifications:
            if c.get("classification") == "likely_cloudflare_timeout":
                has_timeout = True
                break

    # 3. Check top path classifications
    top_paths = breakdown.get("top_5xx_paths")
    if not has_timeout and isinstance(top_paths, list):
        for p in top_paths:
            if p.get("classification") == "likely_cloudflare_timeout":
                has_timeout = True
                break

    if not has_timeout:
        return ""

    # Wir nutzen die Domain aus den Top-Paths oder Fallback
    domain = "electri-c-ity-studios-24-7.com"
    
    lines = [
        "## Origin Timeout Action Checklist",
        "",
        "Origin-Timeouts (504/522/524/530) oder `likely_cloudflare_timeout` wurden erkannt. ",
        "Diese Diagnose-Checkliste hilft bei der Ursachensuche auf dem Origin-Server. ",
        "**Hinweis:** Rein diagnostisch; keine externen Scans; nur eigene Domain/Logs.",
        "",
        "### 1. IONOS / WordPress / PHP Error Logs",
        "Prüfen, ob PHP-Prozesse hängen, Limits erreichen oder SQL-Timeouts vorliegen:",
        "```bash",
        "# WordPress Debug Log (falls in wp-config.php aktiviert)",
        "tail -n 100 wp-content/debug.log",
        "",
        "# Falls lokaler Zugriff auf Webserver-Logs (Hetzner/IONOS) möglich:",
        "tail -n 100 error_log",
        "```",
        "",
        "### 2. HTTP Performance & Pfad-Prüfung",
        "Reaktionszeit und Erreichbarkeit wichtiger Pfade direkt vom Sentinel-Host oder lokal prüfen:",
        "```bash",
        "# Homepage Response-Time Messung",
        f"curl -o /dev/null -s -w 'Total: %{{time_total}}s\\n' https://{domain}/",
        "",
        "# Erreichbarkeit (HEAD-Request)",
        f"curl -I https://{domain}/",
        f"curl -I https://{domain}/wp-login.php",
        f"curl -I https://{domain}/.env",
        "```",
        "",
        "### 3. Cloudflare Timeout Interpretation",
        "- **504 / 524 (Gateway Timeout):** Der Origin hat die Verbindung angenommen, aber nicht rechtzeitig geantwortet (meist >100s PHP-Execution oder DB-Lock).",
        "- **522 (Connection Timeout):** Cloudflare konnte gar keine TCP-Verbindung zum Origin aufbauen (Firewall-Block, Server Down, Network Issue).",
        "- **530 (Origin DNS Error / Site Frozen):** DNS-Auflösung zum Origin schlägt fehl oder Account-Sperrung.",
        "- **Origin Detail Gap:** Wenn viele Fehler nur aggregiert vorliegen (`origin_5xx_aggregate_detail_gap`), fehlen Cloudflare-Logs für die Pfad-Analyse.",
        "",
    ]
    return "\n".join(lines)


def markdown_source_map_404_breakdown(breakdown: Dict[str, object]) -> str:
    lines = [
        "## Source Map 404 Breakdown",
        "",
        (
            "Diese Diagnose nutzt nur vorhandene lokale JSON-Rohdaten und aendert keine "
            "Cloudflare-Regeln oder Schwellenwerte."
        ),
        "",
        f"- Status: `{safe_cell(breakdown.get('status'), 80)}`",
        f"- Interpretation: {safe_cell(breakdown.get('interpretation'), 520)}",
        f"- Policy: {safe_cell(breakdown.get('status_policy'), 520)}",
        f"- Source Directory: `{safe_cell(breakdown.get('source_directory'), 220)}`",
        f"- 404 auf .map: `{safe_cell(breakdown.get('map_404_total'), 40)}`; "
        f"detaillierte Zeilen: `{safe_cell(breakdown.get('observed_map_404_detail_count'), 40)}`; "
        f"Coverage: `{safe_cell(breakdown.get('detail_coverage_percent'), 40)}%`; "
        f"unknown: `{safe_cell(breakdown.get('unclassified_map_404_from_metric'), 40)}` "
        f"(`{safe_cell(breakdown.get('unknown_share_percent'), 40)}%`)",
        f"- Detail Completeness: `{safe_cell(breakdown.get('detail_completeness_status'), 100)}`",
        "",
        "### Top Source Map 404 Paths",
        "",
    ]

    top_paths = breakdown.get("top_map_404_paths")
    if not isinstance(top_paths, list) or not top_paths:
        lines.append("- Keine `.map`-404-Detailzeilen in notfound-404-24h.json gefunden.")
    else:
        lines.extend(
            [
                "| Count | Path | Country | Cache | UA-Gruppen | Classification | Sentinel Combined |",
                "|---:|---|---|---|---|---|---|",
            ]
        )
        for item in top_paths:
            if not isinstance(item, dict):
                continue
            lines.append(
                "| "
                + " | ".join(
                    [
                        safe_cell(item.get("count"), 40),
                        safe_cell(item.get("path"), 180).replace("|", "\\|"),
                        markdown_count_items(item.get("countries"), "country"),
                        markdown_count_items(item.get("cache_status"), "cache_status"),
                        markdown_count_items(item.get("user_agent_groups"), "group"),
                        safe_cell(item.get("classification"), 120),
                        safe_cell(item.get("combined_rule_scope"), 100),
                    ]
                )
                + " |"
            )

    lines.extend(
        [
            "",
            "### Source Map 404 Classification",
            "",
            markdown_simple_count_table(
                breakdown.get("top_map_404_classification"), "classification", "Classification"
            ),
            "",
            "### Source Map 404 Cache Status",
            "",
            markdown_simple_count_table(breakdown.get("top_map_404_cache_status"), "cache_status", "Cache Status"),
            "",
            "### Source Map 404 User-Agent-Gruppen",
            "",
            markdown_simple_count_table(breakdown.get("top_map_404_user_agent_groups"), "group", "User-Agent-Gruppe"),
        ]
    )
    return "\n".join(lines)


def markdown_rolling_window_context(context: Dict[str, object]) -> str:
    comparison = context.get("comparison") if isinstance(context.get("comparison"), dict) else {}
    window = context.get("window") if isinstance(context.get("window"), dict) else {}
    history = context.get("history") if isinstance(context.get("history"), dict) else {}
    lines = [
        "## Rolling Window Context",
        "",
        f"- Status: `{safe_cell(context.get('status'), 80)}`",
        f"- Interpretation: {safe_cell(context.get('interpretation'), 360)}",
        f"- Policy: {safe_cell(context.get('status_policy'), 360)}",
        f"- Source Directory: `{safe_cell(context.get('source_directory'), 200)}`",
        f"- Window: `{safe_cell(window.get('since_24h_utc'), 80)}` bis `{safe_cell(window.get('generated_at_utc'), 80)}` UTC",
        f"- Comparison: previous `{safe_cell(comparison.get('previous_generated_at_utc'), 80)}`, "
        f"current `{safe_cell(comparison.get('current_generated_at_utc'), 80)}`, "
        f"minutes `{safe_cell(comparison.get('minutes_between'), 40)}`",
        "",
    ]
    elevated = context.get("elevated_watchpoints")
    if not isinstance(elevated, list) or not elevated:
        lines.append("- Keine erhoehten Watchpoints im Rolling-Window-Kontext.")
        return "\n".join(lines)

    lines.extend(
        [
            "| Metrik | 24h Status | 24h Wert | Delta zum Vorlauf | Interpretation |",
            "|---|---|---:|---:|---|",
        ]
    )
    for item in elevated:
        if not isinstance(item, dict):
            continue
        delta = item.get("delta_since_previous")
        delta_text = "n/a" if delta is None else str(delta)
        lines.append(
            "| "
            + " | ".join(
                [
                    safe_cell(item.get("label"), 120),
                    f"`{safe_cell(item.get('status'), 40)}`",
                    safe_cell(item.get("value_24h"), 40),
                    (
                        f"{delta_text} ({safe_cell(item.get('delta_comparability_reason'), 80)})"
                        if item.get("delta_comparable") is False
                        else delta_text
                    ),
                    safe_cell(item.get("interpretation"), 240).replace("|", "\\|"),
                ]
            )
            + " |"
        )
    if history:
        lines.extend(
            [
                "",
                "### Multi-Snapshot Stability",
                "",
                f"- Status: `{safe_cell(history.get('status'), 100)}`",
                f"- Interpretation: {safe_cell(history.get('interpretation'), 420)}",
                f"- Policy: {safe_cell(history.get('status_policy'), 420)}",
                f"- Successful Snapshots: `{safe_cell(history.get('successful_snapshot_count'), 40)}` "
                f"from `{safe_cell(history.get('first_successful_run'), 80)}` to `{safe_cell(history.get('latest_successful_run'), 80)}`",
                "",
            ]
        )
        history_metrics = history.get("elevated_metrics")
        if isinstance(history_metrics, list) and history_metrics:
            lines.extend(
                [
                    "| Metrik | Latest Delta | Max Recent Delta | Stable Since | Stable Minutes | Remaining Minutes | Last Significant Growth | Old-Window Eligible |",
                    "|---|---:|---:|---|---:|---:|---|---|",
                ]
            )
            for item in history_metrics:
                if not isinstance(item, dict):
                    continue
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            safe_cell(item.get("label"), 120),
                            safe_cell(item.get("latest_delta"), 40),
                            (
                                f"{safe_cell(item.get('max_recent_delta'), 40)} "
                                f"({safe_cell(item.get('latest_delta_comparability_reason'), 80)})"
                                if item.get("latest_delta_comparable") is False
                                else safe_cell(item.get("max_recent_delta"), 40)
                            ),
                            (
                                f"{safe_cell(item.get('stable_since_utc'), 80)} "
                                f"({safe_cell(item.get('stable_since_reason'), 80)})"
                            ),
                            safe_cell(item.get("stable_minutes"), 40),
                            safe_cell(item.get("remaining_stable_minutes_for_old_window"), 40),
                            safe_cell(item.get("last_significant_growth_at_utc"), 80),
                            f"`{safe_cell(item.get('stable_long_enough_for_old_window'), 40)}`",
                        ]
                    )
                    + " |"
                )
        blockers = history.get("old_window_blockers")
        if isinstance(blockers, list) and blockers:
            lines.extend(
                [
                    "",
                    "### OK Blockers",
                    "",
                    "| Metrik | Reason | Latest Delta | Max Recent Delta | Stable Since | Stable Minutes | Remaining Minutes |",
                    "|---|---|---:|---:|---|---:|---:|",
                ]
            )
            for item in blockers:
                if not isinstance(item, dict):
                    continue
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            safe_cell(item.get("label"), 120),
                            safe_cell(item.get("reason"), 120),
                            (
                                f"{safe_cell(item.get('latest_delta'), 40)} "
                                f"({safe_cell(item.get('delta_comparability_reason'), 80)})"
                                if item.get("latest_delta_comparable") is False
                                else safe_cell(item.get("latest_delta"), 40)
                            ),
                            safe_cell(item.get("max_recent_delta"), 40),
                            (
                                f"{safe_cell(item.get('stable_since_utc'), 80)} "
                                f"({safe_cell(item.get('stable_since_reason'), 80)})"
                            ),
                            safe_cell(item.get("stable_minutes"), 40),
                            safe_cell(item.get("remaining_stable_minutes_for_old_window"), 40),
                        ]
                    )
                    + " |"
                )
    return "\n".join(lines)


def markdown_ok_readiness(readiness: Dict[str, object]) -> str:
    summary = readiness.get("summary") if isinstance(readiness.get("summary"), dict) else {}
    lines = [
        "## OK Readiness",
        "",
        f"- Status: `{safe_cell(readiness.get('status'), 80)}`",
        f"- Policy: {safe_cell(readiness.get('policy'), 520)}",
        f"- Direct Status Blockers: `{safe_cell(summary.get('direct_status_blocker_count'), 40)}`; "
        f"Low-Growth Blockers: `{safe_cell(summary.get('low_growth_blocker_count'), 40)}`; "
        f"Aggregate Detail Blockers: `{safe_cell(summary.get('aggregate_detail_blocker_count'), 40)}`; "
        f"Diagnostic-only v2 Findings: `{safe_cell(summary.get('diagnostic_nonblocking_count'), 40)}`",
        "",
        "### Direct Status Blockers",
        "",
    ]
    direct = readiness.get("direct_status_blockers")
    if isinstance(direct, list) and direct:
        lines.extend(["| Metrik | Status | Wert | Effect | Reason |", "|---|---|---:|---|---|"])
        for item in direct:
            if not isinstance(item, dict):
                continue
            lines.append(
                "| "
                + " | ".join(
                    [
                        safe_cell(item.get("label"), 120),
                        f"`{safe_cell(item.get('status'), 60)}`",
                        safe_cell(item.get("value"), 40),
                        safe_cell(item.get("status_effect"), 100),
                        safe_cell(item.get("reason"), 260).replace("|", "\\|"),
                    ]
                )
                + " |"
            )
    else:
        lines.append("- Keine direkten Statusblocker.")

    lines.extend(["", "### Low-Growth Blockers", ""])
    low_growth = readiness.get("low_growth_blockers")
    if isinstance(low_growth, list) and low_growth:
        lines.extend(["| Metrik | Reason | Stable Since | Remaining Minutes |", "|---|---|---|---:|"])
        for item in low_growth:
            if not isinstance(item, dict):
                continue
            lines.append(
                "| "
                + " | ".join(
                    [
                        safe_cell(item.get("label"), 120),
                        safe_cell(item.get("reason"), 120),
                        f"{safe_cell(item.get('stable_since_utc'), 80)} ({safe_cell(item.get('stable_since_reason'), 80)})",
                        safe_cell(item.get("remaining_stable_minutes_for_old_window"), 40),
                    ]
                )
                + " |"
            )
    else:
        lines.append("- Keine Low-Growth-Blocker.")

    lines.extend(["", "### Aggregate Detail Blockers", ""])
    detail = readiness.get("aggregate_detail_blockers")
    if isinstance(detail, list) and detail:
        lines.extend(["| Key | Status | Wert | Effect | Reason |", "|---|---|---:|---|---|"])
        for item in detail:
            if not isinstance(item, dict):
                continue
            lines.append(
                "| "
                + " | ".join(
                    [
                        safe_cell(item.get("key"), 120),
                        f"`{safe_cell(item.get('status'), 80)}`",
                        safe_cell(item.get("value"), 40),
                        safe_cell(item.get("status_effect"), 120),
                        safe_cell(item.get("reason"), 300).replace("|", "\\|"),
                    ]
                )
                + " |"
            )
    else:
        lines.append("- Keine Aggregate-Detail-Blocker.")

    lines.extend(["", "### Diagnostic-only v2 Findings", ""])
    diagnostic = readiness.get("diagnostic_nonblocking_findings")
    if isinstance(diagnostic, list) and diagnostic:
        lines.extend(["| Signal | Status | Count | Effect | Recommendation |", "|---|---|---:|---|---|"])
        for item in diagnostic:
            if not isinstance(item, dict):
                continue
            lines.append(
                "| "
                + " | ".join(
                    [
                        safe_cell(item.get("signal_id"), 120),
                        f"`{safe_cell(item.get('status'), 60)}`",
                        safe_cell(item.get("count"), 40),
                        safe_cell(item.get("status_effect"), 100),
                        safe_cell(item.get("recommendation"), 260).replace("|", "\\|"),
                    ]
                )
                + " |"
            )
    else:
        lines.append("- Keine erhoehten diagnostic-only v2 Findings.")
    return "\n".join(lines)


def markdown_monitor_attempt_context(context: Dict[str, object]) -> str:
    evaluated = context.get("evaluated_run") if isinstance(context.get("evaluated_run"), dict) else {}
    newest = context.get("newest_attempt") if isinstance(context.get("newest_attempt"), dict) else {}
    lines = [
        "## Monitor Attempt Context",
        "",
        f"- Status: `{safe_cell(context.get('status'), 100)}`",
        f"- Interpretation: {safe_cell(context.get('interpretation'), 420)}",
        f"- Policy: {safe_cell(context.get('status_policy'), 420)}",
        f"- Evaluated Run: `{safe_cell(evaluated.get('run_id'), 80)}` (`{safe_cell(evaluated.get('status'), 80)}`)",
        f"- Newest Attempt: `{safe_cell(newest.get('run_id'), 80)}` (`{safe_cell(newest.get('status'), 80)}`)",
        f"- Newer Attempts: `{safe_cell(context.get('newer_attempt_count'), 40)}`; "
        f"failed `{safe_cell(context.get('newer_failed_attempt_count'), 40)}`; "
        f"successful `{safe_cell(context.get('newer_success_attempt_count'), 40)}`",
        f"- latest -> evaluated run: `{safe_cell(context.get('latest_points_to_evaluated_run'), 40)}`",
        "",
    ]
    attempts = context.get("newer_attempts")
    if not isinstance(attempts, list) or not attempts:
        lines.append("- Keine neueren Monitor-Versuche nach dem ausgewerteten Snapshot gefunden.")
        return "\n".join(lines)

    lines.extend(["| Run | Status | Generated | Errors | Missing |", "|---|---|---|---:|---|"])
    for item in attempts:
        if not isinstance(item, dict):
            continue
        missing = item.get("missing_files") if isinstance(item.get("missing_files"), list) else []
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{safe_cell(item.get('run_id'), 80)}`",
                    f"`{safe_cell(item.get('status'), 80)}`",
                    f"`{safe_cell(item.get('generated_at_utc'), 80)}`",
                    safe_cell(item.get("error_count"), 40),
                    markdown_list([safe_cell(value, 80) for value in missing], limit=4),
                ]
            )
            + " |"
        )
    return "\n".join(lines)


def markdown_actions_table(actions: Sequence[Dict[str, object]], empty_text: str) -> str:
    if not actions:
        return f"- {empty_text}"

    lines = [
        "| Action ID | Cloudflare Action | TTL Hours | Expression | Reason |",
        "|---|---|---:|---|---|",
    ]
    for action in actions:
        action_id = str(action.get("action_id", "n/a")).replace("|", "\\|")
        cloudflare_action = str(action.get("cloudflare_action", "n/a")).replace("|", "\\|")
        ttl = str(action.get("ttl_hours", "n/a")).replace("|", "\\|")
        expression = str(action.get("expression", "n/a")).replace("|", "\\|")
        reason = str(action.get("reason", "n/a")).replace("|", "\\|")
        if "created_rule_id" in action:
            reason = f"created_rule_id={action.get('created_rule_id')}"
        lines.append(f"| `{action_id}` | `{cloudflare_action}` | {ttl} | `{expression}` | {reason} |")
    return "\n".join(lines)


def action_safety_summary(action: Dict[str, object]) -> str:
    checks = action.get("safety_checks")
    if not isinstance(checks, list) or not checks:
        return "no action-specific checks"
    failed = [
        str(check.get("name", "unknown"))
        for check in checks
        if isinstance(check, dict) and not bool(check.get("passed"))
    ]
    if failed:
        return "failed: " + ", ".join(failed)
    return "allowlisted managed_challenge"


def markdown_active_defense_v1(mode: str, protective: ProtectiveModeResult) -> str:
    lines = [
        "## Active Defense v1",
        "",
        (
            "Active Defense v1 plant nur exakt allowlistete `managed_challenge`-Regeln. "
            "In `simulate` wird keine Cloudflare API genutzt; Anwendung erfordert `--mode apply-safe` "
            "und `--confirm-apply`."
        ),
        "",
        "| Action ID | Mode | Selected | Reason | Safety |",
        "|---|---|---:|---|---|",
    ]
    if not protective.planned_actions:
        lines.append(f"| - | `{mode}` | `false` | Keine allowlistete Aktion ausgewählt. | - |")
    else:
        for action in protective.planned_actions:
            reason = str(action.get("reason", "-")).replace("|", "\\|")
            lines.append(
                f"| `{action.get('action_id', '-')}` | `{mode}` | `true` | {reason} | "
                f"{action_safety_summary(action).replace('|', '\\|')} |"
            )
    return "\n".join(lines)


def markdown_skipped_table(skipped: Sequence[Dict[str, object]]) -> str:
    if not skipped:
        return "- Keine übersprungenen Aktionen."
    lines = ["| Grund | Details |", "|---|---|"]
    for item in skipped:
        reason = str(item.get("reason", "n/a")).replace("|", "\\|")
        details = ", ".join(f"{key}={value}" for key, value in item.items() if key != "reason")
        lines.append(f"| {reason} | {details or '-'} |")
    return "\n".join(lines)


def markdown_safety_checks(checks: Sequence[SafetyCheck]) -> str:
    if not checks:
        return "- Keine Safety Checks erzeugt."
    lines = ["| Check | Passed | Detail |", "|---|---:|---|"]
    for check in checks:
        detail = check.detail.replace("|", "\\|")
        lines.append(f"| `{check.name}` | `{str(check.passed).lower()}` | {detail} |")
    return "\n".join(lines)


def markdown_protective_mode(mode: str, correlation: CorrelationResult, protective: ProtectiveModeResult) -> str:
    selected_reason = ""
    if protective.planned_actions:
        selected_reason = str(protective.planned_actions[0].get("reason", "")).strip()

    lines = [
        "## Protective Mode",
        "",
        f"- Mode: `{mode}`",
        f"- Confirm Apply: `{str(protective.confirm_apply).lower()}`",
        f"- Correlation Status: `{correlation.correlation_status}`",
        f"- Apply Safe Enabled: `{str(protective.apply_safe_enabled).lower()}`",
        f"- Cloudflare API Used: `{str(protective.cloudflare_api_used).lower()}`",
        f"- Cloudflare Result Summary: {protective.cloudflare_result_summary}",
    ]
    if selected_reason:
        lines.append(f"- Selected Action Reason: {selected_reason}")
    lines.extend(
        [
            "",
            "### Planned Actions",
            "",
            markdown_actions_table(protective.planned_actions, "Keine geplanten Aktionen."),
            "",
            "### Applied Actions",
            "",
            markdown_actions_table(protective.applied_actions, "Keine angewendeten Aktionen."),
            "",
            "### Skipped Actions",
            "",
            markdown_skipped_table(protective.skipped_actions),
            "",
            "### Safety Checks",
            "",
            markdown_safety_checks(protective.safety_checks),
        ]
    )
    return "\n".join(lines)


def markdown_trend_layer(trend: TrendResult, history_path: Path, history_warnings: Sequence[str]) -> str:
    summary = trend.summary
    lines = [
        "## Trend Layer",
        "",
        f"- History Path: `{history_path}`",
        f"- Läufe ausgewertet: `{summary.get('runs')}`",
        "",
        "| Metrik | Wert |",
        "|---|---:|",
        f"| Overall CRITICAL | {summary.get('overall_critical_count')} |",
        f"| Correlation WATCH | {summary.get('correlation_watch_count')} |",
        f"| Correlation ACTION_CANDIDATE | {summary.get('correlation_action_candidate_count')} |",
        f"| Durchschnitt SiteLockSpider | {summary.get('avg_sitelockspider')} |",
        f"| Durchschnitt 5xx gesamt | {summary.get('avg_total_5xx')} |",
        f"| Durchschnitt 504 auf / | {summary.get('avg_root_504')} |",
        f"| Höchster SiteLockSpider-Wert | {summary.get('max_sitelockspider')} |",
        f"| Höchster 5xx-Wert | {summary.get('max_total_5xx')} |",
        "",
        "### Trend-Interpretation",
        "",
    ]
    for item in trend.interpretations:
        lines.append(f"- {item}")

    if history_warnings:
        lines.extend(["", "### History-Warnungen", ""])
        for warning in history_warnings:
            lines.append(f"- {warning}")

    return "\n".join(lines)


def render_markdown(
    *,
    report_path: Path,
    out_json_path: Path,
    mode: str,
    generated_at: str,
    results: Sequence[MetricResult],
    correlation: CorrelationResult,
    correlation_v2_findings: Sequence[CorrelationV2Finding],
    origin_pressure_breakdown: Dict[str, object],
    source_map_404_breakdown: Dict[str, object],
    notfound_404_path_breakdown: Dict[str, object],
    rolling_window_context: Dict[str, object],
    ok_readiness: Dict[str, object],
    monitor_attempt_context: Dict[str, object],
    protective: ProtectiveModeResult,
    trend: TrendResult,
    history_path: Path,
    history_warnings: Sequence[str],
) -> str:
    overall = overall_status(results)
    elevated = active_recommendations(results)

    lines = [
        "# Sentinel Defense Report",
        "",
        f"**Generated:** {generated_at} UTC  ",
        f"**Mode:** `{mode}`  ",
        f"**Overall Status:** `{overall}`  ",
        f"**Correlation Status:** `{correlation.correlation_status}`  ",
        f"**Operational Interpretation:** {correlation.operational_interpretation}  ",
        "**Correlation Layer v2:** Diagnose und Active-Defense-Signale; `correlation_status` bleibt unverändert.  ",
        f"**Source Report:** `{report_path}`  ",
        f"**JSON Output:** `{out_json_path}`",
        "",
        "## Sicherheitsgrenzen",
        "",
        "- Observe-only ist der Standard.",
        "- Dieser Bot liest lokale Reports und schreibt lokale Auswertungen.",
        "- Keine Cloudflare-Regeln werden veraendert.",
        "- Externe Systeme werden nur im 404-Priority-Breakdown read-only abgefragt (Live-Check /page/2/).",
        "- Keine Gegenangriffe, keine Scans, keine Credential-Sammlung.",
        "",
        "## Watchpoint-Bewertung",
        "",
        markdown_status_table(results),
        "",
        "## Correlation Layer",
        "",
        f"**Operational Interpretation:** {correlation.operational_interpretation}",
        "",
        markdown_correlation_table(correlation),
        "",
        "## Correlation Layer v2",
        "",
        (
            "Diese Diagnose-Schicht nutzt lokale Cloudflare-Rohdaten, um mehrere 5xx-Treiber "
            "sichtbar zu machen. Sie aendert keine Cloudflare-Regeln und erhoeht den bestehenden "
            "`correlation_status` nicht."
        ),
        "",
        markdown_correlation_v2_table(correlation_v2_findings),
        "",
        markdown_origin_pressure_breakdown(origin_pressure_breakdown),
        "",
        markdown_origin_timeout_action_checklist(origin_pressure_breakdown),
        "",
        markdown_source_map_404_breakdown(source_map_404_breakdown),
        "",
        markdown_notfound_404_path_breakdown(notfound_404_path_breakdown),
        "",
        markdown_rolling_window_context(rolling_window_context),
        "",
        markdown_ok_readiness(ok_readiness),
        "",
        markdown_monitor_attempt_context(monitor_attempt_context),
        "",
        markdown_active_defense_v1(mode, protective),
        "",
        markdown_protective_mode(mode, correlation, protective),
        "",
        markdown_trend_layer(trend, history_path, history_warnings),
        "",
        "## Defensive Empfehlungen",
        "",
    ]

    if not elevated:
        lines.append("- Keine erhoehten Watchpoints. Weiter beobachten.")
    else:
        for result in elevated:
            if result.status == STATUS_UNKNOWN:
                lines.append(f"- `{result.status}` `{result.label}`: {result.note}")
            else:
                lines.append(f"- `{result.status}` `{result.label}` ({result.value}): {result.recommendation}")

    for finding in correlation_v2_findings:
        if finding.status in {STATUS_WATCH, STATUS_WARNING, STATUS_CRITICAL}:
            lines.append(
                f"- `{finding.status}` `v2:{finding.signal_id}` ({finding.count}): {finding.recommendation}"
            )

    lines.extend(["", "## Simulationshinweise", ""])
    if mode == "simulate":
        actions = simulated_actions(results, correlation)
        if actions:
            for action in actions:
                lines.append(f"- {action}")
        else:
            lines.append("- Keine hypothetischen Aktionen erforderlich.")
        lines.append("- Es wurde nichts angewendet.")
    elif mode == "apply-safe":
        lines.append("- Apply-safe Ergebnis steht im Abschnitt `Protective Mode`.")
        lines.append("- Es wurden nur allowlistete Safety-Gates ausgewertet.")
    else:
        lines.append("- Nicht aktiv: `--mode observe` schreibt nur Bewertung und Empfehlungen.")
        lines.append("- Es wurde nichts angewendet.")

    unknown = [result for result in results if result.status == STATUS_UNKNOWN]
    if unknown:
        lines.extend(["", "## Parser-Hinweise", ""])
        for result in unknown:
            lines.append(f"- `{result.label}`: {result.note}")

    return "\n".join(lines) + "\n"


def build_json_payload(
    *,
    report_path: Path,
    out_md_path: Path,
    out_json_path: Path,
    mode: str,
    generated_at: str,
    results: Sequence[MetricResult],
    correlation: CorrelationResult,
    correlation_v2_findings: Sequence[CorrelationV2Finding],
    origin_pressure_breakdown: Dict[str, object],
    source_map_404_breakdown: Dict[str, object],
    notfound_404_path_breakdown: Dict[str, object],
    rolling_window_context: Dict[str, object],
    ok_readiness: Dict[str, object],
    monitor_attempt_context: Dict[str, object],
    protective: ProtectiveModeResult,
    trend: TrendResult,
    history_path: Path,
    history_warnings: Sequence[str],
) -> Dict[str, object]:
    elevated = active_recommendations(results)
    recommendation_entries = [
        {
            "metric": result.label,
            "status": result.status,
            "value": result.value,
            "recommendation": result.recommendation if result.status != STATUS_UNKNOWN else result.note,
        }
        for result in elevated
    ]
    recommendation_entries.extend(
        {
            "metric": f"v2:{finding.signal_id}",
            "status": finding.status,
            "value": finding.count,
            "recommendation": finding.recommendation,
        }
        for finding in correlation_v2_findings
        if finding.status in {STATUS_WATCH, STATUS_WARNING, STATUS_CRITICAL}
    )
    return {
        "schema_version": "1.0",
        "generated_at_utc": generated_at,
        "mode": mode,
        "overall_status": overall_status(results),
        "correlation_status": correlation.correlation_status,
        "operational_interpretation": correlation.operational_interpretation,
        "history_path": str(history_path),
        "source_report": str(report_path),
        "outputs": {
            "markdown": str(out_md_path),
            "json": str(out_json_path),
        },
        "safety": {
            "observe_only_default": True,
            "network_access": protective.cloudflare_api_used,
            "cloudflare_mutations": bool(protective.applied_actions),
            "external_scans": False,
            "counterattacks": False,
            "credential_collection": False,
        },
        "metrics": [
            {
                "key": result.key,
                "label": result.label,
                "source_label": result.source_label,
                "value": result.value,
                "status": result.status,
                "thresholds": {
                    "warning": result.warning,
                    "critical": result.critical,
                },
                "recommendation": result.recommendation,
                "note": result.note,
            }
            for result in results
        ],
        "recommendation_count": len(recommendation_entries),
        "recommendations": recommendation_entries,
        "correlation_findings": [
            {
                "signal": finding.signal,
                "value": finding.value,
                "interpretation": finding.interpretation,
                "recommended_next_action": finding.recommended_next_action,
            }
            for finding in correlation.findings
        ],
        "correlation_v2_findings": [
            {
                "signal_id": finding.signal_id,
                "status": finding.status,
                "count": finding.count,
                "paths": finding.paths,
                "user_agents": finding.user_agents,
                "countries": finding.countries,
                "explanation": finding.explanation,
                "recommendation": finding.recommendation,
            }
            for finding in correlation_v2_findings
        ],
        "origin_pressure_breakdown": origin_pressure_breakdown,
        "top_5xx_paths": origin_pressure_breakdown.get("top_5xx_paths", []),
        "top_5xx_cache_status": origin_pressure_breakdown.get("top_5xx_cache_status", []),
        "top_5xx_classification": origin_pressure_breakdown.get("top_5xx_classification", []),
        "top_5xx_status_inclusive_classification": origin_pressure_breakdown.get(
            "top_5xx_status_inclusive_classification", []
        ),
        "top_5xx_request_shapes": origin_pressure_breakdown.get("top_5xx_request_shapes", []),
        "top_5xx_actor_signals": origin_pressure_breakdown.get("top_5xx_actor_signals", []),
        "top_5xx_failure_modes": origin_pressure_breakdown.get("top_5xx_failure_modes", []),
        "source_map_404_breakdown": source_map_404_breakdown,
        "top_map_404_paths": source_map_404_breakdown.get("top_map_404_paths", []),
        "top_map_404_classification": source_map_404_breakdown.get("top_map_404_classification", []),
        "notfound_404_path_breakdown": notfound_404_path_breakdown,
        "top_notfound_404_paths": notfound_404_path_breakdown.get("top_paths", []),
        "page2_internal_link_check": notfound_404_path_breakdown.get("page2_internal_link_check", {}),
        "rolling_window_context": rolling_window_context,
        "ok_readiness": ok_readiness,
        "monitor_attempt_context": monitor_attempt_context,
        "simulated_actions": simulated_actions(results, correlation) if mode == "simulate" else [],
        "planned_actions": protective.planned_actions,
        "applied_actions": protective.applied_actions,
        "skipped_actions": protective.skipped_actions,
        "safety_checks": safety_checks_to_json(protective.safety_checks),
        "active_defense_v1": {
            "mode": mode,
            "planned_actions": protective.planned_actions,
            "applied_actions": protective.applied_actions,
            "skipped_actions": protective.skipped_actions,
            "safety_checks": safety_checks_to_json(protective.safety_checks),
        },
        "apply_safe_enabled": protective.apply_safe_enabled,
        "confirm_apply": protective.confirm_apply,
        "cloudflare_api_used": protective.cloudflare_api_used,
        "cloudflare_result_summary": protective.cloudflare_result_summary,
        "trend_summary": trend.summary,
        "trend_interpretation": trend.interpretations,
        "history_warnings": list(history_warnings),
    }


def expand_path(value: str) -> Path:
    path = Path(value).expanduser()
    if path.is_absolute():
        return path
    return Path.cwd() / path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate local Cloudflare daily monitor reports and generate defensive Sentinel recommendations."
    )
    parser.add_argument("--report", default=str(DEFAULT_REPORT), help="Path to cloudflare-daily-monitor.md")
    parser.add_argument("--out-md", default=str(DEFAULT_OUT_MD), help="Path for Markdown output")
    parser.add_argument("--out-json", default=str(DEFAULT_OUT_JSON), help="Path for JSON output")
    parser.add_argument("--history-path", default=str(DEFAULT_HISTORY_PATH), help="Path for Sentinel JSONL history")
    parser.add_argument(
        "--mode",
        choices=("observe", "simulate", "apply-safe", "consolidate-simulate", "consolidate-apply-safe"),
        default="observe",
        help="Defensive output mode",
    )
    parser.add_argument("--confirm-apply", action="store_true", help="Required before apply-safe may use Cloudflare API")
    parser.add_argument("--cloudflare-zone-id", default="", help="Cloudflare zone id for apply-safe")
    parser.add_argument("--cloudflare-ruleset-id", default="", help="Optional Cloudflare custom firewall ruleset id")
    parser.add_argument("--max-actions", type=int, default=2, help="Maximum apply-safe actions; must be <= 2")
    parser.add_argument("--action-ttl-hours", type=int, default=24, help="Documentation TTL for temporary actions")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report_path = expand_path(args.report)
    out_md_path = expand_path(args.out_md)
    out_json_path = expand_path(args.out_json)
    history_path = expand_path(args.history_path)
    mode = args.mode

    if mode in {"consolidate-simulate", "consolidate-apply-safe"}:
        return run_consolidation_mode(args, out_md_path, out_json_path)

    if not report_path.is_file():
        raise SystemExit(f"Report nicht gefunden: {report_path}")

    markdown = report_path.read_text(encoding="utf-8")
    results = evaluate(markdown)
    correlation = correlate(results)
    correlation_v2_findings = correlate_v2(report_path, results)
    origin_pressure_breakdown = build_origin_pressure_breakdown(report_path, results)
    source_map_404_breakdown = build_source_map_404_breakdown(report_path, results)
    notfound_404_path_breakdown = build_notfound_404_path_breakdown(report_path, results)
    rolling_window_context = build_rolling_window_context(report_path, results)
    ok_readiness = build_ok_readiness(
        results=results,
        correlation_v2_findings=correlation_v2_findings,
        origin_pressure_breakdown=origin_pressure_breakdown,
        source_map_404_breakdown=source_map_404_breakdown,
        rolling_window_context=rolling_window_context,
    )
    monitor_attempt_context = build_monitor_attempt_context(report_path)
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    out_md_path.parent.mkdir(parents=True, exist_ok=True)
    out_json_path.parent.mkdir(parents=True, exist_ok=True)
    protective = evaluate_protective_mode(
        mode=mode,
        confirm_apply=args.confirm_apply,
        cloudflare_zone_id=args.cloudflare_zone_id.strip() or None,
        cloudflare_ruleset_id=args.cloudflare_ruleset_id.strip() or None,
        max_actions=args.max_actions,
        action_ttl_hours=args.action_ttl_hours,
        results=results,
        correlation=correlation,
        correlation_v2_findings=correlation_v2_findings,
        generated_at=generated_at,
        output_dir=out_md_path.parent,
    )
    history_entries, history_warnings = load_history(history_path)
    history_record = build_history_record(
        timestamp=generated_at,
        mode=mode,
        overall=overall_status(results),
        correlation=correlation,
        results=results,
        protective=protective,
    )
    trend = summarize_trend(history_entries + [history_record])

    json_payload = build_json_payload(
        report_path=report_path,
        out_md_path=out_md_path,
        out_json_path=out_json_path,
        mode=mode,
        generated_at=generated_at,
        results=results,
        correlation=correlation,
        correlation_v2_findings=correlation_v2_findings,
        origin_pressure_breakdown=origin_pressure_breakdown,
        source_map_404_breakdown=source_map_404_breakdown,
        notfound_404_path_breakdown=notfound_404_path_breakdown,
        rolling_window_context=rolling_window_context,
        ok_readiness=ok_readiness,
        monitor_attempt_context=monitor_attempt_context,
        protective=protective,
        trend=trend,
        history_path=history_path,
        history_warnings=history_warnings,
    )
    markdown_output = render_markdown(
        report_path=report_path,
        out_json_path=out_json_path,
        mode=mode,
        generated_at=generated_at,
        results=results,
        correlation=correlation,
        correlation_v2_findings=correlation_v2_findings,
        origin_pressure_breakdown=origin_pressure_breakdown,
        source_map_404_breakdown=source_map_404_breakdown,
        notfound_404_path_breakdown=notfound_404_path_breakdown,
        rolling_window_context=rolling_window_context,
        ok_readiness=ok_readiness,
        monitor_attempt_context=monitor_attempt_context,
        protective=protective,
        trend=trend,
        history_path=history_path,
        history_warnings=history_warnings,
    )

    out_json_path.write_text(json.dumps(json_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    out_md_path.write_text(markdown_output, encoding="utf-8")

    history_write_warning = append_history(history_path, history_record)
    if history_write_warning:
        history_warnings = [*history_warnings, history_write_warning]
        json_payload = build_json_payload(
            report_path=report_path,
            out_md_path=out_md_path,
            out_json_path=out_json_path,
            mode=mode,
            generated_at=generated_at,
            results=results,
            correlation=correlation,
            correlation_v2_findings=correlation_v2_findings,
            origin_pressure_breakdown=origin_pressure_breakdown,
            source_map_404_breakdown=source_map_404_breakdown,
            notfound_404_path_breakdown=notfound_404_path_breakdown,
            rolling_window_context=rolling_window_context,
            ok_readiness=ok_readiness,
            monitor_attempt_context=monitor_attempt_context,
            protective=protective,
            trend=trend,
            history_path=history_path,
            history_warnings=history_warnings,
        )
        markdown_output = render_markdown(
            report_path=report_path,
            out_json_path=out_json_path,
            mode=mode,
            generated_at=generated_at,
            results=results,
            correlation=correlation,
            correlation_v2_findings=correlation_v2_findings,
            origin_pressure_breakdown=origin_pressure_breakdown,
            source_map_404_breakdown=source_map_404_breakdown,
            notfound_404_path_breakdown=notfound_404_path_breakdown,
            rolling_window_context=rolling_window_context,
            ok_readiness=ok_readiness,
            monitor_attempt_context=monitor_attempt_context,
            protective=protective,
            trend=trend,
            history_path=history_path,
            history_warnings=history_warnings,
        )
        out_json_path.write_text(json.dumps(json_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        out_md_path.write_text(markdown_output, encoding="utf-8")

    print(f"overall_status={json_payload['overall_status']}")
    print(f"correlation_status={json_payload['correlation_status']}")
    print(f"operational_interpretation={json_payload['operational_interpretation']}")
    print(f"cloudflare_api_used={json_payload['cloudflare_api_used']}")
    print(f"cloudflare_result_summary={json_payload['cloudflare_result_summary']}")
    print(f"history_path={history_path}")
    if history_warnings:
        for warning in history_warnings:
            print(f"history_warning={warning}")
    for item in protective.skipped_actions:
        print(f"skipped_action={item.get('reason', 'unknown')}")
    print(f"markdown={out_md_path}")
    print(f"json={out_json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
