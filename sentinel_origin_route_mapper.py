#!/usr/bin/env python3
"""Sentinel origin route mapper — Phase 10.22.

Reconstructs the provable request route for first-party hosts:

    Client -> Cloudflare Edge -> Zone/DNS record -> Origin host
           -> Reverse proxy -> Upstream -> Application

Read-only. Cloudflare access is limited to GET on the zone and its DNS records;
no DNS, proxy-status, ruleset, SSL or load-balancer change is possible from this
module. Credential values are never written to any output.

Probes are restricted to hostnames inside the configured first-party zone and to
a fixed endpoint allowlist. Origin probes resolve only to an origin address that
authoritative Cloudflare DNS returned for that same hostname, so no arbitrary
host or URL can be reached. Response bodies are never stored; only status,
latency, size class, content type and a small header allowlist are recorded.

Every causal statement carries an evidence level:
PROVEN / STRONG / SUGGESTIVE / INSUFFICIENT / CONTRADICTED.
"""

from __future__ import annotations

import argparse
import http.client
import json
import re
import socket
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


PROJECT_DIR = Path(__file__).resolve().parent
SCHEMA_VERSION = "sentinel-origin-route-mapper-10.22"

REPORT_DIR = PROJECT_DIR / "reports/latest"
STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
AUDIT_DIR = PROJECT_DIR / "audit"
PLAYBOOK_DIR = PROJECT_DIR / "playbooks"
MONITOR_DIR = PROJECT_DIR / "cloudflare-monitor"

ENV_FILE = Path("/etc/sentinel-defense.env")
WEBSITE_JSON = REPORT_DIR / "sentinel-defense-report.json"

ROUTE_MAP_JSON = REPORT_DIR / "sentinel-origin-route-map.json"
ROUTE_MAP_MD = REPORT_DIR / "sentinel-origin-route-map.md"
OWNERSHIP_JSON = REPORT_DIR / "sentinel-origin-ownership.json"
OWNERSHIP_MD = REPORT_DIR / "sentinel-origin-ownership.md"
ENDPOINT_MATRIX_JSON = REPORT_DIR / "sentinel-endpoint-origin-matrix.json"
ENDPOINT_MATRIX_MD = REPORT_DIR / "sentinel-endpoint-origin-matrix.md"
NOWPLAYING_CHAIN_JSON = REPORT_DIR / "sentinel-nowplaying-origin-chain.json"
NOWPLAYING_CHAIN_MD = REPORT_DIR / "sentinel-nowplaying-origin-chain.md"

STATE_JSON = STATE_DIR / "origin_route_map.json"
HISTORY_JSON = STATE_DIR / "origin_route_map_history.json"
AUDIT_JSONL = AUDIT_DIR / "sentinel-origin-route-mapper.jsonl"

PLAYBOOKS = (PLAYBOOK_DIR / "sentinel-origin-route-discovery.playbook.json",)

# --------------------------------------------------------------------------- #
# Fixed scope — no free hosts, URLs or endpoints
# --------------------------------------------------------------------------- #

ZONE_APEX = "electri-c-ity-studios-24-7.com"

FIXED_ENDPOINTS: Tuple[Dict[str, str], ...] = (
    {"path": "/api/nowplaying/electri-city-ai-electro-radio", "host": f"ai-radio.{ZONE_APEX}"},
    {"path": "/api/time", "host": f"ai-radio.{ZONE_APEX}"},
    {"path": "/wp-json/wp/v2/users/me", "host": ZONE_APEX},
    {"path": "/", "host": ZONE_APEX},
    {"path": "/wp-login.php", "host": ZONE_APEX},
    {"path": "/page/2/", "host": ZONE_APEX},
    {"path": "/wp-admin/images/w-logo-gray.png", "host": ZONE_APEX},
)

NOWPLAYING_PATH = "/api/nowplaying/electri-city-ai-electro-radio"
NOWPLAYING_HOST = f"ai-radio.{ZONE_APEX}"
WP_USERS_ME_PATH = "/wp-json/wp/v2/users/me"

# Only these Cloudflare API paths may be requested, and only with GET.
ALLOWED_CF_API_PATHS = (
    "/zones/{zone_id}",
    "/zones/{zone_id}/dns_records",
)
CF_API_BASE = "https://api.cloudflare.com/client/v4"

PROBE_TIMEOUT_SECONDS = 20
PROBE_MAX_BODY_BYTES = 4096  # read only to size the response; never stored

# Headers that may be recorded from a probe. Nothing else is kept.
ALLOWED_RESPONSE_HEADERS = (
    "server",
    "content-type",
    "cache-control",
    "x-sentinel-nowplaying-cache",
    "cf-cache-status",
    "cf-ray",
    "age",
    "x-powered-by",
    "vary",
)

EVIDENCE_PROVEN = "PROVEN"
EVIDENCE_STRONG = "STRONG"
EVIDENCE_SUGGESTIVE = "SUGGESTIVE"
EVIDENCE_INSUFFICIENT = "INSUFFICIENT"
EVIDENCE_CONTRADICTED = "CONTRADICTED"

ORIGIN_CLASS_HETZNER = "HETZNER"
ORIGIN_CLASS_IONOS = "IONOS"
ORIGIN_CLASS_OTHER_FIRST_PARTY = "OTHER_FIRST_PARTY"
ORIGIN_CLASS_UNKNOWN = "UNKNOWN"

EXECUTION_BOUNDARIES = {
    "cloudflare_write": False,
    "dns_change": False,
    "proxy_status_change": False,
    "ruleset_change": False,
    "tls_change": False,
    "waf_change": False,
    "load_balancer_change": False,
    "origin_migration": False,
    "wordpress_write": False,
    "database_change": False,
    "nginx_change": False,
    "systemd_change": False,
    "credential_output": False,
    "cookie_storage": False,
    "authorization_header_storage": False,
    "response_body_storage": False,
    "free_shell": False,
    "arbitrary_hosts": False,
    "phase_type": "read_only_route_discovery",
}

REPORT_CLASSIFICATION = [
    "PRIVATE_OWNER_OPERATIONAL_REPORT",
    "NOT_FOR_PUBLIC_RELEASE",
    "NOT_FOR_GIT",
    "CONTAINS_INFRASTRUCTURE_METADATA",
]

SECRET_RE = re.compile(
    r"(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token|bearer|authorization|cookie|"
    r"private[_-]?key)\s*[:=]\s*[^\s,;]+"
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----")

IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

# Fixed, argument-free local commands. No shell, no user input.
FIXED_LOCAL_COMMANDS = {
    "local_ipv4": ("/usr/sbin/ip", "-j", "-4", "addr", "show"),
    "local_ipv6": ("/usr/sbin/ip", "-j", "-6", "addr", "show"),
}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_DIR.resolve()))
    except (OSError, ValueError):
        return str(path)


def is_within_project(path: Path) -> bool:
    try:
        path.resolve().relative_to(PROJECT_DIR.resolve())
        return True
    except (OSError, ValueError):
        return False


def ensure_dirs() -> None:
    for directory in (REPORT_DIR, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def write_text(path: Path, text: str) -> None:
    if not is_within_project(path):
        raise RuntimeError(f"write outside project blocked: {path}")
    if SECRET_RE.search(text) or PRIVATE_KEY_RE.search(text):
        raise RuntimeError(f"secret-like content blocked: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def write_json(path: Path, data: Any) -> None:
    text = json.dumps(data, indent=2, sort_keys=True)
    json.loads(text)
    write_text(path, text)


def append_jsonl(path: Path, row: Dict[str, Any]) -> None:
    if not is_within_project(path):
        raise RuntimeError(f"audit path outside project blocked: {path}")
    line = json.dumps(row, sort_keys=True)
    if SECRET_RE.search(line) or PRIVATE_KEY_RE.search(line):
        raise RuntimeError("secret-like audit content blocked")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def read_json(path: Path) -> Tuple[Any, str]:
    if not path.exists():
        return None, "missing"
    try:
        return json.loads(path.read_text(encoding="utf-8")), "ok"
    except json.JSONDecodeError:
        return None, "invalid_json"
    except OSError:
        return None, "read_error"


def load_dict(path: Path) -> Dict[str, Any]:
    data, status = read_json(path)
    return data if status == "ok" and isinstance(data, dict) else {}


def read_env_values() -> Dict[str, str]:
    """Safe parser for the environment file. Values are used, never emitted."""
    values: Dict[str, str] = {}
    if not ENV_FILE.exists():
        return values
    try:
        lines = ENV_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, _, value = line.partition("=")
        key = key.strip()
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            continue
        value = value.strip()
        if value[:1] in {"'", '"'} and value[-1:] == value[:1] and len(value) >= 2:
            value = value[1:-1]
        values[key] = value
    return values


def is_first_party_host(hostname: Any) -> bool:
    """Only the configured zone and its subdomains may ever be contacted."""
    if not isinstance(hostname, str) or not hostname.strip():
        return False
    host = hostname.strip().lower().rstrip(".")
    if ":" in host:
        host = host.split(":", 1)[0]
    return host == ZONE_APEX or host.endswith("." + ZONE_APEX)


def is_allowed_endpoint(host: str, path: str) -> bool:
    return any(item["host"] == host and item["path"] == path for item in FIXED_ENDPOINTS)


# --------------------------------------------------------------------------- #
# Cloudflare read-only access
# --------------------------------------------------------------------------- #

def cloudflare_get(api_path: str, zone_id: str, token: str, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """GET one allowlisted Cloudflare API path. No other method is implemented."""
    template = api_path
    if template not in ALLOWED_CF_API_PATHS:
        return {"status": "CF_PATH_NOT_ALLOWLISTED", "result": None}
    url = CF_API_BASE + template.format(zone_id=urllib.parse.quote(zone_id, safe=""))
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "SentinelDefense-RouteMapper/10.22",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=PROBE_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return {"status": "CF_HTTP_ERROR", "http_status": exc.code, "result": None}
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        return {"status": "CF_REQUEST_FAILED", "error_type": type(exc).__name__, "result": None}
    if not payload.get("success"):
        return {
            "status": "CF_API_UNSUCCESSFUL",
            "result": None,
            "error_codes": [item.get("code") for item in payload.get("errors", []) if isinstance(item, dict)],
        }
    return {"status": "CF_OK", "result": payload.get("result")}


def sanitize_dns_record(record: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": record.get("name"),
        "record_type": record.get("type"),
        "content": record.get("content"),
        "proxied": record.get("proxied"),
        "ttl": record.get("ttl"),
        "modified_on": record.get("modified_on"),
        "comment_present": bool(record.get("comment")),
    }


def discover_cloudflare() -> Dict[str, Any]:
    """Credential presence and read-only zone reachability. No values emitted."""
    env = read_env_values()
    token = env.get("CLOUDFLARE_API_TOKEN") or env.get("CF_API_TOKEN") or ""
    zone_id = env.get("CLOUDFLARE_ZONE_ID") or env.get("CF_ZONE_ID") or ""
    presence = {
        "cloudflare_api_token_present": bool(token),
        "cloudflare_zone_id_present": bool(zone_id),
        "env_file": str(ENV_FILE),
        "credential_values_disclosed": False,
    }
    if not (token and zone_id):
        return {
            "status": "CF_CREDENTIALS_MISSING",
            "presence": presence,
            "zone_name": None,
            "records": [],
            "read_only": True,
        }
    zone = cloudflare_get("/zones/{zone_id}", zone_id, token)
    zone_name = zone["result"].get("name") if zone["status"] == "CF_OK" and isinstance(zone.get("result"), dict) else None
    records_call = cloudflare_get("/zones/{zone_id}/dns_records", zone_id, token, {"per_page": "100"})
    records: List[Dict[str, Any]] = []
    if records_call["status"] == "CF_OK" and isinstance(records_call.get("result"), list):
        for item in records_call["result"]:
            if not isinstance(item, dict) or item.get("type") not in {"A", "AAAA", "CNAME"}:
                continue
            if not is_first_party_host(item.get("name")):
                continue
            records.append(sanitize_dns_record(item))
    status = "CF_READ_ONLY_OK" if zone["status"] == "CF_OK" and records_call["status"] == "CF_OK" else "CF_READ_ONLY_PARTIAL"
    if zone_name and zone_name != ZONE_APEX:
        status = "CF_ZONE_MISMATCH"
    return {
        "status": status,
        "presence": presence,
        "zone_name": zone_name,
        "zone_matches_configured_apex": zone_name == ZONE_APEX,
        "records": sorted(records, key=lambda row: (str(row.get("name")), str(row.get("record_type")))),
        "record_count": len(records),
        "zone_call_status": zone["status"],
        "records_call_status": records_call["status"],
        "read_only": True,
        "write_operations_attempted": 0,
    }


# --------------------------------------------------------------------------- #
# Local host identity
# --------------------------------------------------------------------------- #

def run_fixed_local(command_id: str) -> Dict[str, Any]:
    command = FIXED_LOCAL_COMMANDS.get(command_id)
    if command is None:
        return {"returncode": 126, "stdout": "", "error": "command_not_allowlisted"}
    try:
        result = subprocess.run(
            list(command), capture_output=True, text=True, timeout=15, shell=False, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"returncode": 127, "stdout": "", "error": type(exc).__name__}
    return {"returncode": result.returncode, "stdout": result.stdout, "error": None}


def local_host_identity() -> Dict[str, Any]:
    addresses: List[str] = []
    for command_id in ("local_ipv4", "local_ipv6"):
        result = run_fixed_local(command_id)
        if result["returncode"] != 0 or not result["stdout"].strip():
            continue
        try:
            payload = json.loads(result["stdout"])
        except json.JSONDecodeError:
            continue
        for interface in payload if isinstance(payload, list) else []:
            for info in interface.get("addr_info", []) if isinstance(interface, dict) else []:
                address = info.get("local") if isinstance(info, dict) else None
                if isinstance(address, str) and address:
                    addresses.append(address)
    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = "unknown"
    return {
        "hostname": hostname,
        "local_addresses": sorted(set(addresses)),
        "address_evidence": EVIDENCE_PROVEN if addresses else EVIDENCE_INSUFFICIENT,
    }


def ssh_profile_hosts() -> List[str]:
    """Known SSH profiles only. No discovery, no credential creation."""
    config = Path.home() / ".ssh/config"
    hosts: List[str] = []
    if not config.exists():
        return hosts
    try:
        for raw in config.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if line.lower().startswith("host ") and not line.lower().startswith("hostname"):
                hosts.extend(part for part in line.split()[1:] if part)
    except OSError:
        return hosts
    return sorted(set(hosts))


# --------------------------------------------------------------------------- #
# Read-only probes
# --------------------------------------------------------------------------- #

def probe(
    host: str,
    path: str,
    origin_address: Optional[str] = None,
    verify_tls: bool = True,
) -> Dict[str, Any]:
    """One bounded read-only GET. Bodies are never stored.

    `origin_address` pins the connection to an address that authoritative
    Cloudflare DNS returned for exactly this hostname, so no arbitrary host can
    be contacted. Without it the request goes through the Cloudflare edge.
    """
    layer = "ORIGIN" if origin_address else "EDGE"
    result: Dict[str, Any] = {
        "layer": layer,
        "hostname": host,
        "path": path,
        "origin_address": origin_address,
        "checked_at": utc_now(),
        "status_code": None,
        "latency_ms": None,
        "timed_out": False,
        "content_type": None,
        "response_size_class": None,
        "tls_verified": None,
        "headers": {},
        "error": None,
        "body_stored": False,
    }
    if not is_first_party_host(host) or not is_allowed_endpoint(host, path):
        result["error"] = "target_not_in_fixed_scope"
        return result
    if origin_address is not None and not IPV4_RE.match(origin_address):
        result["error"] = "origin_address_not_ipv4_literal"
        return result

    context = ssl.create_default_context()
    if origin_address:
        # Direct origin probe: the edge certificate is not presented by the origin,
        # so verification is relaxed for reachability testing only. Nothing from the
        # response body is read or trusted.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    started = datetime.now(timezone.utc)
    connection: Optional[http.client.HTTPSConnection] = None
    try:
        if origin_address:
            connection = _PinnedHTTPSConnection(host, origin_address, context, PROBE_TIMEOUT_SECONDS)
        else:
            connection = http.client.HTTPSConnection(
                host, 443, timeout=PROBE_TIMEOUT_SECONDS, context=context
            )
        connection.request(
            "GET",
            path,
            headers={
                "Host": host,
                "Accept": "*/*",
                "User-Agent": "SentinelDefense-RouteMapper/10.22",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        body = response.read(PROBE_MAX_BODY_BYTES)
        result["status_code"] = response.status
        result["headers"] = {
            key.lower(): value
            for key, value in response.getheaders()
            if key.lower() in ALLOWED_RESPONSE_HEADERS
        }
        result["content_type"] = response.getheader("Content-Type")
        result["response_size_class"] = size_class(len(body))
        result["tls_verified"] = origin_address is None
    except (TimeoutError, socket.timeout):
        result["timed_out"] = True
        result["error"] = "timeout"
        result["tls_verified"] = False
    except (ssl.SSLError, OSError, http.client.HTTPException) as exc:
        result["error"] = type(exc).__name__
        result["tls_verified"] = False
    finally:
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass
        result["latency_ms"] = round(
            (datetime.now(timezone.utc) - started).total_seconds() * 1000, 2
        )
    return result


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """TCP to an address proven by authoritative DNS, SNI and Host stay the hostname."""

    def __init__(self, host: str, pinned_address: str, context: ssl.SSLContext, timeout: int) -> None:
        super().__init__(host, 443, timeout=timeout, context=context)
        self._pinned_address = pinned_address

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_address, 443), self.timeout)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def size_class(size: int) -> str:
    if size <= 0:
        return "empty"
    if size < 1024:
        return "tiny"
    if size < 16 * 1024:
        return "small"
    if size < 256 * 1024:
        return "medium"
    return "large"


def edge_verdict(row: Dict[str, Any]) -> str:
    """A Cloudflare bot challenge is not endpoint health."""
    status = row.get("status_code")
    if row.get("timed_out"):
        return "EDGE_TIMEOUT"
    if status == 403 and str(row.get("content_type") or "").startswith("text/html"):
        return "EDGE_CHALLENGE_EXPECTED_FOR_NON_BROWSER"
    if status is None:
        return "EDGE_UNREACHABLE"
    if 200 <= int(status) < 400:
        return "EDGE_OK"
    if 500 <= int(status) < 600:
        return "EDGE_SERVER_ERROR"
    return "EDGE_OTHER"


def origin_verdict(row: Dict[str, Any]) -> str:
    status = row.get("status_code")
    if row.get("timed_out"):
        return "ORIGIN_TIMEOUT"
    if status is None:
        return "ORIGIN_UNREACHABLE"
    if 500 <= int(status) < 600:
        return "ORIGIN_SERVER_ERROR"
    if 200 <= int(status) < 400:
        return "ORIGIN_OK"
    return "ORIGIN_OTHER"


# --------------------------------------------------------------------------- #
# Ownership matrix
# --------------------------------------------------------------------------- #

def classify_origin(record: Dict[str, Any], zone_records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Provider classification requires evidence; otherwise UNKNOWN."""
    content = str(record.get("content") or "")
    record_type = record.get("record_type")
    reasons: List[str] = []

    if record_type == "CNAME" and content.endswith(".cfargotunnel.com"):
        return {
            "origin_class": ORIGIN_CLASS_OTHER_FIRST_PARTY,
            "origin_kind": "CLOUDFLARE_TUNNEL",
            "evidence_level": EVIDENCE_PROVEN,
            "reasons": ["CNAME target is a Cloudflare tunnel identifier."],
        }

    ionos_markers = [
        row.get("content") for row in zone_records
        if isinstance(row.get("content"), str) and "ionos." in str(row.get("content"))
    ]
    ionos_backup_dir = (PROJECT_DIR / "ionos-htaccess-backups").is_dir()

    if content.startswith("217.160.") or content.startswith("87.106."):
        if ionos_markers:
            reasons.append("Zone contains IONOS service records (autodiscover/_domainconnect).")
        if ionos_backup_dir:
            reasons.append("Repository holds IONOS webspace rollback material.")
        level = EVIDENCE_STRONG if reasons else EVIDENCE_SUGGESTIVE
        return {
            "origin_class": ORIGIN_CLASS_IONOS if reasons else ORIGIN_CLASS_UNKNOWN,
            "origin_kind": "SHARED_WEBSPACE" if reasons else "UNKNOWN",
            "evidence_level": level,
            "reasons": reasons or ["Address range alone is not provider evidence."],
        }

    return {
        "origin_class": ORIGIN_CLASS_OTHER_FIRST_PARTY if record_type in {"A", "AAAA"} else ORIGIN_CLASS_UNKNOWN,
        "origin_kind": "DEDICATED_OR_VPS" if record_type in {"A", "AAAA"} else "UNKNOWN",
        "evidence_level": EVIDENCE_SUGGESTIVE,
        "reasons": ["First-party zone record without independent provider evidence."],
    }


def build_ownership(discovery: Dict[str, Any], identity: Dict[str, Any]) -> Dict[str, Any]:
    records = discovery.get("records", [])
    local_addresses = set(identity.get("local_addresses", []))
    ssh_hosts = ssh_profile_hosts()
    relevant_hosts = {item["host"] for item in FIXED_ENDPOINTS}

    rows: List[Dict[str, Any]] = []
    for record in records:
        name = str(record.get("name") or "")
        content = str(record.get("content") or "")
        classification = classify_origin(record, records)
        local = content in local_addresses
        rows.append({
            "hostname": name,
            "cloudflare_zone": discovery.get("zone_name"),
            "dns_type": record.get("record_type"),
            "proxied": record.get("proxied"),
            "origin_target": content,
            "origin_class": classification["origin_class"],
            "origin_kind": classification["origin_kind"],
            "evidence_level": (
                EVIDENCE_PROVEN if discovery.get("status") == "CF_READ_ONLY_OK" else EVIDENCE_INSUFFICIENT
            ),
            "origin_class_evidence_level": classification["evidence_level"],
            "origin_class_reasons": classification["reasons"],
            "local_to_sentinel_host": local,
            "local_to_sentinel_host_evidence": (
                EVIDENCE_PROVEN if identity.get("address_evidence") == EVIDENCE_PROVEN else EVIDENCE_INSUFFICIENT
            ),
            "ssh_profile_available": any(host == name or host == content for host in ssh_hosts),
            "nginx_present": None,
            "apache_present": None,
            "application_class": None,
            "carries_monitored_endpoint": name in relevant_hosts,
            "remote_access_status": None,
        })

    for row in rows:
        if row["local_to_sentinel_host"]:
            row["remote_access_status"] = "LOCAL_HOST"
        elif row["ssh_profile_available"]:
            row["remote_access_status"] = "SSH_PROFILE_PRESENT"
        else:
            row["remote_access_status"] = "REMOTE_OWNER_ACTION_REQUIRED"

    known = [row for row in rows if row["evidence_level"] == EVIDENCE_PROVEN]
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "status": "ORIGIN_OWNERSHIP_OK" if known else "ORIGIN_OWNERSHIP_INSUFFICIENT",
        "report_classification": REPORT_CLASSIFICATION,
        "execution_boundaries": EXECUTION_BOUNDARIES,
        "zone": discovery.get("zone_name"),
        "cloudflare_status": discovery.get("status"),
        "sentinel_host": identity,
        "ssh_profiles_known": ssh_hosts,
        "hosts": sorted(rows, key=lambda row: str(row["hostname"])),
        "counts": {
            "records": len(rows),
            "known_origins": len(known),
            "unknown_origins": len(rows) - len(known),
            "local_origins": sum(1 for row in rows if row["local_to_sentinel_host"]),
            "remote_owner_action_required": sum(
                1 for row in rows if row["remote_access_status"] == "REMOTE_OWNER_ACTION_REQUIRED"
            ),
        },
    }


def origin_for_host(ownership: Dict[str, Any], hostname: str) -> Dict[str, Any]:
    candidates = [
        row for row in ownership.get("hosts", [])
        if row.get("hostname") == hostname and row.get("dns_type") in {"A", "CNAME"}
    ]
    for row in candidates:
        if row.get("dns_type") == "A":
            return row
    return candidates[0] if candidates else {}


# --------------------------------------------------------------------------- #
# Endpoint evidence from the current monitor snapshot
# --------------------------------------------------------------------------- #

def monitor_snapshot_dir() -> Optional[Path]:
    latest = MONITOR_DIR / "latest"
    if latest.is_symlink() or latest.is_dir():
        try:
            resolved = latest.resolve()
        except OSError:
            return None
        if is_within_project(resolved) and resolved.is_dir():
            return resolved
    return None


def endpoint_traffic() -> Dict[str, Dict[str, Any]]:
    """Per-endpoint request volume and status mix from the current snapshot."""
    snapshot = monitor_snapshot_dir()
    result: Dict[str, Dict[str, Any]] = {}
    if snapshot is None:
        return result
    data, status = read_json(snapshot / "top-paths-24h.json")
    if status != "ok":
        return result
    try:
        rows = data["data"]["viewer"]["zones"][0]["httpRequestsAdaptiveGroups"]
    except (KeyError, IndexError, TypeError):
        return result
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        dimensions = row.get("dimensions", {})
        path = dimensions.get("clientRequestPath")
        host = dimensions.get("clientRequestHTTPHost")
        if not isinstance(path, str) or not is_first_party_host(host):
            continue
        key = f"{host}{path}"
        entry = result.setdefault(key, {
            "hostname": host, "path": path, "requests_24h": 0, "status_counts": {},
            "cache_status_counts": {}, "country_counts": {},
        })
        count = int(row.get("count", 0) or 0)
        entry["requests_24h"] += count
        status_code = dimensions.get("edgeResponseStatus")
        if status_code is not None:
            entry["status_counts"][str(status_code)] = entry["status_counts"].get(str(status_code), 0) + count
        cache_status = dimensions.get("cacheStatus")
        if cache_status:
            entry["cache_status_counts"][str(cache_status)] = entry["cache_status_counts"].get(str(cache_status), 0) + count
        country = dimensions.get("clientCountryName")
        if country:
            entry["country_counts"][str(country)] = entry["country_counts"].get(str(country), 0) + count
    return result


def endpoint_5xx() -> Dict[str, Dict[str, Any]]:
    snapshot = monitor_snapshot_dir()
    result: Dict[str, Dict[str, Any]] = {}
    if snapshot is None:
        return result
    data, status = read_json(snapshot / "errors-5xx-24h.json")
    if status != "ok":
        return result
    try:
        rows = data["data"]["viewer"]["zones"][0]["httpRequestsAdaptiveGroups"]
    except (KeyError, IndexError, TypeError):
        return result
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        dimensions = row.get("dimensions", {})
        path = dimensions.get("clientRequestPath")
        host = dimensions.get("clientRequestHTTPHost")
        if not isinstance(path, str) or not is_first_party_host(host):
            continue
        key = f"{host}{path}"
        entry = result.setdefault(key, {
            "hostname": host, "path": path, "total_5xx": 0, "status_counts": {},
            "cache_status_counts": {}, "country_counts": {},
        })
        count = int(row.get("count", 0) or 0)
        entry["total_5xx"] += count
        status_code = dimensions.get("edgeResponseStatus")
        if status_code is not None:
            entry["status_counts"][str(status_code)] = entry["status_counts"].get(str(status_code), 0) + count
        cache_status = dimensions.get("cacheStatus")
        if cache_status:
            entry["cache_status_counts"][str(cache_status)] = entry["cache_status_counts"].get(str(cache_status), 0) + count
        country = dimensions.get("clientCountryName")
        if country:
            entry["country_counts"][str(country)] = entry["country_counts"].get(str(country), 0) + count
    return result


# --------------------------------------------------------------------------- #
# Endpoint -> origin matrix
# --------------------------------------------------------------------------- #

def repairability_for(
    endpoint: Dict[str, Any], ownership_row: Dict[str, Any], causality_status: str
) -> Dict[str, Any]:
    """Repairability is decided by access and evidence, never by failure volume."""
    if endpoint["path"] == WP_USERS_ME_PATH:
        return {
            "repairability": "OWNER_REVIEW_ONLY",
            "reason": (
                "The WordPress REST identity endpoint can carry authenticated context; "
                "caching, auth changes and REST permission changes are forbidden here."
            ),
            "automatic_repair_allowed": False,
        }
    if not ownership_row:
        return {
            "repairability": "UNKNOWN_ORIGIN",
            "reason": "No authoritative origin record; no repair may be planned.",
            "automatic_repair_allowed": False,
        }
    if ownership_row.get("remote_access_status") == "REMOTE_OWNER_ACTION_REQUIRED":
        return {
            "repairability": "REMOTE_OWNER_ACTION_REQUIRED",
            "reason": (
                f"The authoritative origin {ownership_row.get('origin_target')} is not this host "
                "and no verified access profile exists."
            ),
            "automatic_repair_allowed": False,
        }
    if causality_status != EVIDENCE_PROVEN:
        return {
            "repairability": "CAUSE_NOT_PROVEN",
            "reason": "Causality is not PROVEN; no automatic repair is permitted.",
            "automatic_repair_allowed": False,
        }
    return {
        "repairability": "SAFE_CANDIDATE",
        "reason": "Origin is local and cause is proven; a scoped Sentinel-owned repair may be prepared.",
        "automatic_repair_allowed": True,
    }


def build_endpoint_matrix(
    ownership: Dict[str, Any], probes: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    traffic = endpoint_traffic()
    errors = endpoint_5xx()
    rows: List[Dict[str, Any]] = []

    for item in FIXED_ENDPOINTS:
        host, path = item["host"], item["path"]
        key = f"{host}{path}"
        traffic_row = traffic.get(key, {})
        error_row = errors.get(key, {})
        ownership_row = origin_for_host(ownership, host)
        edge_probe = probes.get(f"EDGE:{key}", {})
        origin_probe = probes.get(f"ORIGIN:{key}", {})

        status_counts = error_row.get("status_counts", {})
        current_504 = int(status_counts.get("504", 0))
        current_503 = int(status_counts.get("503", 0))
        current_5xx = int(error_row.get("total_5xx", 0))
        requests_24h = int(traffic_row.get("requests_24h", 0))
        failure_ratio = round(current_5xx / requests_24h * 100, 2) if requests_24h else None

        origin_reachable = origin_verdict(origin_probe) == "ORIGIN_OK" if origin_probe else None
        causality_status, causality_reason = endpoint_causality(
            current_504, requests_24h, origin_probe, edge_probe, ownership_row
        )
        repairability = repairability_for(item, ownership_row, causality_status)

        rows.append({
            "endpoint": path,
            "hostname": host,
            "current_5xx": current_5xx,
            "current_504": current_504,
            "current_503": current_503,
            "requests_24h": requests_24h or None,
            "failure_ratio_percent": failure_ratio,
            "status_mix": traffic_row.get("status_counts", {}),
            "country_mix": error_row.get("country_counts", {}),
            "edge_class": edge_verdict(edge_probe) if edge_probe else "NOT_PROBED",
            "cache_class": (
                max(error_row.get("cache_status_counts", {}).items(), key=lambda pair: pair[1])[0]
                if error_row.get("cache_status_counts") else "unknown"
            ),
            "origin": ownership_row.get("origin_target"),
            "origin_class": ownership_row.get("origin_class"),
            "origin_evidence_level": ownership_row.get("evidence_level", EVIDENCE_INSUFFICIENT),
            "origin_local_to_sentinel_host": ownership_row.get("local_to_sentinel_host"),
            "origin_reachable_direct": origin_reachable,
            "origin_probe_verdict": origin_verdict(origin_probe) if origin_probe else "NOT_PROBED",
            "origin_probe_latency_ms": origin_probe.get("latency_ms"),
            "reverse_proxy": origin_probe.get("headers", {}).get("server"),
            "reverse_proxy_evidence": EVIDENCE_PROVEN if origin_probe.get("headers", {}).get("server") else EVIDENCE_INSUFFICIENT,
            "upstream": upstream_hint(origin_probe),
            "application": application_hint(origin_probe),
            "sentinel_cache_header": origin_probe.get("headers", {}).get("x-sentinel-nowplaying-cache"),
            "evidence_level": causality_status,
            "causality_status": causality_reason,
            "repairability": repairability["repairability"],
            "repairability_reason": repairability["reason"],
            "automatic_repair_allowed": repairability["automatic_repair_allowed"],
        })

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "status": "ENDPOINT_ORIGIN_MATRIX_OK" if rows else "ENDPOINT_ORIGIN_MATRIX_EMPTY",
        "report_classification": REPORT_CLASSIFICATION,
        "execution_boundaries": EXECUTION_BOUNDARIES,
        "snapshot_dir": rel(monitor_snapshot_dir()) if monitor_snapshot_dir() else None,
        "endpoints": rows,
        "counts": {
            "endpoints": len(rows),
            "with_known_origin": sum(1 for row in rows if row["origin_evidence_level"] == EVIDENCE_PROVEN),
            "automatic_repair_allowed": sum(1 for row in rows if row["automatic_repair_allowed"]),
        },
    }


def upstream_hint(origin_probe: Dict[str, Any]) -> Optional[str]:
    headers = origin_probe.get("headers", {}) if origin_probe else {}
    powered = headers.get("x-powered-by")
    if powered:
        return f"application runtime reported as {powered}"
    return None


def application_hint(origin_probe: Dict[str, Any]) -> Optional[str]:
    if not origin_probe:
        return None
    content_type = origin_probe.get("content_type")
    if content_type:
        return f"responds with {content_type}"
    return None


def endpoint_causality(
    current_504: int,
    requests_24h: int,
    origin_probe: Dict[str, Any],
    edge_probe: Dict[str, Any],
    ownership_row: Dict[str, Any],
) -> Tuple[str, str]:
    """Evidence level for the failing layer, never a guess."""
    if not ownership_row:
        return EVIDENCE_INSUFFICIENT, "ORIGIN_EVIDENCE_INSUFFICIENT"
    if current_504 == 0:
        return EVIDENCE_PROVEN, "NO_CURRENT_504"
    if not origin_probe:
        return EVIDENCE_INSUFFICIENT, "ORIGIN_NOT_PROBED"
    verdict = origin_verdict(origin_probe)
    if verdict == "ORIGIN_TIMEOUT":
        return EVIDENCE_PROVEN, "ORIGIN_TIMEOUT_REPRODUCED"
    if verdict in {"ORIGIN_UNREACHABLE"}:
        return EVIDENCE_STRONG, "ORIGIN_UNREACHABLE_FROM_SENTINEL_HOST"
    if verdict == "ORIGIN_SERVER_ERROR":
        return EVIDENCE_STRONG, "ORIGIN_RETURNS_SERVER_ERROR"
    # Origin answers cleanly while the edge records timeouts: the failing leg is
    # between edge and origin, or intermittent. That is not provable from here.
    return EVIDENCE_STRONG, "EDGE_TO_ORIGIN_INTERMITTENT_ORIGIN_HEALTHY_ON_DIRECT_PROBE"


# --------------------------------------------------------------------------- #
# Route map and NowPlaying chain
# --------------------------------------------------------------------------- #

def build_route_map(
    discovery: Dict[str, Any],
    ownership: Dict[str, Any],
    matrix: Dict[str, Any],
    probes: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    routes = []
    for row in matrix.get("endpoints", []):
        routes.append({
            "endpoint": row["endpoint"],
            "hostname": row["hostname"],
            "chain": [
                {"layer": "client", "status": "unknown", "evidence_level": EVIDENCE_INSUFFICIENT},
                {
                    "layer": "cloudflare_edge",
                    "status": row["edge_class"],
                    "evidence_level": EVIDENCE_PROVEN if row["edge_class"] != "NOT_PROBED" else EVIDENCE_INSUFFICIENT,
                },
                {
                    "layer": "cloudflare_dns_record",
                    "status": f"{row['origin']} proxied" if row["origin"] else "unknown",
                    "evidence_level": row["origin_evidence_level"],
                },
                {
                    "layer": "origin_host",
                    "status": row["origin_probe_verdict"],
                    "evidence_level": EVIDENCE_PROVEN if row["origin_probe_verdict"] != "NOT_PROBED" else EVIDENCE_INSUFFICIENT,
                },
                {
                    "layer": "reverse_proxy",
                    "status": row["reverse_proxy"] or "unknown",
                    "evidence_level": row["reverse_proxy_evidence"],
                },
                {
                    "layer": "upstream",
                    "status": row["upstream"] or "unknown",
                    "evidence_level": EVIDENCE_STRONG if row["upstream"] else EVIDENCE_INSUFFICIENT,
                },
                {
                    "layer": "application",
                    "status": row["application"] or "unknown",
                    "evidence_level": EVIDENCE_STRONG if row["application"] else EVIDENCE_INSUFFICIENT,
                },
            ],
            "causality_status": row["causality_status"],
            "evidence_level": row["evidence_level"],
        })
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "status": "ORIGIN_ROUTE_MAP_VALID" if ownership.get("counts", {}).get("known_origins") else "ORIGIN_ROUTE_MAP_PARTIAL",
        "report_classification": REPORT_CLASSIFICATION,
        "execution_boundaries": EXECUTION_BOUNDARIES,
        "zone": discovery.get("zone_name"),
        "cloudflare_status": discovery.get("status"),
        "sentinel_host": ownership.get("sentinel_host", {}),
        "routes": routes,
        "probe_count": len(probes),
        "counts": {
            "known_origins": ownership.get("counts", {}).get("known_origins", 0),
            "unknown_origins": ownership.get("counts", {}).get("unknown_origins", 0),
        },
    }


def build_nowplaying_chain(
    ownership: Dict[str, Any], matrix: Dict[str, Any], probes: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    key = f"{NOWPLAYING_HOST}{NOWPLAYING_PATH}"
    row = next(
        (item for item in matrix.get("endpoints", []) if item["endpoint"] == NOWPLAYING_PATH),
        {},
    )
    origin_probe = probes.get(f"ORIGIN:{key}", {})
    edge_probe = probes.get(f"EDGE:{key}", {})
    headers = origin_probe.get("headers", {}) if origin_probe else {}
    cache_header = headers.get("x-sentinel-nowplaying-cache")
    cache_control = headers.get("cache-control")

    microcache_state = {
        "expected_header": "x-sentinel-nowplaying-cache",
        "observed_header_value": cache_header,
        "present_at_actual_origin": bool(cache_header),
        "evidence_level": EVIDENCE_PROVEN if origin_probe and not origin_probe.get("error") else EVIDENCE_INSUFFICIENT,
        "cache_control": cache_control,
        "verdict": (
            "SENTINEL_MICROCACHE_ACTIVE_AT_ORIGIN" if cache_header
            else "SENTINEL_MICROCACHE_NOT_OBSERVED" if origin_probe and not origin_probe.get("error")
            else "SENTINEL_MICROCACHE_EVIDENCE_INSUFFICIENT"
        ),
        "historical_report_note": (
            "A historical MISS_THEN_HIT_CONFIRMED report is not current evidence; only the "
            "live origin probe above counts."
        ),
    }

    failure_class, failure_evidence, failure_reason = classify_nowplaying(row, origin_probe, edge_probe, microcache_state)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "status": failure_class,
        "report_classification": REPORT_CLASSIFICATION,
        "execution_boundaries": EXECUTION_BOUNDARIES,
        "endpoint": NOWPLAYING_PATH,
        "hostname": NOWPLAYING_HOST,
        "cloudflare_hostname": NOWPLAYING_HOST,
        "origin_target": row.get("origin"),
        "origin_class": row.get("origin_class"),
        "origin_evidence_level": row.get("origin_evidence_level"),
        "origin_local_to_sentinel_host": row.get("origin_local_to_sentinel_host"),
        "reverse_proxy": row.get("reverse_proxy"),
        "upstream": row.get("upstream"),
        "application": row.get("application"),
        "cache_layer": microcache_state,
        "edge_probe": edge_probe,
        "origin_probe": origin_probe,
        "current_504": row.get("current_504"),
        "requests_24h": row.get("requests_24h"),
        "failure_ratio_percent": row.get("failure_ratio_percent"),
        "country_mix": row.get("country_mix"),
        "failure_class": failure_class,
        "failure_evidence_level": failure_evidence,
        "failure_reason": failure_reason,
        "repairability": row.get("repairability"),
        "automatic_repair_allowed": row.get("automatic_repair_allowed", False),
    }


NOWPLAYING_CLASSES = (
    "NOWPLAYING_EDGE_TIMEOUT",
    "NOWPLAYING_ORIGIN_CONNECTION_TIMEOUT",
    "NOWPLAYING_REVERSE_PROXY_TIMEOUT",
    "NOWPLAYING_UPSTREAM_TIMEOUT",
    "NOWPLAYING_APPLICATION_TIMEOUT",
    "NOWPLAYING_CACHE_MISS_PRESSURE",
    "NOWPLAYING_CACHE_BYPASS",
    "NOWPLAYING_CACHE_STAMPEDE",
    "NOWPLAYING_STALE_FALLBACK_FAILED",
    "NOWPLAYING_WRONG_ORIGIN_ROUTE",
    "NOWPLAYING_BACKEND_UNAVAILABLE",
    "NOWPLAYING_REQUEST_STORM",
    "NOWPLAYING_HEALTHY",
    "NOWPLAYING_EVIDENCE_INSUFFICIENT",
)


def classify_nowplaying(
    row: Dict[str, Any],
    origin_probe: Dict[str, Any],
    edge_probe: Dict[str, Any],
    microcache_state: Dict[str, Any],
) -> Tuple[str, str, str]:
    """Classification from observed evidence only; the class never authorises a repair."""
    current_504 = int(row.get("current_504") or 0)
    if not row or row.get("origin_evidence_level") != EVIDENCE_PROVEN:
        return (
            "NOWPLAYING_EVIDENCE_INSUFFICIENT",
            EVIDENCE_INSUFFICIENT,
            "No authoritative origin record for the NowPlaying hostname.",
        )
    if current_504 == 0:
        return (
            "NOWPLAYING_HEALTHY",
            EVIDENCE_PROVEN,
            "No current 504 events for this endpoint in the current window.",
        )
    if not origin_probe or origin_probe.get("error") and not origin_probe.get("timed_out"):
        return (
            "NOWPLAYING_EVIDENCE_INSUFFICIENT",
            EVIDENCE_INSUFFICIENT,
            "The actual origin could not be probed; the failing layer stays unproven.",
        )
    if origin_probe.get("timed_out"):
        return (
            "NOWPLAYING_ORIGIN_CONNECTION_TIMEOUT",
            EVIDENCE_PROVEN,
            "A direct origin probe reproduced the timeout.",
        )
    verdict = origin_verdict(origin_probe)
    if verdict == "ORIGIN_SERVER_ERROR":
        return (
            "NOWPLAYING_BACKEND_UNAVAILABLE",
            EVIDENCE_STRONG,
            "The origin answers with a server error on a direct probe.",
        )
    if verdict == "ORIGIN_OK" and not microcache_state.get("present_at_actual_origin"):
        return (
            "NOWPLAYING_CACHE_BYPASS",
            EVIDENCE_STRONG,
            "The origin answers, but the expected Sentinel cache lane is not observable.",
        )
    if verdict == "ORIGIN_OK" and microcache_state.get("present_at_actual_origin"):
        return (
            "NOWPLAYING_EVIDENCE_INSUFFICIENT",
            EVIDENCE_INSUFFICIENT,
            (
                "The origin answers quickly from the intact Sentinel cache lane while the edge "
                "still records 504s. The failing leg lies between the Cloudflare edge and the "
                "origin, or is intermittent; origin-side logs are required to prove the layer."
            ),
        )
    return (
        "NOWPLAYING_EVIDENCE_INSUFFICIENT",
        EVIDENCE_INSUFFICIENT,
        "Observed evidence does not identify a single failing layer.",
    )


# --------------------------------------------------------------------------- #
# Probing plan
# --------------------------------------------------------------------------- #

def run_probes(ownership: Dict[str, Any], include_origin: bool = True) -> Dict[str, Dict[str, Any]]:
    probes: Dict[str, Dict[str, Any]] = {}
    for item in FIXED_ENDPOINTS:
        host, path = item["host"], item["path"]
        key = f"{host}{path}"
        probes[f"EDGE:{key}"] = probe(host, path)
        if not include_origin:
            continue
        ownership_row = origin_for_host(ownership, host)
        target = ownership_row.get("origin_target")
        if (
            ownership_row.get("dns_type") == "A"
            and isinstance(target, str)
            and IPV4_RE.match(target)
        ):
            probes[f"ORIGIN:{key}"] = probe(host, path, origin_address=target)
    return probes


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def private_header(title: str) -> List[str]:
    return [f"# {title}", "", "Classification: " + " | ".join(REPORT_CLASSIFICATION), ""]


def render_ownership(ownership: Dict[str, Any]) -> str:
    lines = private_header("Sentinel Origin Ownership")
    identity = ownership.get("sentinel_host", {})
    lines += [
        f"- status: `{ownership.get('status')}`",
        f"- generated: `{ownership.get('generated_at_utc')}`",
        f"- zone: `{ownership.get('zone')}`",
        f"- Cloudflare access: `{ownership.get('cloudflare_status')}` (read-only)",
        f"- Sentinel host: `{identity.get('hostname')}`",
        f"- Sentinel host addresses: `{', '.join(identity.get('local_addresses', [])) or 'unknown'}`",
        f"- known SSH profiles: `{', '.join(ownership.get('ssh_profiles_known', [])) or 'none'}`",
        "",
        "| Hostname | Type | Proxied | Origin target | Class | Origin evidence | Local | Access |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for row in ownership.get("hosts", []):
        lines.append(
            f"| `{row['hostname']}` | `{row['dns_type']}` | `{str(row['proxied']).lower()}` | "
            f"`{row['origin_target']}` | `{row['origin_class']}` | `{row['origin_class_evidence_level']}` | "
            f"`{str(row['local_to_sentinel_host']).lower()}` | `{row['remote_access_status']}` |"
        )
    counts = ownership.get("counts", {})
    lines += [
        "",
        "## Counts",
        "",
        f"- records: `{counts.get('records')}`",
        f"- known origins: `{counts.get('known_origins')}`",
        f"- unknown origins: `{counts.get('unknown_origins')}`",
        f"- origins local to this Sentinel host: `{counts.get('local_origins')}`",
        f"- origins requiring owner action: `{counts.get('remote_owner_action_required')}`",
        "",
        "## Safety",
        "",
        "- Cloudflare access is read-only: zone and DNS records are read, nothing is written.",
        "- No DNS, proxy status, ruleset, TLS or load balancer change is possible from this module.",
        "- Credential values are never written to any output.",
    ]
    return "\n".join(lines)


def render_endpoint_matrix(matrix: Dict[str, Any]) -> str:
    lines = private_header("Sentinel Endpoint to Origin Matrix")
    lines += [
        f"- status: `{matrix.get('status')}`",
        f"- generated: `{matrix.get('generated_at_utc')}`",
        f"- snapshot: `{matrix.get('snapshot_dir')}`",
        "",
        "| Endpoint | 5xx | 504 | Requests | Fail% | Edge | Cache | Origin | Origin probe | Evidence | Repairability |",
        "|---|---:|---:|---:|---:|---|---|---|---|---|---|",
    ]
    for row in matrix.get("endpoints", []):
        lines.append(
            f"| `{row['endpoint']}` | {row['current_5xx']} | {row['current_504']} | "
            f"{row['requests_24h'] or '-'} | {row['failure_ratio_percent'] if row['failure_ratio_percent'] is not None else '-'} | "
            f"`{row['edge_class']}` | `{row['cache_class']}` | `{row['origin']}` | "
            f"`{row['origin_probe_verdict']}` | `{row['evidence_level']}` | `{row['repairability']}` |"
        )
    lines += ["", "## Causality", ""]
    for row in matrix.get("endpoints", []):
        lines.append(
            f"- `{row['endpoint']}`: `{row['causality_status']}` ({row['evidence_level']}) — "
            f"{row['repairability_reason']}"
        )
    return "\n".join(lines)


def render_route_map(route_map: Dict[str, Any]) -> str:
    lines = private_header("Sentinel Origin Route Map")
    lines += [
        f"- status: `{route_map.get('status')}`",
        f"- generated: `{route_map.get('generated_at_utc')}`",
        f"- zone: `{route_map.get('zone')}`",
        f"- probes: `{route_map.get('probe_count')}`",
        "",
    ]
    for route in route_map.get("routes", []):
        lines += [
            f"## `{route['hostname']}{route['endpoint']}`",
            "",
            f"- causality: `{route['causality_status']}` (`{route['evidence_level']}`)",
            "",
            "| Layer | Status | Evidence |",
            "|---|---|---|",
        ]
        for step in route["chain"]:
            lines.append(f"| `{step['layer']}` | `{step['status']}` | `{step['evidence_level']}` |")
        lines.append("")
    return "\n".join(lines)


def render_nowplaying_chain(chain: Dict[str, Any]) -> str:
    lines = private_header("Sentinel NowPlaying Origin Chain")
    cache = chain.get("cache_layer", {})
    lines += [
        f"- endpoint: `{chain.get('endpoint')}`",
        f"- hostname: `{chain.get('hostname')}`",
        f"- failure class: `{chain.get('failure_class')}`",
        f"- failure evidence: `{chain.get('failure_evidence_level')}`",
        f"- current 504: `{chain.get('current_504')}`",
        f"- requests 24h: `{chain.get('requests_24h')}`",
        f"- failure ratio: `{chain.get('failure_ratio_percent')}%`",
        f"- country mix: `{chain.get('country_mix')}`",
        "",
        "## Route",
        "",
        f"- origin target: `{chain.get('origin_target')}` (`{chain.get('origin_evidence_level')}`)",
        f"- origin class: `{chain.get('origin_class')}`",
        f"- local to Sentinel host: `{str(chain.get('origin_local_to_sentinel_host')).lower()}`",
        f"- reverse proxy: `{chain.get('reverse_proxy')}`",
        f"- upstream: `{chain.get('upstream')}`",
        f"- application: `{chain.get('application')}`",
        "",
        "## Cache Layer",
        "",
        f"- verdict: `{cache.get('verdict')}`",
        f"- observed cache header: `{cache.get('observed_header_value')}`",
        f"- cache-control: `{cache.get('cache_control')}`",
        f"- evidence: `{cache.get('evidence_level')}`",
        f"- note: {cache.get('historical_report_note')}",
        "",
        "## Reason",
        "",
        f"- {chain.get('failure_reason')}",
        "",
        f"- repairability: `{chain.get('repairability')}`",
        f"- automatic repair allowed: `{str(chain.get('automatic_repair_allowed')).lower()}`",
    ]
    return "\n".join(lines)


def build_playbook() -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "name": "sentinel-origin-route-discovery",
        "status": "PLAYBOOK_ACTIVE",
        "principle": "evidence first; a route is only known when authoritative records prove it",
        "chain": [
            "client", "cloudflare_edge", "cloudflare_dns_record", "origin_host",
            "reverse_proxy", "upstream", "application",
        ],
        "evidence_levels": [
            EVIDENCE_PROVEN, EVIDENCE_STRONG, EVIDENCE_SUGGESTIVE,
            EVIDENCE_INSUFFICIENT, EVIDENCE_CONTRADICTED,
        ],
        "scope": {
            "zone": ZONE_APEX,
            "endpoints": [item["path"] for item in FIXED_ENDPOINTS],
            "cloudflare_api_paths": list(ALLOWED_CF_API_PATHS),
            "cloudflare_methods": ["GET"],
        },
        "forbidden": [
            "dns change", "proxy status change", "ruleset change", "ssl mode change",
            "origin rules change", "load balancer change", "arbitrary hosts",
            "arbitrary urls", "credential output", "response body storage",
        ],
        "execution_boundaries": EXECUTION_BOUNDARIES,
    }


# --------------------------------------------------------------------------- #
# Pipeline
# --------------------------------------------------------------------------- #

def build_all(include_origin_probes: bool = True) -> Dict[str, Any]:
    discovery = discover_cloudflare()
    identity = local_host_identity()
    ownership = build_ownership(discovery, identity)
    probes = run_probes(ownership, include_origin=include_origin_probes)
    matrix = build_endpoint_matrix(ownership, probes)
    route_map = build_route_map(discovery, ownership, matrix, probes)
    chain = build_nowplaying_chain(ownership, matrix, probes)
    return {
        "discovery": discovery,
        "identity": identity,
        "ownership": ownership,
        "probes": probes,
        "matrix": matrix,
        "route_map": route_map,
        "nowplaying_chain": chain,
    }


def persist(bundle: Dict[str, Any]) -> None:
    ensure_dirs()
    write_json(OWNERSHIP_JSON, bundle["ownership"])
    write_text(OWNERSHIP_MD, render_ownership(bundle["ownership"]))
    write_json(ENDPOINT_MATRIX_JSON, bundle["matrix"])
    write_text(ENDPOINT_MATRIX_MD, render_endpoint_matrix(bundle["matrix"]))
    write_json(ROUTE_MAP_JSON, bundle["route_map"])
    write_text(ROUTE_MAP_MD, render_route_map(bundle["route_map"]))
    write_json(NOWPLAYING_CHAIN_JSON, bundle["nowplaying_chain"])
    write_text(NOWPLAYING_CHAIN_MD, render_nowplaying_chain(bundle["nowplaying_chain"]))
    for path in PLAYBOOKS:
        write_json(path, build_playbook())

    chain = bundle["nowplaying_chain"]
    state = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "route_map_status": bundle["route_map"]["status"],
        "ownership_status": bundle["ownership"]["status"],
        "zone": bundle["ownership"].get("zone"),
        "sentinel_host": bundle["identity"].get("hostname"),
        "known_origins": bundle["ownership"]["counts"]["known_origins"],
        "unknown_origins": bundle["ownership"]["counts"]["unknown_origins"],
        "nowplaying_origin": chain.get("origin_target"),
        "nowplaying_origin_local": chain.get("origin_local_to_sentinel_host"),
        "nowplaying_failure_class": chain.get("failure_class"),
        "nowplaying_failure_evidence": chain.get("failure_evidence_level"),
        "nowplaying_automatic_repair_allowed": chain.get("automatic_repair_allowed"),
    }
    write_json(STATE_JSON, state)
    history, status = read_json(HISTORY_JSON)
    if status != "ok" or not isinstance(history, list):
        history = []
    history.append(state)
    write_json(HISTORY_JSON, history[-300:])
    append_jsonl(AUDIT_JSONL, {
        "timestamp_utc": state["generated_at_utc"],
        "event": "origin_route_mapped",
        "route_map_status": state["route_map_status"],
        "known_origins": state["known_origins"],
        "nowplaying_origin_local": state["nowplaying_origin_local"],
        "nowplaying_failure_class": state["nowplaying_failure_class"],
        "cloudflare_writes": 0,
        "dns_changes": 0,
    })


def validate() -> Dict[str, Any]:
    findings: List[str] = []
    for path in (ROUTE_MAP_JSON, OWNERSHIP_JSON, ENDPOINT_MATRIX_JSON, NOWPLAYING_CHAIN_JSON, *PLAYBOOKS):
        data, status = read_json(path)
        if status != "ok":
            findings.append(f"{status}:{path.name}")
    for path in (ROUTE_MAP_MD, OWNERSHIP_MD, ENDPOINT_MATRIX_MD, NOWPLAYING_CHAIN_MD):
        if not path.exists() or not path.read_text(encoding="utf-8").strip():
            findings.append(f"missing_markdown:{path.name}")
    ownership = load_dict(OWNERSHIP_JSON)
    for row in ownership.get("hosts", []):
        if not is_first_party_host(row.get("hostname")):
            findings.append(f"foreign_host_in_output:{row.get('hostname')}")
    matrix = load_dict(ENDPOINT_MATRIX_JSON)
    for row in matrix.get("endpoints", []):
        if not is_allowed_endpoint(row.get("hostname"), row.get("endpoint")):
            findings.append(f"endpoint_outside_scope:{row.get('endpoint')}")
        if row.get("automatic_repair_allowed") and row.get("evidence_level") != EVIDENCE_PROVEN:
            findings.append(f"repair_allowed_without_proof:{row.get('endpoint')}")
    return {
        "status": "ORIGIN_ROUTE_MAP_VALIDATION_OK" if not findings else "ORIGIN_ROUTE_MAP_VALIDATION_FAILED",
        "findings": findings,
    }


# --------------------------------------------------------------------------- #
# Self-test
# --------------------------------------------------------------------------- #

def run_self_test() -> Dict[str, Any]:
    checks: Dict[str, Any] = {}

    # Scope containment.
    checks["first_party_only"] = (
        is_first_party_host(ZONE_APEX)
        and is_first_party_host(f"ai-radio.{ZONE_APEX}")
        and not is_first_party_host("example.com")
        and not is_first_party_host(f"evil-{ZONE_APEX}.attacker.test")
        and not is_first_party_host(None)
    )
    checks["endpoint_allowlist"] = (
        is_allowed_endpoint(NOWPLAYING_HOST, NOWPLAYING_PATH)
        and not is_allowed_endpoint(NOWPLAYING_HOST, "/wp-admin/admin-ajax.php")
        and not is_allowed_endpoint("example.com", "/")
    )
    checks["probe_rejects_foreign_host"] = (
        probe("example.com", "/")["error"] == "target_not_in_fixed_scope"
    )
    checks["probe_rejects_unlisted_path"] = (
        probe(ZONE_APEX, "/wp-config.php")["error"] == "target_not_in_fixed_scope"
    )
    checks["probe_rejects_non_ip_origin"] = (
        probe(NOWPLAYING_HOST, NOWPLAYING_PATH, origin_address="evil.example.com")["error"]
        == "origin_address_not_ipv4_literal"
    )
    checks["cloudflare_path_allowlist"] = (
        cloudflare_get("/zones/{zone_id}/purge_cache", "z", "t")["status"] == "CF_PATH_NOT_ALLOWLISTED"
    )

    # Test A — Sentinel host is not the authoritative origin.
    identity = {"hostname": "sentinel-host", "local_addresses": ["10.0.0.1"], "address_evidence": EVIDENCE_PROVEN}
    discovery = {
        "status": "CF_READ_ONLY_OK",
        "zone_name": ZONE_APEX,
        "records": [
            {"name": NOWPLAYING_HOST, "record_type": "A", "content": "203.0.113.10", "proxied": True, "ttl": 1},
        ],
    }
    ownership = build_ownership(discovery, identity)
    row = origin_for_host(ownership, NOWPLAYING_HOST)
    checks["test_a_origin_not_local"] = row["local_to_sentinel_host"] is False
    checks["test_a_no_local_repair"] = (
        repairability_for(
            {"path": NOWPLAYING_PATH}, row, EVIDENCE_PROVEN
        )["automatic_repair_allowed"] is False
    )
    checks["test_a_remote_owner_action"] = row["remote_access_status"] == "REMOTE_OWNER_ACTION_REQUIRED"

    # Test B — authoritative record plus matching local address proves a local origin.
    local_identity = {"hostname": "sentinel-host", "local_addresses": ["203.0.113.10"], "address_evidence": EVIDENCE_PROVEN}
    local_ownership = build_ownership(discovery, local_identity)
    local_row = origin_for_host(local_ownership, NOWPLAYING_HOST)
    checks["test_b_origin_proven"] = local_row["evidence_level"] == EVIDENCE_PROVEN
    checks["test_b_origin_local"] = local_row["local_to_sentinel_host"] is True

    # Test H — no authoritative record means no repair.
    empty_ownership = build_ownership({"status": "CF_CREDENTIALS_MISSING", "zone_name": None, "records": []}, identity)
    empty_row = origin_for_host(empty_ownership, NOWPLAYING_HOST)
    unknown_repair = repairability_for({"path": NOWPLAYING_PATH}, empty_row, EVIDENCE_INSUFFICIENT)
    checks["test_h_unknown_origin"] = (
        empty_row == {}
        and unknown_repair["repairability"] == "UNKNOWN_ORIGIN"
        and unknown_repair["automatic_repair_allowed"] is False
    )
    checks["test_h_causality_insufficient"] = (
        endpoint_causality(10, 100, {}, {}, {})[0] == EVIDENCE_INSUFFICIENT
    )

    # Test F — the identity endpoint is never automatically repairable.
    checks["test_f_users_me_owner_only"] = (
        repairability_for({"path": WP_USERS_ME_PATH}, local_row, EVIDENCE_PROVEN)["automatic_repair_allowed"]
        is False
    )

    # A healthy origin probe with an intact cache lane must not claim a proven layer.
    chain_class, chain_evidence, _ = classify_nowplaying(
        {"origin_evidence_level": EVIDENCE_PROVEN, "current_504": 300},
        {"status_code": 200, "latency_ms": 8.0, "headers": {"x-sentinel-nowplaying-cache": "HIT"}},
        {"status_code": 403},
        {"present_at_actual_origin": True},
    )
    checks["healthy_origin_not_overclaimed"] = (
        chain_class == "NOWPLAYING_EVIDENCE_INSUFFICIENT" and chain_evidence == EVIDENCE_INSUFFICIENT
    )
    timeout_class, timeout_evidence, _ = classify_nowplaying(
        {"origin_evidence_level": EVIDENCE_PROVEN, "current_504": 300},
        {"timed_out": True, "headers": {}},
        {"status_code": 403},
        {"present_at_actual_origin": True},
    )
    checks["reproduced_timeout_is_proven"] = (
        timeout_class == "NOWPLAYING_ORIGIN_CONNECTION_TIMEOUT" and timeout_evidence == EVIDENCE_PROVEN
    )
    checks["classes_declared"] = chain_class in NOWPLAYING_CLASSES and timeout_class in NOWPLAYING_CLASSES
    checks["edge_challenge_not_health"] = (
        edge_verdict({"status_code": 403, "content_type": "text/html; charset=UTF-8"})
        == "EDGE_CHALLENGE_EXPECTED_FOR_NON_BROWSER"
    )

    # Structural safety.
    source_text = Path(__file__).read_text(encoding="utf-8")
    checks["no_shell_true"] = not re.search(r"shell\s*=\s*True", source_text)
    checks["fixed_local_commands"] = all(
        isinstance(value, tuple) for value in FIXED_LOCAL_COMMANDS.values()
    )
    checks["no_write_methods"] = not re.search(
        r'method\s*=\s*"(?:POST|PUT|PATCH|DELETE)"', source_text
    )
    checks["no_body_storage"] = '"body_stored": False' in source_text
    checks["execution_boundaries_closed"] = all(
        value is False for key, value in EXECUTION_BOUNDARIES.items() if isinstance(value, bool)
    )

    findings = [name for name, value in checks.items() if not value]
    return {
        "status": "ORIGIN_ROUTE_MAPPER_SELF_TEST_OK" if not findings else "ORIGIN_ROUTE_MAPPER_SELF_TEST_FAILED",
        "checks": checks,
        "findings": findings,
        "breach": False,
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel origin route mapper (Phase 10.22)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--discover", action="store_true")
    group.add_argument("--map-hosts", action="store_true")
    group.add_argument("--map-endpoints", action="store_true")
    group.add_argument("--validate", action="store_true")
    group.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        result = run_self_test()
        print(result["status"])
        for name in result["findings"]:
            print(f"finding={name}")
        return 0 if not result["findings"] else 1

    if args.discover:
        discovery = discover_cloudflare()
        print(discovery["status"])
        print(f"zone_matches_apex={discovery.get('zone_matches_configured_apex')}")
        print(f"first_party_records={discovery.get('record_count', 0)}")
        print(f"credential_values_disclosed={discovery['presence']['credential_values_disclosed']}")
        print("write_operations_attempted=0")
        return 0 if discovery["status"].startswith("CF_READ_ONLY") else 2

    if args.map_hosts:
        discovery = discover_cloudflare()
        identity = local_host_identity()
        ownership = build_ownership(discovery, identity)
        ensure_dirs()
        write_json(OWNERSHIP_JSON, ownership)
        write_text(OWNERSHIP_MD, render_ownership(ownership))
        print(ownership["status"])
        print(f"sentinel_host={identity.get('hostname')}")
        for row in ownership["hosts"]:
            if row["carries_monitored_endpoint"]:
                print(
                    f"{row['hostname']} -> {row['origin_target']} class={row['origin_class']} "
                    f"local={str(row['local_to_sentinel_host']).lower()} access={row['remote_access_status']}"
                )
        return 0

    if args.map_endpoints:
        bundle = build_all()
        persist(bundle)
        print(bundle["route_map"]["status"])
        for row in bundle["matrix"]["endpoints"]:
            print(
                f"{row['endpoint']} 504={row['current_504']} req={row['requests_24h']} "
                f"origin={row['origin']} probe={row['origin_probe_verdict']} "
                f"evidence={row['evidence_level']} repairability={row['repairability']}"
            )
        return 0

    if args.validate:
        result = validate()
        print(result["status"])
        for item in result["findings"]:
            print(f"finding={item}")
        return 0 if not result["findings"] else 2

    state = load_dict(STATE_JSON)
    if not state:
        print("ORIGIN_ROUTE_MAP_NOT_RUN")
        return 1
    print(state.get("route_map_status", "NOT_RUN"))
    for key in (
        "zone", "sentinel_host", "known_origins", "unknown_origins",
        "nowplaying_origin", "nowplaying_origin_local", "nowplaying_failure_class",
        "nowplaying_failure_evidence", "nowplaying_automatic_repair_allowed",
    ):
        print(f"{key}={state.get(key)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
