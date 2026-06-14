#!/usr/bin/env python3
import datetime
import json
import os
import posixpath
from pathlib import Path

import paramiko

MARKERS = [
    "soc-schema-graph",
    "data-soc-schema",
    "#soc-entity",
    "#soc-website",
    "#soc-logo",
]

ALLOWED_EXTENSIONS = {
    ".php",
    ".html",
    ".htm",
    ".js",
    ".json",
    ".txt",
}

SKIP_DIR_PARTS = {
    "cache",
    "uploads/cache",
    "backup",
    "backups",
    "upgrade",
    "ai1wm-backups",
    "wflogs",
}

SKIP_FILE_TERMS = {
    "wp-config",
    ".env",
    "secret",
    "token",
    "key",
    "password",
    "credential",
}

OUT_JSON = Path("reports/latest/soc-schema-sftp-source-search.json")
OUT_MD = Path("reports/latest/soc-schema-sftp-source-search.md")
OWNER_MD = Path("drafts/owner/soc-schema-sftp-source-search-owner-review.md")
SNAPSHOT_DIR = Path("snapshots")
AUDIT = Path("audit/soc-schema-sftp-source-search.jsonl")

ALLOWED_WRITE_ROOTS = [
    "reports/latest",
    "drafts/owner",
    "snapshots",
    "audit",
]


def utc_ts():
    return datetime.datetime.now(datetime.UTC).strftime("%Y%m%d-%H%M%S")


def is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def ensure_allowed_write(path: Path):
    target = path.resolve()
    cwd = Path.cwd().resolve()

    for root in ALLOWED_WRITE_ROOTS:
        allowed = (cwd / root).resolve()
        if is_relative_to(target, allowed):
            return

    raise RuntimeError(f"blocked write outside allowed roots: {path}")


def write_text(path: Path, text: str):
    ensure_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def append_audit(path: Path, item: dict):
    ensure_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")


def safe_path(path: str) -> bool:
    lower = path.lower()

    if not path.startswith("/wordpress/wp-content/"):
        return False

    if any(term in lower for term in SKIP_FILE_TERMS):
        return False

    if any(part in lower for part in SKIP_DIR_PARTS):
        return False

    ext = posixpath.splitext(path)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def read_text_safely(sftp, path: str, max_bytes=350000):
    with sftp.open(path, "rb") as f:
        data = f.read(max_bytes + 1)

    if len(data) > max_bytes:
        return None, "file_too_large_skipped"

    try:
        return data.decode("utf-8", errors="replace"), None
    except Exception as exc:
        return None, str(exc)


def walk_limited(sftp, root: str, max_files=2500, max_depth=8):
    stack = [(root, 0)]
    files = []

    while stack and len(files) < max_files:
        current, depth = stack.pop()

        if depth > max_depth:
            continue

        try:
            entries = sftp.listdir_attr(current)
        except Exception:
            continue

        for entry in entries:
            name = entry.filename
            if name in {".", ".."}:
                continue

            path = posixpath.join(current, name)
            mode = entry.st_mode

            is_dir = str(oct(mode)).startswith("0o4") or bool(mode & 0o040000)

            if is_dir:
                lower = path.lower()
                if any(part in lower for part in SKIP_DIR_PARTS):
                    continue
                stack.append((path, depth + 1))
            else:
                if safe_path(path):
                    files.append(path)

    return files


def classify_hit(path: str):
    lower = path.lower()

    if "/mu-plugins/" in lower:
        return "mu_plugin"
    if "/plugins/" in lower:
        parts = lower.split("/plugins/", 1)[1].split("/")
        return f"plugin:{parts[0]}" if parts else "plugin"
    if "/themes/" in lower:
        parts = lower.split("/themes/", 1)[1].split("/")
        return f"theme:{parts[0]}" if parts else "theme"

    return "wp_content_other"


def find_marker_context(text: str, marker: str, radius=120):
    idx = text.lower().find(marker.lower())
    if idx < 0:
        return None

    start = max(0, idx - radius)
    end = min(len(text), idx + len(marker) + radius)
    snippet = text[start:end]

    # Do not leak long code or possible secrets. Keep tiny context only.
    snippet = " ".join(snippet.split())
    return snippet[:300]


def run():
    ts = utc_ts()

    result = {
        "phase": "6.7-soc-schema-sftp-source-search",
        "timestamp_utc": ts,
        "status": None,
        "breach": False,
        "error": None,
        "host": os.environ.get("SENTINEL_SFTP_HOST"),
        "remote_search_root": None,
        "connected": False,
        "files_scanned": 0,
        "files_skipped": 0,
        "hits_count": 0,
        "hits": [],
        "recommended_next_step": None,
        "safety": {
            "read_only": True,
            "writes_remote": False,
            "sftp_rename": False,
            "sftp_put": False,
            "sftp_remove": False,
            "sftp_mkdir": False,
            "password_output": False,
        },
    }

    host = os.environ["SENTINEL_SFTP_HOST"]
    port = int(os.environ.get("SENTINEL_SFTP_PORT", "22"))
    user = os.environ["SENTINEL_SFTP_USER"]
    password = os.environ["SENTINEL_SFTP_PASSWORD"]
    root = os.environ["SENTINEL_SFTP_REMOTE_ROOT"].rstrip("/")
    search_root = posixpath.join(root, "wp-content")

    result["remote_search_root"] = search_root

    if search_root != "/wordpress/wp-content":
        result["status"] = "SOC_SCHEMA_SFTP_SOURCE_SEARCH_BREACH"
        result["breach"] = True
        result["error"] = f"unexpected search root: {search_root}"
    else:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.load_host_keys(str(Path.home() / ".ssh" / "known_hosts"))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

        try:
            client.connect(
                hostname=host,
                port=port,
                username=user,
                password=password,
                timeout=20,
                banner_timeout=20,
                auth_timeout=20,
                look_for_keys=False,
                allow_agent=False,
            )
            result["connected"] = True

            sftp = client.open_sftp()
            files = walk_limited(sftp, search_root)

            for path in files:
                text, err = read_text_safely(sftp, path)
                if err:
                    result["files_skipped"] += 1
                    continue

                result["files_scanned"] += 1

                matched = []
                contexts = {}

                for marker in MARKERS:
                    if marker.lower() in text.lower():
                        matched.append(marker)
                        contexts[marker] = find_marker_context(text, marker)

                if matched:
                    result["hits"].append({
                        "path": path,
                        "classification": classify_hit(path),
                        "matched_markers": matched,
                        "safe_context_preview": contexts,
                    })

            sftp.close()

            result["hits_count"] = len(result["hits"])

            if result["hits_count"] > 0:
                result["status"] = "SOC_SCHEMA_SFTP_SOURCE_SEARCH_FOUND"
                result["recommended_next_step"] = "Review the hit path(s). Do not edit automatically."
            else:
                result["status"] = "SOC_SCHEMA_SFTP_SOURCE_SEARCH_NO_HITS"
                result["recommended_next_step"] = "Search may be generated dynamically from database/plugin options. Use WordPress admin manual review."

        except Exception as exc:
            result["status"] = "SOC_SCHEMA_SFTP_SOURCE_SEARCH_FAILED"
            result["breach"] = False
            result["error"] = str(exc)

        finally:
            client.close()

    snapshot_json = SNAPSHOT_DIR / f"soc-schema-sftp-source-search-{ts}.json"
    snapshot_md = SNAPSHOT_DIR / f"soc-schema-sftp-source-search-{ts}.md"

    json_text = json.dumps(result, indent=2, ensure_ascii=False)

    lines = [
        "# SOC Schema SFTP Source Search",
        "",
        f"- status: {result['status']}",
        f"- breach: {result['breach']}",
        f"- connected: {result['connected']}",
        f"- remote_search_root: {result['remote_search_root']}",
        f"- files_scanned: {result['files_scanned']}",
        f"- files_skipped: {result['files_skipped']}",
        f"- hits_count: {result['hits_count']}",
        f"- error: `{result['error']}`",
        "",
        "## Hits",
        "",
    ]

    for hit in result["hits"]:
        lines.extend([
            f"### {hit['path']}",
            "",
            f"- classification: {hit['classification']}",
            f"- matched_markers: {', '.join(hit['matched_markers'])}",
            "",
        ])

    lines.extend([
        "## Safety",
        "",
        "- Read-only SFTP search.",
        "- No SFTP upload.",
        "- No SFTP rename.",
        "- No SFTP delete.",
        "- No WordPress, Cloudflare, Nginx, .htaccess, database, theme, systemd or crontab change.",
        "- Password was used only as an environment variable and not written to reports.",
    ])

    md_text = "\n".join(lines) + "\n"

    write_text(OUT_JSON, json_text + "\n")
    write_text(OUT_MD, md_text)
    write_text(OWNER_MD, md_text)
    write_text(snapshot_json, json_text + "\n")
    write_text(snapshot_md, md_text)
    append_audit(AUDIT, result)

    print(json_text)
    return 2 if result["breach"] else 0


if __name__ == "__main__":
    raise SystemExit(run())
