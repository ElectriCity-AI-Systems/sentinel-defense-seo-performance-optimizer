#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="/srv/sentinel-defense"
BACKUP_ROOT="${BASE_DIR}/ionos-htaccess-backups"
RULE='RewriteRule ^hello-world/?$ - [G,L]'
RULE_COMMENT='# Electri_C_ity Sentinel: retire unused hello-world URL'

required_vars=(
  IONOS_SFTP_HOST
  IONOS_SFTP_USER
  IONOS_SFTP_PORT
  IONOS_SFTP_REMOTE_HTACCESS
  IONOS_SFTP_PASSWORD
)

for var_name in "${required_vars[@]}"; do
  if [[ -z "${!var_name:-}" ]]; then
    printf 'Missing required environment variable: %s\n' "$var_name" >&2
    exit 2
  fi
done

if command -v lftp >/dev/null 2>&1; then
  SFTP_TOOL="lftp"
elif command -v sshpass >/dev/null 2>&1 && command -v sftp >/dev/null 2>&1; then
  SFTP_TOOL="sshpass-sftp"
else
  printf 'No supported SFTP helper found. Install lftp, for example: sudo apt install lftp\n' >&2
  exit 3
fi

mkdir -p "$BASE_DIR" "$BACKUP_ROOT"

timestamp="$(date -u +%Y%m%d-%H%M%S)"
backup_dir="${BACKUP_ROOT}/${timestamp}"
mkdir -p "$backup_dir"

work_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$work_dir"
}
trap cleanup EXIT

downloaded_htaccess="${work_dir}/remote.htaccess"
working_htaccess="${work_dir}/working.htaccess"
verified_htaccess="${work_dir}/verified.htaccess"
backup_htaccess="${backup_dir}/.htaccess"

lftp_quote() {
  local value="$1"
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  printf '"%s"' "$value"
}

sftp_batch_quote() {
  local value="$1"
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  printf '"%s"' "$value"
}

sftp_download() {
  local remote_path="$1"
  local local_path="$2"

  if [[ "$SFTP_TOOL" == "lftp" ]]; then
    local lftp_script
    lftp_script="${work_dir}/download.lftp"
    {
      printf 'set sftp:auto-confirm yes\n'
      printf 'set cmd:fail-exit yes\n'
      printf 'set net:max-retries 1\n'
      printf 'set net:timeout 20\n'
      printf 'open -p %s -u %s,%s sftp://%s\n' \
        "$(lftp_quote "$IONOS_SFTP_PORT")" \
        "$(lftp_quote "$IONOS_SFTP_USER")" \
        "$(lftp_quote "$IONOS_SFTP_PASSWORD")" \
        "$(lftp_quote "$IONOS_SFTP_HOST")"
      printf 'get %s -o %s\n' "$(lftp_quote "$remote_path")" "$(lftp_quote "$local_path")"
      printf 'bye\n'
    } > "$lftp_script"
    chmod 600 "$lftp_script"
    if ! lftp -f "$lftp_script"; then
      printf 'SFTP download failed. No secrets were printed.\n' >&2
      return 1
    fi
  else
    local batch_file
    batch_file="${work_dir}/download.sftp"
    printf 'get %s %s\n' "$(sftp_batch_quote "$remote_path")" "$(sftp_batch_quote "$local_path")" > "$batch_file"
    chmod 600 "$batch_file"
    if ! SSHPASS="$IONOS_SFTP_PASSWORD" sshpass -e sftp \
      -oBatchMode=no \
      -oStrictHostKeyChecking=accept-new \
      -P "$IONOS_SFTP_PORT" \
      -b "$batch_file" \
      "${IONOS_SFTP_USER}@${IONOS_SFTP_HOST}"; then
      printf 'SFTP download failed. No secrets were printed.\n' >&2
      return 1
    fi
  fi
}

sftp_upload() {
  local local_path="$1"
  local remote_path="$2"

  if [[ "$SFTP_TOOL" == "lftp" ]]; then
    local lftp_script
    lftp_script="${work_dir}/upload.lftp"
    {
      printf 'set sftp:auto-confirm yes\n'
      printf 'set cmd:fail-exit yes\n'
      printf 'set net:max-retries 1\n'
      printf 'set net:timeout 20\n'
      printf 'open -p %s -u %s,%s sftp://%s\n' \
        "$(lftp_quote "$IONOS_SFTP_PORT")" \
        "$(lftp_quote "$IONOS_SFTP_USER")" \
        "$(lftp_quote "$IONOS_SFTP_PASSWORD")" \
        "$(lftp_quote "$IONOS_SFTP_HOST")"
      printf 'put %s -o %s\n' "$(lftp_quote "$local_path")" "$(lftp_quote "$remote_path")"
      printf 'bye\n'
    } > "$lftp_script"
    chmod 600 "$lftp_script"
    if ! lftp -f "$lftp_script"; then
      printf 'SFTP upload failed. Remote .htaccess may be unchanged; verify before retrying.\n' >&2
      return 1
    fi
  else
    local batch_file
    batch_file="${work_dir}/upload.sftp"
    printf 'put %s %s\n' "$(sftp_batch_quote "$local_path")" "$(sftp_batch_quote "$remote_path")" > "$batch_file"
    chmod 600 "$batch_file"
    if ! SSHPASS="$IONOS_SFTP_PASSWORD" sshpass -e sftp \
      -oBatchMode=no \
      -oStrictHostKeyChecking=accept-new \
      -P "$IONOS_SFTP_PORT" \
      -b "$batch_file" \
      "${IONOS_SFTP_USER}@${IONOS_SFTP_HOST}"; then
      printf 'SFTP upload failed. Remote .htaccess may be unchanged; verify before retrying.\n' >&2
      return 1
    fi
  fi
}

count_non_hello_gone_rules() {
  local path="$1"
  awk -v hello_rule="$RULE" '
    /RewriteRule .+\[G,L\]/ && $0 != hello_rule { count += 1 }
    END { print count + 0 }
  ' "$path"
}

printf 'SFTP environment: all required variables present.\n'
printf 'Using SFTP helper: %s\n' "$SFTP_TOOL"

sftp_download "$IONOS_SFTP_REMOTE_HTACCESS" "$downloaded_htaccess"
cp "$downloaded_htaccess" "$backup_htaccess"
cp "$downloaded_htaccess" "$working_htaccess"

if grep -Fqx "$RULE" "$working_htaccess"; then
  printf 'hello-world Gone rule already present; remote upload will be skipped.\n'
else
  if ! grep -Fq '# BEGIN WordPress' "$working_htaccess"; then
    printf 'Could not find "# BEGIN WordPress" in remote .htaccess; aborting without upload.\n' >&2
    printf 'Backup path: %s\n' "$backup_htaccess" >&2
    exit 4
  fi

  python3 - "$working_htaccess" "$RULE_COMMENT" "$RULE" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
comment = sys.argv[2]
rule = sys.argv[3]
text = path.read_text(encoding="utf-8")
marker = "# BEGIN WordPress"
insert = f"{comment}\n{rule}\n\n"
if rule in text.splitlines():
    raise SystemExit(0)
if marker not in text:
    raise SystemExit(4)
path.write_text(text.replace(marker, insert + marker, 1), encoding="utf-8")
PY

  changed_count="$(grep -Fxc "$RULE" "$working_htaccess")"
  if [[ "$changed_count" != "1" ]]; then
    printf 'Safety check failed: expected exactly one hello-world Gone rule, found %s.\n' "$changed_count" >&2
    exit 5
  fi

  extra_gone_rules="$(count_non_hello_gone_rules "$working_htaccess")"
  original_extra_gone_rules="$(count_non_hello_gone_rules "$downloaded_htaccess")"
  if [[ "$extra_gone_rules" != "$original_extra_gone_rules" ]]; then
    printf 'Safety check failed: non-hello-world Gone rules changed unexpectedly.\n' >&2
    exit 6
  fi

  sftp_upload "$working_htaccess" "$IONOS_SFTP_REMOTE_HTACCESS"
  printf 'Remote .htaccess uploaded with hello-world Gone rule.\n'
fi

sftp_download "$IONOS_SFTP_REMOTE_HTACCESS" "$verified_htaccess"
if grep -Fqx "$RULE" "$verified_htaccess"; then
  printf 'Remote verification: hello-world Gone rule present.\n'
else
  printf 'Remote verification failed: hello-world Gone rule missing after upload.\n' >&2
  exit 7
fi

printf 'Backup path: %s\n' "$backup_htaccess"
printf 'Rollback: upload the backup file back to $IONOS_SFTP_REMOTE_HTACCESS after manual review.\n'
printf '\n'
printf 'Public checks follow. Cloudflare Managed Challenge can mask Origin 410 as 403 with cf-mitigated: challenge.\n'

urls=(
  "https://electri-c-ity-studios-24-7.com/hello-world/"
  "https://electri-c-ity-studios-24-7.com/hello-world"
  "https://electri-c-ity-studios-24-7.com/app/"
  "https://electri-c-ity-studios-24-7.com/app"
  "https://electri-c-ity-studios-24-7.com/"
  "https://electri-c-ity-studios-24-7.com/wp-login.php"
  "https://electri-c-ity-studios-24-7.com/wp-json/"
  "https://electri-c-ity-studios-24-7.com/sitemap_index.xml"
)

for url in "${urls[@]}"; do
  status="$(curl -sS -o /dev/null -w '%{http_code}' -I --max-time 20 "$url" || true)"
  mitigated="$(curl -sS -I --max-time 20 "$url" 2>/dev/null | awk 'BEGIN{IGNORECASE=1} /^cf-mitigated:/ {print $2; exit}' | tr -d '\r' || true)"
  if [[ -n "$mitigated" ]]; then
    printf '%s -> HTTP %s (cf-mitigated: %s)\n' "$url" "$status" "$mitigated"
  else
    printf '%s -> HTTP %s\n' "$url" "$status"
  fi
done
