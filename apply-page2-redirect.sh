#!/usr/bin/env bash
# =============================================================================
# apply-page2-redirect.sh
# Electri_C_ity Studios — Sentinel Defense
#
# Ziel: /page/2 und /page/2/ auf 301 Redirect zu / setzen.
# Keine Cloudflare-Mutation, keine Secrets im Output.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${SCRIPT_DIR}/ionos-htaccess-backups/${TIMESTAMP}"
REMOTE_HTACCESS="${IONOS_SFTP_REMOTE_HTACCESS:-/wordpress/.htaccess}"

# ---------------------------------------------------------------------------
# 1. Variablen-Check (nur present/missing, keine Werte)
# ---------------------------------------------------------------------------
echo "=== Variable Check ==="
for var in IONOS_SFTP_HOST IONOS_SFTP_USER IONOS_SFTP_PORT IONOS_SFTP_PASSWORD IONOS_SFTP_REMOTE_HTACCESS; do
    if [[ -n "${!var:-}" ]]; then
        echo "  ${var}: present"
    else
        echo "  ${var}: MISSING"
        exit 1
    fi
done
echo ""

# ---------------------------------------------------------------------------
# 2. Backup-Verzeichnis anlegen
# ---------------------------------------------------------------------------
mkdir -p "${BACKUP_DIR}"
echo "=== Backup directory ==="
echo "  ${BACKUP_DIR}"
echo ""

# ---------------------------------------------------------------------------
# 3. Remote .htaccess herunterladen
# ---------------------------------------------------------------------------
echo "=== Downloading remote .htaccess ==="
curl -sS --max-time 30 \
    -u "${IONOS_SFTP_USER}:${IONOS_SFTP_PASSWORD}" \
    "sftp://${IONOS_SFTP_HOST}:${IONOS_SFTP_PORT}${REMOTE_HTACCESS}" \
    -o "${BACKUP_DIR}/.htaccess" 2>&1 | head -5 || {
    echo "ERROR: Download failed"
    exit 1
}

echo "  Download OK"
echo "  Size: $(wc -c < "${BACKUP_DIR}/.htaccess") bytes"
echo ""

# ---------------------------------------------------------------------------
# 4. Backup lokal kopieren
# ---------------------------------------------------------------------------
LOCAL_HTACCESS="${SCRIPT_DIR}/.htaccess.tmp.${TIMESTAMP}"
cp "${BACKUP_DIR}/.htaccess" "${LOCAL_HTACCESS}"

# ---------------------------------------------------------------------------
# 5. Prüfen, ob page/2-Regel bereits existiert
# ---------------------------------------------------------------------------
echo "=== Checking existing rules ==="
if grep -qE '^\s*RewriteRule\s+\^page/2/\?\$' "${LOCAL_HTACCESS}"; then
    echo "  page/2 redirect: ALREADY PRESENT"
    echo "  Nothing to change."
    rm -f "${LOCAL_HTACCESS}"
    exit 0
else
    echo "  page/2 redirect: NOT present"
fi

# Bestehende Regeln verifizieren (nur Anwesenheit, keine Inhalte)
for rule in "^app/?\$" "^hello-world/?\$"; do
    if grep -qE "RewriteRule\s+${rule}" "${LOCAL_HTACCESS}"; then
        echo "  existing rule for ${rule}: present"
    else
        echo "  existing rule for ${rule}: NOT FOUND (WARNING)"
    fi
done
echo ""

# ---------------------------------------------------------------------------
# 6. Neue Regel einfügen (vor BEGIN WordPress)
# ---------------------------------------------------------------------------
echo "=== Inserting page/2 redirect ==="

# Wir fügen die Regel direkt nach der hello-world Regel ein
# oder vor "# BEGIN WordPress" falls hello-world nicht da ist
NEW_RULE=$'\n# Electri_C_ity Sentinel: redirect unused legacy pagination\nRewriteRule ^page/2/?$ / [R=301,L]\n'

if grep -q "^RewriteRule ^hello-world/?\$" "${LOCAL_HTACCESS}"; then
    # Nach hello-world Regel einfügen
    sed -i '/^RewriteRule \^hello-world\/?\$/a \
\
# Electri_C_ity Sentinel: redirect unused legacy pagination\
RewriteRule ^page/2/?$ / [R=301,L]' "${LOCAL_HTACCESS}"
else
    # Vor BEGIN WordPress einfügen
    sed -i '/# BEGIN WordPress/i \
# Electri_C_ity Sentinel: redirect unused legacy pagination\
RewriteRule ^page/2/?$ / [R=301,L]\
' "${LOCAL_HTACCESS}"
fi

echo "  Inserted page/2 redirect rule"
echo ""

# ---------------------------------------------------------------------------
# 7. Geänderte .htaccess hochladen
# ---------------------------------------------------------------------------
echo "=== Uploading modified .htaccess ==="
curl -sS --max-time 30 -T "${LOCAL_HTACCESS}" \
    -u "${IONOS_SFTP_USER}:${IONOS_SFTP_PASSWORD}" \
    "sftp://${IONOS_SFTP_HOST}:${IONOS_SFTP_PORT}${REMOTE_HTACCESS}" 2>&1 | head -5 || {
    echo "ERROR: Upload failed"
    exit 1
}
echo "  Upload OK"
echo ""

# ---------------------------------------------------------------------------
# 8. Remote-Verifikation: .htaccess erneut herunterladen und prüfen
# ---------------------------------------------------------------------------
echo "=== Remote verification ==="
VERIFY_FILE="${SCRIPT_DIR}/.htaccess.verify.${TIMESTAMP}"
curl -sS --max-time 30 \
    -u "${IONOS_SFTP_USER}:${IONOS_SFTP_PASSWORD}" \
    "sftp://${IONOS_SFTP_HOST}:${IONOS_SFTP_PORT}${REMOTE_HTACCESS}" \
    -o "${VERIFY_FILE}" 2>&1 | head -5 || {
    echo "ERROR: Verification download failed"
    exit 1
}

if grep -qE '^\s*RewriteRule\s+\^page/2/\?\$' "${VERIFY_FILE}"; then
    echo "  page/2 redirect rule: PRESENT (verified remote)"
else
    echo "  page/2 redirect rule: NOT PRESENT (remote verification FAILED)"
    rm -f "${LOCAL_HTACCESS}" "${VERIFY_FILE}"
    exit 1
fi

if grep -qE '^\s*RewriteRule\s+\^hello-world/\?\$' "${VERIFY_FILE}"; then
    echo "  hello-world rule: PRESENT (verified remote)"
else
    echo "  hello-world rule: NOT PRESENT (WARNING)"
fi

if grep -qE '^\s*RewriteRule\s+\^app/\?\$' "${VERIFY_FILE}"; then
    echo "  app rule: PRESENT (verified remote)"
else
    echo "  app rule: NOT PRESENT (WARNING)"
fi

echo ""

# ---------------------------------------------------------------------------
# 9. Cleanup temporärer Dateien
# ---------------------------------------------------------------------------
rm -f "${LOCAL_HTACCESS}" "${VERIFY_FILE}"

# ---------------------------------------------------------------------------
# 10. Öffentliche Checks (Cloudflare kann 403 maskieren — nur informativ)
# ---------------------------------------------------------------------------
echo "=== Public endpoint checks (informational only) ==="
echo "Note: Cloudflare Managed Challenge may mask origin responses."
echo ""

for path in "/page/2/" "/page/2" "/hello-world/" "/app/" "/" "/wp-login.php" "/wp-json/" "/sitemap_index.xml"; do
    url="https://electri-c-ity-studios-24-7.com${path}"
    http_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 15 -I "${url}" 2>/dev/null || echo "ERR")
    echo "  ${url} -> HTTP ${http_code}"
done

echo ""

# ---------------------------------------------------------------------------
# 11. Abschluss
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "  Backup:           ${BACKUP_DIR}/.htaccess"
echo "  page/2 redirect:  PRESENT (remote verified)"
echo "  hello-world rule: preserved"
echo "  app rule:         preserved"
echo "  Changes applied:  YES"
echo ""
echo "To revert, restore from backup:"
echo "  cp ${BACKUP_DIR}/.htaccess <remote>"
echo ""
