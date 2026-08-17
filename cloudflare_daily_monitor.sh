#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOKEN_FILE="${CLOUDFLARE_TOKEN_FILE:-$HOME/.config/cloudflare/codex-electri-city.token}"
ZONE_ID="${CLOUDFLARE_ZONE_ID:-dc6aafd51001b6050913257a99facdaa}"
ZONE_NAME="${CLOUDFLARE_ZONE_NAME:-electri-c-ity-studios-24-7.com}"
OUT_ROOT="${CLOUDFLARE_MONITOR_DIR:-$BASE_DIR/cloudflare-monitor}"
DETAIL_LIMIT="${CLOUDFLARE_MONITOR_DETAIL_LIMIT:-500}"
USER_AGENT_LIMIT="${CLOUDFLARE_MONITOR_USER_AGENT_LIMIT:-500}"

if [[ ! "$DETAIL_LIMIT" =~ ^[0-9]+$ || ! "$USER_AGENT_LIMIT" =~ ^[0-9]+$ ]]; then
  echo "Cloudflare monitor limits must be numeric." >&2
  exit 1
fi

if [[ ! -s "$TOKEN_FILE" ]]; then
  echo "Cloudflare token file missing or empty: $TOKEN_FILE" >&2
  exit 1
fi

TOKEN="$(tr -d '\r\n' < "$TOKEN_FILE")"
RUN_DIR="$OUT_ROOT/$(date +%Y%m%d-%H%M%S)"
PREV_DIR=""
if [[ -L "$OUT_ROOT/latest" ]]; then
  PREV_DIR="$(readlink -f "$OUT_ROOT/latest" || true)"
fi
mkdir -p "$RUN_DIR"

NOW_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SINCE_24H="$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)"

jq -n \
  --arg zone_id "$ZONE_ID" \
  --arg zone_name "$ZONE_NAME" \
  --arg generated_at_utc "$NOW_UTC" \
  --arg since_24h_utc "$SINCE_24H" \
  --argjson detail_limit "$DETAIL_LIMIT" \
  --argjson user_agent_limit "$USER_AGENT_LIMIT" \
  '{
    zone_id:$zone_id,
    zone_name:$zone_name,
    generated_at_utc:$generated_at_utc,
    since_24h_utc:$since_24h_utc,
    detail_limit:$detail_limit,
    user_agent_limit:$user_agent_limit
  }' \
  > "$RUN_DIR/meta.json"

gql() {
  local query="$1"
  local variables="$2"
  local output="$3"

  jq -n --arg q "$query" --argjson variables "$variables" '{query:$q, variables:$variables}' |
    curl -fsS --max-time 45 \
      -H "Authorization: Bearer ${TOKEN}" \
      -H 'Content-Type: application/json' \
      --data @- \
      https://api.cloudflare.com/client/v4/graphql \
      > "$output"
}

vars="$(jq -n --arg zoneTag "$ZONE_ID" --arg since "$SINCE_24H" --arg until "$NOW_UTC" '{zoneTag:$zoneTag,since:$since,until:$until}')"

gql 'query Hourly($zoneTag: string, $since: Time, $until: Time) {
  viewer { zones(filter: { zoneTag: $zoneTag }) {
    httpRequests1hGroups(limit: 30, filter: { datetime_geq: $since, datetime_leq: $until }, orderBy: [datetime_ASC]) {
      dimensions { datetime }
      sum { requests bytes cachedRequests cachedBytes threats pageViews encryptedRequests }
      uniq { uniques }
    }
  } }
}' "$vars" "$RUN_DIR/hourly-24h.json"

gql 'query Status($zoneTag: string, $since: Time, $until: Time) {
  viewer { zones(filter: { zoneTag: $zoneTag }) {
    httpRequestsAdaptiveGroups(limit: 30, filter: { datetime_geq: $since, datetime_leq: $until }, orderBy: [count_DESC]) {
      count
      dimensions { edgeResponseStatus }
      sum { edgeResponseBytes visits }
    }
  } }
}' "$vars" "$RUN_DIR/status-24h.json"

gql 'query Cache($zoneTag: string, $since: Time, $until: Time) {
  viewer { zones(filter: { zoneTag: $zoneTag }) {
    httpRequestsAdaptiveGroups(limit: 30, filter: { datetime_geq: $since, datetime_leq: $until }, orderBy: [count_DESC]) {
      count
      dimensions { cacheStatus }
      sum { edgeResponseBytes visits }
    }
  } }
}' "$vars" "$RUN_DIR/cache-24h.json"

gql "query SecurityActions(\$zoneTag: string, \$since: Time, \$until: Time) {
  viewer { zones(filter: { zoneTag: \$zoneTag }) {
    httpRequestsAdaptiveGroups(limit: ${DETAIL_LIMIT}, filter: { datetime_geq: \$since, datetime_leq: \$until, securityAction_neq: \"unknown\" }, orderBy: [count_DESC]) {
      count
      dimensions { securityAction securitySource edgeResponseStatus clientCountryName clientRequestHTTPHost clientRequestPath }
      sum { edgeResponseBytes visits }
    }
  } }
}" "$vars" "$RUN_DIR/security-actions-24h.json"

gql "query Errors5xx(\$zoneTag: string, \$since: Time, \$until: Time) {
  viewer { zones(filter: { zoneTag: \$zoneTag }) {
    httpRequestsAdaptiveGroups(limit: ${DETAIL_LIMIT}, filter: { datetime_geq: \$since, datetime_leq: \$until, edgeResponseStatus_geq: 500 }, orderBy: [count_DESC]) {
      count
      dimensions { clientRequestHTTPHost clientRequestPath edgeResponseStatus cacheStatus clientCountryName }
      sum { edgeResponseBytes visits }
    }
  } }
}" "$vars" "$RUN_DIR/errors-5xx-24h.json"

gql "query NotFound(\$zoneTag: string, \$since: Time, \$until: Time) {
  viewer { zones(filter: { zoneTag: \$zoneTag }) {
    httpRequestsAdaptiveGroups(limit: ${DETAIL_LIMIT}, filter: { datetime_geq: \$since, datetime_leq: \$until, edgeResponseStatus: 404 }, orderBy: [count_DESC]) {
      count
      dimensions { clientRequestHTTPHost clientRequestPath cacheStatus clientCountryName }
      sum { edgeResponseBytes visits }
    }
  } }
}" "$vars" "$RUN_DIR/notfound-404-24h.json"

gql "query TopPaths(\$zoneTag: string, \$since: Time, \$until: Time) {
  viewer { zones(filter: { zoneTag: \$zoneTag }) {
    httpRequestsAdaptiveGroups(limit: ${DETAIL_LIMIT}, filter: { datetime_geq: \$since, datetime_leq: \$until }, orderBy: [count_DESC]) {
      count
      dimensions { clientRequestHTTPHost clientRequestPath edgeResponseStatus cacheStatus clientCountryName securityAction securitySource }
      sum { edgeResponseBytes visits }
    }
  } }
}" "$vars" "$RUN_DIR/top-paths-24h.json"

gql 'query Countries($zoneTag: string, $since: Time, $until: Time) {
  viewer { zones(filter: { zoneTag: $zoneTag }) {
    httpRequestsAdaptiveGroups(limit: 30, filter: { datetime_geq: $since, datetime_leq: $until }, orderBy: [count_DESC]) {
      count
      dimensions { clientCountryName }
      sum { edgeResponseBytes visits }
    }
  } }
}' "$vars" "$RUN_DIR/countries-24h.json"

gql "query UserAgents(\$zoneTag: string, \$since: Time, \$until: Time) {
  viewer { zones(filter: { zoneTag: \$zoneTag }) {
    httpRequestsAdaptiveGroups(limit: ${USER_AGENT_LIMIT}, filter: { datetime_geq: \$since, datetime_leq: \$until }, orderBy: [count_DESC]) {
      count
      dimensions { userAgent edgeResponseStatus clientRequestPath clientCountryName }
      sum { edgeResponseBytes visits }
    }
  } }
}" "$vars" "$RUN_DIR/user-agents-24h.json"

for json in "$RUN_DIR"/*.json; do
  if jq -e '.errors and (.errors | length > 0)' "$json" >/dev/null 2>&1; then
    echo "GraphQL errors in $json" >&2
    jq '.errors' "$json" >&2
  fi
done

totals="$(jq -r '
  def pct($n;$d): if $d == 0 then "0.0" else ((($n * 10000 / $d) | round / 100) | tostring) end;
  [.data.viewer.zones[0].httpRequests1hGroups[]] as $h
  | ($h | map(.sum.requests) | add) as $req
  | ($h | map(.sum.bytes) | add) as $bytes
  | ($h | map(.sum.cachedRequests) | add) as $creq
  | ($h | map(.sum.cachedBytes) | add) as $cbytes
  | ($h | map(.sum.encryptedRequests) | add) as $enc
  | [$req, ($bytes / 1000000 | round), $creq, pct($creq;$req), ($cbytes / 1000000 | round), pct($cbytes;$bytes), pct($enc;$req), ($h | map(.sum.threats) | add), ($h | map(.sum.pageViews) | add)] | @tsv
' "$RUN_DIR/hourly-24h.json")"
read -r REQ MB CREQ CREQP CMB CMBP ENCP THREATS PAGEVIEWS <<< "$totals"

jq -n \
  --arg generated_at_utc "$NOW_UTC" \
  --arg since_24h_utc "$SINCE_24H" \
  --argjson requests "$REQ" \
  --argjson pageviews "$PAGEVIEWS" \
  --argjson bandwidth_mb "$MB" \
  --argjson cached_requests "$CREQ" \
  --arg cache_request_pct "$CREQP" \
  --argjson cached_mb "$CMB" \
  --arg cache_byte_pct "$CMBP" \
  --arg encrypted_pct "$ENCP" \
  --argjson threats "$THREATS" \
  --slurpfile status "$RUN_DIR/status-24h.json" \
  --slurpfile errors "$RUN_DIR/errors-5xx-24h.json" \
  --slurpfile notfound "$RUN_DIR/notfound-404-24h.json" \
  --slurpfile uas "$RUN_DIR/user-agents-24h.json" '
    def groups($x): $x[0].data.viewer.zones[0].httpRequestsAdaptiveGroups // [];
    def sum_counts($items): ($items | map(.count) | add) // 0;
    {
      generated_at_utc: $generated_at_utc,
      since_24h_utc: $since_24h_utc,
      requests: $requests,
      pageviews: $pageviews,
      bandwidth_mb: $bandwidth_mb,
      cached_requests: $cached_requests,
      cache_request_pct: ($cache_request_pct | tonumber),
      cached_mb: $cached_mb,
      cache_byte_pct: ($cache_byte_pct | tonumber),
      encrypted_pct: ($encrypted_pct | tonumber),
      threats: $threats,
      total_5xx: sum_counts(groups($status) | map(select(.dimensions.edgeResponseStatus >= 500))),
      wp_login_503: sum_counts(groups($errors) | map(select(.dimensions.edgeResponseStatus == 503 and .dimensions.clientRequestPath == "/wp-login.php"))),
      root_504: sum_counts(groups($errors) | map(select(.dimensions.edgeResponseStatus == 504 and .dimensions.clientRequestPath == "/"))),
      map_404: sum_counts(groups($notfound) | map(select(.dimensions.clientRequestPath | endswith(".map")))),
      oembed_503: sum_counts(groups($errors) | map(select(.dimensions.edgeResponseStatus == 503 and .dimensions.clientRequestPath == "/wp-json/oembed/1.0/embed"))),
      oembed_404: sum_counts(groups($notfound) | map(select(.dimensions.clientRequestPath == "/wp-json/oembed/1.0/embed"))),
      app_404: sum_counts(groups($notfound) | map(select(.dimensions.clientRequestPath == "/app" or .dimensions.clientRequestPath == "/app/"))),
      sitelock_top_user_agent_requests: sum_counts(groups($uas) | map(select(.dimensions.userAgent | contains("SiteLockSpider"))))
    }
  ' > "$RUN_DIR/metrics.json"

if [[ -n "$PREV_DIR" && -f "$PREV_DIR/metrics.json" ]]; then
  jq -n --slurpfile current "$RUN_DIR/metrics.json" --slurpfile previous "$PREV_DIR/metrics.json" '
    ($current[0]) as $c
    | ($previous[0]) as $p
    | {
        previous_generated_at_utc: $p.generated_at_utc,
        current_generated_at_utc: $c.generated_at_utc,
        deltas: {
          requests: ($c.requests - $p.requests),
          cache_request_pct: (($c.cache_request_pct - $p.cache_request_pct) * 100 | round / 100),
          cache_byte_pct: (($c.cache_byte_pct - $p.cache_byte_pct) * 100 | round / 100),
          total_5xx: ($c.total_5xx - $p.total_5xx),
          wp_login_503: ($c.wp_login_503 - $p.wp_login_503),
          root_504: ($c.root_504 - $p.root_504),
          map_404: ($c.map_404 - $p.map_404),
          oembed_503: ($c.oembed_503 - $p.oembed_503),
          oembed_404: ($c.oembed_404 - $p.oembed_404),
          app_404: ($c.app_404 - $p.app_404),
          sitelock_top_user_agent_requests: ($c.sitelock_top_user_agent_requests - $p.sitelock_top_user_agent_requests)
        }
      }
  ' > "$RUN_DIR/comparison.json"
fi

REPORT="$RUN_DIR/cloudflare-daily-monitor.md"
{
  printf '# Cloudflare Daily Monitor - %s\n\n' "$ZONE_NAME"
  printf '**Erstellt:** %s UTC  \n' "$NOW_UTC"
  printf '**Fenster:** %s bis %s UTC\n\n' "$SINCE_24H" "$NOW_UTC"

  printf '## Summary\n\n'
  printf -- '- Requests: `%s`, Pageviews: `%s`, Bandbreite: `%s MB`\n' "$REQ" "$PAGEVIEWS" "$MB"
  printf -- '- Cache: `%s%%` Requests, `%s%%` Bytes (`%s MB`)\n' "$CREQP" "$CMBP" "$CMB"
  printf -- '- TLS/Encrypted Requests: `%s%%`\n' "$ENCP"
  printf -- '- Threats: `%s`\n\n' "$THREATS"

  printf '## Watchpoints\n\n'
  printf '| Metrik | Wert letzte 24h |\n|---|---:|\n'
  jq -r '[
    ["5xx gesamt", .total_5xx],
    ["503 auf /wp-login.php", .wp_login_503],
    ["504 auf /", .root_504],
    ["404 auf .map", .map_404],
    ["503 auf oEmbed", .oembed_503],
    ["404 auf oEmbed", .oembed_404],
    ["404 auf /app", .app_404],
    ["SiteLockSpider in Top User-Agents", .sitelock_top_user_agent_requests]
  ][] | @tsv' "$RUN_DIR/metrics.json" |
    awk -F '\t' '{printf "| %s | %s |\n", $1, $2}'
  printf '\n'

  if [[ -f "$RUN_DIR/comparison.json" ]]; then
    printf '## Vergleich Zum Vorlauf\n\n'
    printf '| Metrik | Delta |\n|---|---:|\n'
    jq -r '.deltas | [
      ["Requests", .requests],
      ["Cache Request %", .cache_request_pct],
      ["Cache Byte %", .cache_byte_pct],
      ["5xx gesamt", .total_5xx],
      ["503 auf /wp-login.php", .wp_login_503],
      ["504 auf /", .root_504],
      ["404 auf .map", .map_404],
      ["503 auf oEmbed", .oembed_503],
      ["404 auf oEmbed", .oembed_404],
      ["404 auf /app", .app_404],
      ["SiteLockSpider Top-UA Requests", .sitelock_top_user_agent_requests]
    ][] | @tsv' "$RUN_DIR/comparison.json" |
      awk -F '\t' '{printf "| %s | %s |\n", $1, $2}'
    printf '\n'
  fi

  printf '## Statuscodes\n\n'
  printf '| Status | Requests | MB |\n|---:|---:|---:|\n'
  jq -r '.data.viewer.zones[0].httpRequestsAdaptiveGroups[] | [.dimensions.edgeResponseStatus, .count, (.sum.edgeResponseBytes / 1000000 | round)] | @tsv' "$RUN_DIR/status-24h.json" |
    awk -F '\t' '{printf "| %s | %s | %s |\n", $1, $2, $3}'
  printf '\n'

  printf '## Cache\n\n'
  printf '| Cache | Requests | MB |\n|---|---:|---:|\n'
  jq -r '.data.viewer.zones[0].httpRequestsAdaptiveGroups[] | [.dimensions.cacheStatus, .count, (.sum.edgeResponseBytes / 1000000 | round)] | @tsv' "$RUN_DIR/cache-24h.json" |
    awk -F '\t' '{printf "| `%s` | %s | %s |\n", $1, $2, $3}'
  printf '\n'

  printf '## 5xx Top\n\n'
  printf '| Count | Status | Country | Path | Cache |\n|---:|---:|---|---|---|\n'
  jq -r '.data.viewer.zones[0].httpRequestsAdaptiveGroups[0:15][] | [.count, .dimensions.edgeResponseStatus, .dimensions.clientCountryName, .dimensions.clientRequestPath, .dimensions.cacheStatus] | @tsv' "$RUN_DIR/errors-5xx-24h.json" |
    awk -F '\t' '{gsub(/\|/, "\\|", $4); printf "| %s | %s | %s | `%s` | `%s` |\n", $1, $2, $3, $4, $5}'
  printf '\n'

  printf '## 404 Top\n\n'
  printf '| Count | Country | Host | Path | Cache |\n|---:|---|---|---|---|\n'
  jq -r '.data.viewer.zones[0].httpRequestsAdaptiveGroups[0:15][] | [.count, .dimensions.clientCountryName, .dimensions.clientRequestHTTPHost, .dimensions.clientRequestPath, .dimensions.cacheStatus] | @tsv' "$RUN_DIR/notfound-404-24h.json" |
    awk -F '\t' '{gsub(/\|/, "\\|", $4); printf "| %s | %s | `%s` | `%s` | `%s` |\n", $1, $2, $3, $4, $5}'
  printf '\n'

  printf '## Security Actions\n\n'
  printf '| Count | Action | Source | Status | Country | Path |\n|---:|---|---|---:|---|---|\n'
  jq -r '.data.viewer.zones[0].httpRequestsAdaptiveGroups[0:15][] | [.count, .dimensions.securityAction, .dimensions.securitySource, .dimensions.edgeResponseStatus, .dimensions.clientCountryName, .dimensions.clientRequestPath] | @tsv' "$RUN_DIR/security-actions-24h.json" |
    awk -F '\t' '{gsub(/\|/, "\\|", $6); printf "| %s | `%s` | `%s` | %s | %s | `%s` |\n", $1, $2, $3, $4, $5, $6}'
  printf '\n'

  printf '## Top-Länder\n\n'
  printf '| Country | Requests | MB |\n|---|---:|---:|\n'
  jq -r '.data.viewer.zones[0].httpRequestsAdaptiveGroups[0:15][] | [.dimensions.clientCountryName, .count, (.sum.edgeResponseBytes / 1000000 | round)] | @tsv' "$RUN_DIR/countries-24h.json" |
    awk -F '\t' '{printf "| %s | %s | %s |\n", $1, $2, $3}'
  printf '\n'

  printf '## Rohdaten\n\n'
  printf -- '- `%s`\n' "$RUN_DIR"
} > "$REPORT"

ln -sfn "$RUN_DIR" "$OUT_ROOT/latest"
echo "$REPORT"
