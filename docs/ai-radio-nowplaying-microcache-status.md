# AI-Radio NowPlaying Microcache Status

Generated: `2026-05-31T10:37:17Z` UTC

## Confirmed Remediation

| Field | Value |
| --- | --- |
| microcache_deployed | `true` |
| deployed_on_host | `ubuntu-16gb-hel1-2` |
| origin_ip | `204.168.173.77` |
| endpoint | `/api/nowplaying/electri-city-ai-electro-radio` |
| local_validation | `MISS_THEN_HIT_CONFIRMED` |
| cache_header | `X-Sentinel-NowPlaying-Cache` |
| nginx_cache_ttl_seconds | `15` |
| stale_on_error | `true` |
| cloudflare_change | `false` |
| waf_change | `false` |

## Evidence

- Local HTTPS validation on the origin with `--resolve` to `127.0.0.1` returned one `MISS` followed by repeated `HIT` responses.
- The active origin Nginx configuration uses `proxy_cache sentinel_ai_radio_nowplaying`.
- The active origin Nginx configuration uses `proxy_cache_valid 200 15s`.
- The active origin Nginx configuration uses `proxy_cache_use_stale error timeout http_500 http_502 http_503 http_504 updating`.
- The cache header is emitted as `X-Sentinel-NowPlaying-Cache`.
- Cache files exist under `/var/cache/sentinel-ai-radio/nowplaying/` on `ubuntu-16gb-hel1-2`.

## Expected Effect

24h 504 window should decay if no new growth occurs. Sentinel must continue to treat raw 24h 5xx/504 totals conservatively until the rolling window confirms the old values have aged out.

## Next Action

Observe 24h rolling-window decay. Do not add a new WAF rule for this origin-timeout signal.
