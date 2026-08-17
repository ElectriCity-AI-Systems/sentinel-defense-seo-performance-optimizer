# Sentinel Current State

## Stand

Dieses Dokument beschreibt den dokumentierten Betriebsstand der SentinelDefense-Kette am 2026-05-22.

## Architektur

```text
Cloudflare Daily Monitor -> Sentinel Defense Bot -> Hetzner Local Agent -> Sentinel Master -> Daily Mail
```

Lokaler privater Ubuntu-PC:

```text
Sentinel Local Agent -> UFW -> fail2ban -> read-only Helper
```

## Website-Schutz

Aktive kombinierte Cloudflare-Regel:

```text
sentinel_combined_wordpress_scanner_challenge
```

Aktion:

```text
managed_challenge
```

Abgedeckte Pfade und Signale:

- SiteLockSpider auf `/wp-login.php`
- SiteLockSpider auf `/wp-json/oembed/1.0/embed`
- `/xmlrpc.php`
- `.env`
- `phpinfo`
- `secrets`
- host-gebunden auf `electri-c-ity-studios-24-7.com` und `www.electri-c-ity-studios-24-7.com`:
  - `_next`
  - `__rsc`
  - `__nextjs_action`
  - `api/auth`

Cloudflare-Regelstand:

- 4 Regeln insgesamt
- 3 fremde Regeln unveraendert
- alte SentinelDefense-Einzelregeln zusammengefuehrt
- Backup und Rollback-Hinweis vorhanden

## Betriebsmodell

Standardzyklus:

```text
observe -> correlate -> simulate -> apply-safe -> validate -> report
```

Apply-Safe ist kein unkontrollierter Autopilot. Regelanderungen brauchen Simulation, `--confirm-apply`, Backup, Rollback-Hinweis und Validierung.

## Daily Report Interpretation

Statuswerte:

- `OK`
- `WARNING`
- `CRITICAL`

Website Correlation Status:

- `NORMAL`
- `WATCH`
- `ACTION_CANDIDATE`

Action Status:

- `WARNING_REVIEW`
- `APPLY_CANDIDATE`
- `WATCH_ONLY`
- `LOCAL_ATTENTION`
- `OK`
- `UNKNOWN`

## Lokaler Status

Der private lokale Ubuntu-PC hatte zuletzt:

- `overall_status=OK`
- keine Findings

Ein Hetzner Local Agent `WARNING` kann parallel auftreten, ohne dass der private PC unsicher ist. Hetzner-Server und privater PC sind getrennte Schutzbereiche.

Aktueller Hetzner-Status nach lokaler Re-Klassifikation:

- UFW und fail2ban werden nicht mehr als `WARNING` gemeldet, wenn aktive lokale Evidenz vorliegt.
- `/etc/sentinel-defense.env` mit `0640 root:deploy` ist informational, solange world-read und group/world-write aus bleiben.
- fehlende `/home/deploy/.ssh/authorized_keys` ist informational, wenn deploy-user Key-Login bewusst deaktiviert oder anders geregelt ist.
- Der Hetzner read-only Helper ist dokumentiert in `SENTINEL_HETZNER_STATUS_HELPER.md` und ueber den Zielnamen `SENTINEL_HETZNER_READONLY_HELPER.md` auffindbar; sudoers wird nicht automatisch geaendert.

Der Master trennt:

- Website Status
- Hetzner Local Status
- Private PC Local Status
- Private PC Last Known Local Confirmation

## Sicherheitsgrenzen

- Keine Gegenangriffe.
- Keine fremden Scans.
- Keine Credential-Sammlung.
- Keine IP-, ASN- oder Country-Regeln.
- Keine globalen Blocks.
- Nur `managed_challenge`.
- Keine globale Challenge fuer alle `/api`-Pfade.
- Keine globale Challenge fuer alle `/wp-json`-Pfade.
- Fremde Cloudflare-Regeln nicht aendern.
- Keine Secrets in Logs oder Reports.
- Keine `.env`-Dateien mit `source` laden.

## Troubleshooting-Fokus

- Cloudflare Rules Limit `5/5`: Konsolidierung simulieren, fremde Regeln unveraendert lassen.
- `update failed`: Report, Backup und API-Response pruefen, nicht blind wiederholen.
- sudoers read-only Helper: nur eng allowlistete Lesekommandos.
- 24h Rolling Window: alte Cloudflare-Ereignisse bleiben bis zu 24h sichtbar.
- Website-OK-Blocker werden in `rolling_window_context.history.old_window_blockers[]` ausgewiesen. Solange dort `recent_significant_growth` oder `low_growth_but_not_24h` steht, bleibt Website-OK unbewiesen.
- `comparison_incompatible_requires_new_evidence` markiert Rohdaten-/Limitwechsel und startet fuer betroffene Detailmetriken neue stabile Evidenz.
- Rest-5xx werden in `origin_pressure_breakdown` nach Scanner, Origin, WordPress-Legacy, Cloudflare-Timeout und `unknown` getrennt. `unknown` bedeutet fehlende Detailabdeckung, nicht Entwarnung.
- `source_map_404_breakdown` trennt `.map`-404 nach WordPress-Minify/Core-Referenzen, Scanner-/Fake-Framework-Probes, statischen Asset-Referenzen und `unknown`; das ist Diagnose, keine Statussenkung.
- Aktueller Diagnosepfad nutzt tiefere read-only Monitor-Gruppierungen (`CLOUDFLARE_MONITOR_DETAIL_LIMIT=500`, `CLOUDFLARE_MONITOR_USER_AGENT_LIMIT=500`) fuer zukuenftige Laeufe; das aendert keine Cloudflare-Regeln.
