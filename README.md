# Sentinel Defense Documentation

## Uebersicht

Sentinel Defense ist eine defensive, report-getriebene Schutzkette fuer Website, Hetzner-Server und private lokale Ubuntu-Maschine.

```text
Cloudflare Daily Monitor -> Sentinel Defense Bot -> Hetzner Local Agent -> Sentinel Master -> Daily Mail
```

Ergaenzend schuetzt der private lokale Rechner sich selbst:

```text
Sentinel Local Agent -> UFW -> fail2ban -> read-only Helper
```

Die Schutzebenen sind dauerhaft im Sinne aktivierter Regeln, Timer und lokaler Agenten. Neue produktive Aenderungen werden nicht blind automatisch gesetzt.

## Komponenten

Website:

- `cloudflare_daily_monitor.sh` erzeugt den Cloudflare Daily Monitor Report.
- `sentinel_defense_bot.py` bewertet Watchpoints, Correlation Layer v2 und Trend Layer.
- Die aktive Cloudflare-Regel `sentinel_combined_wordpress_scanner_challenge` ist dauerhaft aktiv.

Hetzner-Server:

- `sentinel_hetzner_local_agent.py` beobachtet lokale Servermetriken passiv.
- Reports werden in `/srv/sentinel-defense/reports/latest/` und kompatibel in `/srv/sentinel-defense/inbox/local/` geschrieben.

Master und Mail:

- `sentinel_master.py` aggregiert Website- und lokale Reports.
- `sentinel_daily_mailer.py` versendet den Master-Report nur mit explizitem `--send`.

Privater lokaler Ubuntu-PC:

- Sentinel Local Agent erzeugt lokale Reports, sobald der Rechner online ist und seine Timer laufen.
- UFW, fail2ban, sshd Jail und read-only Helper bilden die lokale Schutzkette.
- Der private Rechner hatte zuletzt `overall_status=OK` und keine Findings.

## Aktive Cloudflare-Regel

Die aktive kombinierte Regel heisst:

```text
sentinel_combined_wordpress_scanner_challenge
```

Sie nutzt nur `managed_challenge` und deckt ab:

- SiteLockSpider auf `/wp-login.php`
- SiteLockSpider auf `/wp-json/oembed/1.0/embed`
- `/xmlrpc.php`
- `.env`
- `phpinfo`
- `secrets`
- nur auf `electri-c-ity-studios-24-7.com` und `www.electri-c-ity-studios-24-7.com` zusaetzlich:
  - `_next`
  - `__rsc`
  - `__nextjs_action`
  - `api/auth`

Die Regelanzahl in Cloudflare wurde konsolidiert:

- aktuell 4 Regeln
- 3 fremde Regeln bleiben unveraendert
- alte SentinelDefense-Einzelregeln wurden zusammengefuehrt
- Backup und Rollback-Hinweis existieren

## Betriebsmodell

Standardzyklus:

```text
observe -> correlate -> simulate -> apply-safe -> validate -> report
```

Wichtig:

- `observe` laeuft regelmaessig.
- `simulate` prueft geplante Aktionen ohne Cloudflare-Mutation.
- `apply-safe` braucht `--confirm-apply` und darf nur exakt allowlistete defensive Aktionen anwenden.
- `consolidate-apply-safe` wird nur nach sauberer Simulation genutzt.
- Apply-Safe laeuft nicht unkontrolliert dauerhaft automatisch.

## Daily Report

Statuswerte:

- `OK`: keine akute Auffaelligkeit
- `WARNING`: Review erforderlich
- `CRITICAL`: kritisch, aber nicht automatisch ein Apply

Website Correlation Status:

- `NORMAL`
- `WATCH`
- `ACTION_CANDIDATE`

Action Status:

- `OK`
- `WARNING_REVIEW`
- `APPLY_CANDIDATE`
- `WATCH_ONLY`
- `LOCAL_ATTENTION`
- `UNKNOWN`

Ein `CRITICAL` bei Website-5xx kann auch nach einer Schutzregel noch sichtbar bleiben, weil Cloudflare-Reports ein rollierendes 24h-Fenster nutzen.

## Wichtige Dateien

Runbooks:

- `SENTINEL_DEFENSE_RUNBOOK.md`
- `SENTINEL_MASTER_RUNBOOK.md`
- `SENTINEL_HETZNER_LOCAL_RUNBOOK.md`
- `SENTINEL_LOCAL_RUNBOOK.md`
- `SENTINEL_LOCAL_READONLY_HELPER.md`
- `docs/sentinel-current-state.md`

Reports:

- `reports/latest/sentinel-defense-report.md`
- `reports/latest/sentinel-master-report.md`
- `reports/latest/hetzner-local-defense-report.md`
- `reports/latest/sentinel-defense-consolidation-report.md`
- `reports/latest/sentinel-defense-last-rollback.md`

## Betriebskommandos

Reports lesen:

```bash
cd /srv/sentinel-defense
less reports/latest/sentinel-master-report.md
less reports/latest/sentinel-defense-report.md
less reports/latest/hetzner-local-defense-report.md
```

Timer pruefen:

```bash
systemctl is-active cloudflare-daily-monitor.timer sentinel-defense.timer sentinel-master.timer sentinel-daily-mail.timer
systemctl list-timers cloudflare-daily-monitor.timer sentinel-defense.timer sentinel-master.timer sentinel-daily-mail.timer
```

Master neu erzeugen:

```bash
cd /srv/sentinel-defense
python3 sentinel_master.py
```

Der Default liest den Website-Report aus `reports/latest/sentinel-defense-report.json` und den Hetzner-Local-Report aus `inbox/local/local-defense-report.json`. Fehlt eine dieser Pflichtquellen, darf der Master nicht `OK` aggregieren.

Website-Simulation:

```bash
cd /srv/sentinel-defense
python3 sentinel_defense_bot.py \
  --mode simulate \
  --report /srv/sentinel-defense/cloudflare-monitor/latest/cloudflare-daily-monitor.md \
  --out-md /srv/sentinel-defense/reports/latest/sentinel-defense-simulate-report.md \
  --out-json /srv/sentinel-defense/reports/latest/sentinel-defense-simulate-report.json \
  --history-path /srv/sentinel-defense/reports/history/sentinel-defense-history.jsonl
```

Apply-Kommandos stehen bewusst nur in den Runbooks in einem gesonderten manuellen Abschnitt.

## Rollback

Vor Cloudflare-Aenderungen schreibt Sentinel ein Backup:

```text
/srv/sentinel-defense/reports/latest/cloudflare-ruleset-backup-YYYYMMDD-HHMMSS.json
```

Der letzte Rollback-Hinweis liegt hier:

```text
/srv/sentinel-defense/reports/latest/sentinel-defense-last-rollback.md
```

Rollback ist manuell. Es gibt keinen automatischen Rollback ohne Pruefung.

## Sicherheitsgrenzen

- Keine Gegenangriffe.
- Keine fremden Scans.
- Keine Credential-Sammlung.
- Keine IP-, ASN- oder Country-Regeln.
- Keine globalen Blocks.
- Nur `managed_challenge`.
- Fremde Cloudflare-Regeln nicht aendern.
- Keine Secrets in Logs oder Reports.
- Keine `.env`-Dateien mit `source` laden.
- Keine produktiven Konfigurationsaenderungen ohne separate Freigabe.

## Troubleshooting

Cloudflare Rules Limit `5/5`:

- `consolidate-simulate` nutzen.
- Nur SentinelDefense-Regeln duerfen ersetzt werden.
- Fremde Regeln bleiben unveraendert.

Update failed:

- Konsolidierungsreport und API-Response-Datei pruefen.
- Erst read-only verifizieren, dann entscheiden.

`source /etc/sentinel-defense.env` vermeiden:

- Env-Dateien nicht in der Shell sourcen.
- systemd `EnvironmentFile=` oder einen sicheren Parser nutzen.

sudoers read-only Helper:

- Nur fuer lokale Leserechte nutzen.
- Keine Schreibrechte, keine Restart-/Reload-Rechte, keine Secrets-Ausgabe.

24h Rolling Window:

- Cloudflare-Werte beziehen sich auf ein rollierendes 24h-Fenster.
- Nach Schutzmassnahmen koennen alte Events noch im Daily Report sichtbar bleiben.
