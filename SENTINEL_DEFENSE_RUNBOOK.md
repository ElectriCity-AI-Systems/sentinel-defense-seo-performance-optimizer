# Sentinel Defense Bot Runbook

## Zweck

`sentinel_defense_bot.py` bewertet den lokalen Cloudflare Daily Monitor Report und erzeugt defensive Website-Schutzberichte fuer Electri_C_ity Studios. Der Bot ist observe-first: er erkennt, korreliert und dokumentiert Risiken, ohne im Standardmodus Cloudflare zu veraendern.

Der operative Standardpfad ist:

```text
Cloudflare Daily Monitor -> Sentinel Defense Bot -> Sentinel Master -> Daily Mail
```

## Aktiver Website-Schutz

Die aktive konsolidierte Cloudflare Custom Rule heisst:

```text
sentinel_combined_wordpress_scanner_challenge
```

Sie nutzt ausschliesslich `managed_challenge` und schuetzt gegen:

- `SiteLockSpider` auf `/wp-login.php`
- `SiteLockSpider` auf `/wp-json/oembed/1.0/embed`
- `/xmlrpc.php`
- Pfade mit `.env`
- Pfade mit `phpinfo`
- Pfade mit `secrets`
- host-gebunden auf `electri-c-ity-studios-24-7.com` und `www.electri-c-ity-studios-24-7.com` zusaetzlich gegen:
  - `_next`
  - `__rsc`
  - `__nextjs_action`
  - `api/auth`

Die Host-Bindung ist wichtig: Fake-Framework-/NextJS-/Auth-Scannerpfade sind auf der WordPress-Apex-Seite nicht legitim, koennten aber auf anderen Subdomains legitim sein. Deshalb darf die Regel nicht global ueber alle Subdomains greifen.

Die Cloudflare-Regelanzahl wurde konsolidiert:

- aktuell 4 Custom Rules
- 3 fremde Regeln bleiben unveraendert
- alte SentinelDefense-Einzelregeln wurden in die kombinierte Regel zusammengefuehrt
- Backup-Dateien und `sentinel-defense-last-rollback.md` dokumentieren den manuellen Rollback

## Modi

`observe`:

- liest den bestehenden Cloudflare Daily Monitor Report
- schreibt Sentinel Defense Markdown/JSON
- schreibt History
- nutzt keine Cloudflare API
- veraendert keine Cloudflare-Regeln

`simulate`:

- plant hoechstens allowlistete defensive Aktionen
- schreibt geplante Aktionen in den Report
- wendet nichts an

`apply-safe`:

- darf nur mit `--confirm-apply` laufen
- darf nur exakt allowlistete `managed_challenge`-Aktionen anwenden
- ist nicht fuer dauerhaften unkontrollierten Autopilot gedacht
- wird nur nach Review, Korrelation und Simulation genutzt

`consolidate-simulate`:

- liest den Cloudflare Custom Rules Entry Point
- erstellt einen Konsolidierungsplan
- veraendert nichts
- zeigt, welche SentinelDefense-Regeln ersetzt wuerden

`consolidate-apply-safe`:

- darf nur nach erfolgreichem `consolidate-simulate` und mit `--confirm-apply` laufen
- schreibt vor einer Aenderung ein lokales Ruleset-Backup
- ersetzt nur eindeutig erkannte SentinelDefense-Regeln
- veraendert keine fremden Regeln
- erzeugt keine zusaetzliche Regel, wenn die bestehende combined rule aktualisiert werden kann

## Standardzyklus

```text
observe -> correlate -> simulate -> apply-safe -> validate -> report
```

Neue Massnahmen werden nicht blind automatisch gesetzt. Bestehende Schutzregeln bleiben dauerhaft aktiv, aber neue Regelanderungen brauchen Simulation, kontrolliertes Apply-Safe und anschliessende Validierung.

## Correlation Layer Und Trend Layer

Der Defense Bot bewertet klassische Watchpoints und Correlation Layer v2. Relevante Signale sind unter anderem:

- `sitelock_wp_login`
- `sitelock_oembed`
- `sitelock_frontpage`
- `sitelock_legacy_paths`
- `xmlrpc_abuse`
- `oembed_pressure`
- `fake_nextjs_or_secret_scans`
- `generic_origin_pressure`

Der Trend Layer nutzt die History, um wiederkehrende Muster sichtbar zu machen. Ein `CRITICAL` bei `generic_origin_pressure` fuehrt nicht automatisch zu neuen Cloudflare-Regeln. Zuerst muessen Pfade, User-Agents, Laender, Zeitfenster und lokale Origin-Signale korreliert werden.

Der `rolling_window_context` im JSON/Markdown trennt neue Snapshot-Deltas von alten 24h-Fenster-Resten. Diese Diagnose ist bewusst status-neutral: sie erklaert, warum hohe 24h-Werte nach einer Verbesserung noch sichtbar sein koennen, senkt `overall_status` aber nicht kosmetisch.

Innerhalb von `rolling_window_context.history` wird zusaetzlich die Stabilitaet ueber mehrere erfolgreiche Monitor-Snapshots ausgewertet. Ein alter 24h-Rest gilt erst als belastbarer OK-Kandidat, wenn alle erhoehten Watchpoints ueber mindestens 24h erfolgreicher Snapshots nur geringe Deltas zeigen. Bis dahin bleibt die hohe 24h-Metrik massgeblich.

Der `monitor_attempt_context` zeigt, ob nach dem ausgewerteten erfolgreichen Snapshot neuere Cloudflare-Monitor-Versuche fehlgeschlagen sind. Solche Fehler machen alte Metriken nicht `OK`; sie markieren nur, dass die aktuelle Bewertung auf dem letzten vollstaendigen Snapshot beruht.

### 5xx Origin Pressure Breakdown

Der Abschnitt `5xx Origin Pressure Breakdown` erklaert, warum Website-5xx noch nicht OK-faehig sind. Er nutzt lokale JSON-Rohdaten aus dem Monitor:

- `errors-5xx-24h.json`
- `status-24h.json`
- `user-agents-24h.json`
- `top-paths-24h.json`
- `security-actions-24h.json`

Wichtige JSON-Felder:

- `origin_pressure_breakdown.status_24h_total_5xx`: autoritativer 5xx-Gesamtwert aus `status-24h.json`
- `origin_pressure_breakdown.observed_5xx_detail_count`: 5xx-Anteil, der aus detaillierten Pfad-/Cache-Zeilen klassifiziert werden kann
- `origin_pressure_breakdown.detail_coverage_percent`: wie viel der 5xx-Summe durch Detailzeilen abgedeckt ist
- `origin_pressure_breakdown.detail_completeness_status`: z.B. `DETAIL_ROWS_LIMITED`, wenn die Top-Gruppierung nicht genug Detailzeilen fuer volle Klassifikation enthaelt
- `origin_pressure_breakdown.diagnostic_gap`: erklaert die Rest-Unknown-Menge
- `origin_pressure_breakdown.status_detail_gap`: zeigt pro 5xx-Statuscode, wie viel aus `status-24h.json` in den Detailzeilen fehlt
- `origin_pressure_breakdown.status_only_gap_classification`: klassifiziert den nur aggregiert sichtbaren Rest konservativ nach Statuscode
- `origin_pressure_breakdown.top_5xx_status_inclusive_classification`: addiert die Detailklassifikation und die konservative Status-only-Klassifikation des Aggregate-Rests
- `origin_pressure_breakdown.cache_status_interpretation`: sagt explizit, ob die sichtbaren 5xx cache-hit-, dynamic- oder miss-foermig sind
- `origin_pressure_breakdown.top_5xx_request_shapes`: trennt Pfad-Oberflaechen wie Scanner-/Probe-Pfade, WordPress-/Legacy-Pfade und generische Origin-Pfade
- `origin_pressure_breakdown.top_5xx_actor_signals`: trennt User-Agent-/Akteur-Signale wie SiteLockSpider, Scanner/Bot, Browser-like oder unbekannt
- `origin_pressure_breakdown.top_5xx_failure_modes`: trennt Timeout/Cloudflare-to-Origin, Origin/PHP/Upstream und Cache-Hit-Form
- `top_5xx_paths`, `top_5xx_cache_status`, `top_5xx_classification`: maschinenlesbare Zusammenfassungen fuer Master und Mail

Die Klassifikation ist diagnostisch:

- `likely_scanner_pressure`
- `likely_origin_pressure`
- `likely_wordpress_legacy_pressure`
- `likely_cloudflare_timeout`
- `unknown`

`unknown` darf nicht als OK interpretiert werden. Wenn `status-24h.json` mehr 5xx zeigt als die Detailzeilen abdecken, bleibt dieser Rest bis zu tieferer Rohdatenabdeckung oder 24h-low-growth-Evidenz nicht OK-faehig.
Die status-inclusive Klassifikation darf eine Richtung zeigen, zum Beispiel timeout-foermige 504/522/524-Reste, ersetzt aber keine Pfad-/Cache-/User-Agent-Klassifikation und senkt keinen Status.

### OK Readiness

Der Abschnitt `OK Readiness` trennt explizit:

- direkte Statusblocker aus den Watchpoint-Metriken (`overall_status_input`)
- Rolling-Window-/Low-Growth-Blocker
- Aggregate-Detail-Luecken, bei denen status-only Diagnose nicht als OK-Evidenz reicht
- `diagnostic_only` v2-Findings, die Treiber erklaeren, aber den Website-`overall_status` nicht direkt berechnen

`OK Readiness` ist nur dann `OK_READY`, wenn keine direkten Statusblocker, keine Low-Growth-Blocker und keine Aggregate-Detail-Luecken mehr bestehen. `diagnostic_only` v2-Findings duerfen nicht heimlich als OK-Blocker oder OK-Beweis interpretiert werden.

### Source Map 404 Breakdown

Der Abschnitt `Source Map 404 Breakdown` erklaert erhoehte `404 auf .map`, ohne daraus Cloudflare-Regeln oder Statussenkungen abzuleiten. Er nutzt `notfound-404-24h.json` und `user-agents-24h.json`, gruppiert die betroffenen Pfade und schreibt maschinenlesbar:

- `source_map_404_breakdown`
- `top_map_404_paths`
- `top_map_404_classification`

Die Klassifikation trennt typische Ursachen:

- `likely_wordpress_minify_source_map_reference`
- `likely_wordpress_core_source_map_reference`
- `likely_scanner_or_framework_probe`
- `likely_static_asset_source_map_reference`
- `unknown`

Auch diese Diagnose ist status-neutral: `404 auf .map` bleibt auffaellig, solange der 24h-Wert erhoeht ist oder `old_window_blockers[]` noch fehlende 24h-low-growth-Evidenz meldet.

### OK Blockers

`rolling_window_context.history.old_window_blockers` listet konkret, warum alte 24h-Reste noch nicht als OK-Kandidat gelten. Typische Gruende:

- `recent_significant_growth`: mindestens ein erhoehter Watchpoint hatte in den letzten erfolgreichen Snapshots noch Delta ueber dem Low-Growth-Limit
- `low_growth_but_not_24h`: aktuelle Deltas sind niedrig, aber es fehlen noch 1440 stabile Minuten
- `comparison_incompatible_requires_new_evidence`: Monitor-Gruppierungsgrenzen oder Rohdatenabdeckung haben sich geaendert; ab diesem Punkt muss neue stabile Evidenz gesammelt werden

Relevante Felder:

- `latest_delta`
- `max_recent_delta`
- `low_growth_limit`
- `stable_minutes`
- `stable_since_utc`
- `stable_since_reason`
- `remaining_stable_minutes_for_old_window`
- `last_significant_growth_at_utc`

Website darf erst `OK` werden, wenn alle Watchpoints real unter Schwellen liegen oder diese Blocker wegfallen und die 24h-low-growth-Evidenz vollstaendig ist.

`stable_since_reason` zeigt, warum die 24h-Stabilitaetsuhr neu gestartet wurde, zum Beispiel wegen `significant_growth` oder `comparison_incompatible`. Wenn beides vorkommt, zaehlt der neueste dieser Punkte; aeltere inkompatible Snapshots duerfen spaeteres Wachstum nicht verdecken.

## Reports

Aktuelle Reports:

```bash
cd /srv/sentinel-defense
less reports/latest/sentinel-defense-report.md
python3 -m json.tool reports/latest/sentinel-defense-report.json >/dev/null
tail -n 10 reports/history/sentinel-defense-history.jsonl
```

Konsolidierungsreport:

```bash
less /srv/sentinel-defense/reports/latest/sentinel-defense-consolidation-report.md
python3 -m json.tool /srv/sentinel-defense/reports/latest/sentinel-defense-consolidation-report.json >/dev/null
```

Rollback-Hinweis:

```bash
less /srv/sentinel-defense/reports/latest/sentinel-defense-last-rollback.md
```

## Betriebskommandos

Cloudflare Daily Monitor erzeugen:

```bash
cd /srv/sentinel-defense
/bin/bash /srv/sentinel-defense/cloudflare_daily_monitor.sh
```

Der Monitor ist read-only gegen Cloudflare GraphQL. Fuer tiefere Diagnose koennen die Gruppierungs-Limits ohne Regelanderung gesetzt werden:

```bash
CLOUDFLARE_MONITOR_DETAIL_LIMIT=500 CLOUDFLARE_MONITOR_USER_AGENT_LIMIT=500 \
  /bin/bash /srv/sentinel-defense/cloudflare_daily_monitor.sh
```

Observe-Report erzeugen:

```bash
cd /srv/sentinel-defense
python3 sentinel_defense_bot.py \
  --mode observe \
  --report /srv/sentinel-defense/cloudflare-monitor/latest/cloudflare-daily-monitor.md \
  --out-md /srv/sentinel-defense/reports/latest/sentinel-defense-report.md \
  --out-json /srv/sentinel-defense/reports/latest/sentinel-defense-report.json \
  --history-path /srv/sentinel-defense/reports/history/sentinel-defense-history.jsonl
```

Simulation ausfuehren:

```bash
cd /srv/sentinel-defense
python3 sentinel_defense_bot.py \
  --mode simulate \
  --report /srv/sentinel-defense/cloudflare-monitor/latest/cloudflare-daily-monitor.md \
  --out-md /srv/sentinel-defense/reports/latest/sentinel-defense-simulate-report.md \
  --out-json /srv/sentinel-defense/reports/latest/sentinel-defense-simulate-report.json \
  --history-path /srv/sentinel-defense/reports/history/sentinel-defense-history.jsonl
```

Konsolidierung simulieren:

```bash
cd /srv/sentinel-defense
python3 sentinel_defense_bot.py \
  --mode consolidate-simulate \
  --cloudflare-zone-id "$CLOUDFLARE_ZONE_ID" \
  --out-md /srv/sentinel-defense/reports/latest/sentinel-defense-consolidation-report.md \
  --out-json /srv/sentinel-defense/reports/latest/sentinel-defense-consolidation-report.json
```

Timer pruefen:

```bash
systemctl list-timers 'cloudflare-daily-monitor.timer' 'sentinel-defense.timer' 'sentinel-master.timer' 'sentinel-daily-mail.timer'
systemctl is-active cloudflare-daily-monitor.timer sentinel-defense.timer sentinel-master.timer sentinel-daily-mail.timer
```

## Manueller Apply-Abschnitt

Diese Kommandos sind bewusst separat dokumentiert. Sie duerfen nicht als unkontrollierter Dauerlauf verwendet werden.

Active Defense Apply-Safe:

```bash
cd /srv/sentinel-defense
python3 sentinel_defense_bot.py \
  --mode apply-safe \
  --confirm-apply \
  --cloudflare-zone-id "$CLOUDFLARE_ZONE_ID" \
  --report /srv/sentinel-defense/cloudflare-monitor/latest/cloudflare-daily-monitor.md \
  --out-md /srv/sentinel-defense/reports/latest/sentinel-defense-apply-report.md \
  --out-json /srv/sentinel-defense/reports/latest/sentinel-defense-apply-report.json \
  --history-path /srv/sentinel-defense/reports/history/sentinel-defense-history.jsonl
```

Consolidation Apply-Safe:

```bash
cd /srv/sentinel-defense
python3 sentinel_defense_bot.py \
  --mode consolidate-apply-safe \
  --confirm-apply \
  --cloudflare-zone-id "$CLOUDFLARE_ZONE_ID" \
  --out-md /srv/sentinel-defense/reports/latest/sentinel-defense-consolidation-report.md \
  --out-json /srv/sentinel-defense/reports/latest/sentinel-defense-consolidation-report.json
```

Vorher muss ein passender Simulate-Report vorliegen. Nachher muessen JSON, Markdown, Backup, Rollback-Hinweis und Read-only-Verifikation geprueft werden.

## Rollback

Vor produktiven Cloudflare-Aenderungen schreibt der Bot ein Backup:

```text
/srv/sentinel-defense/reports/latest/cloudflare-ruleset-backup-YYYYMMDD-HHMMSS.json
```

Der letzte Rollback-Hinweis steht hier:

```text
/srv/sentinel-defense/reports/latest/sentinel-defense-last-rollback.md
```

Rollback ist manuell. Es gibt bewusst keinen automatischen Delete ohne Pruefung.

## Sicherheitsgrenzen

- Nur defensive Aktionen.
- Keine Gegenangriffe.
- Keine fremden Scans.
- Keine Credential-Sammlung.
- Keine IP-, ASN- oder Country-Regeln.
- Keine globalen Blocks.
- Keine globale Challenge fuer alle `/api`-Pfade.
- Keine globale Challenge fuer alle `/wp-json`-Pfade.
- Nur `managed_challenge`.
- Fremde Cloudflare-Regeln nicht aendern.
- Keine Secrets in Logs oder Reports.
- `.env`-Dateien nicht mit `source /etc/sentinel-defense.env` laden, weil Sonderzeichen von der Shell ausgefuehrt oder geloggt werden koennen.

## Troubleshooting

Cloudflare Rules Limit `5/5`:

- `consolidate-simulate` ausfuehren.
- Pruefen, ob nur SentinelDefense-Regeln ersetzt werden.
- Fremde Regeln duerfen nicht veraendert werden.
- Ergebnisanzahl muss kleiner oder gleich der aktuellen Anzahl und kleiner oder gleich 5 sein.

`update failed`:

- Report und lokale API-Response-Datei pruefen.
- Backup nicht loeschen.
- Keine zweite Aenderung starten, bevor der Zustand read-only verifiziert wurde.

`source /etc/sentinel-defense.env` vermeiden:

- Env-Datei nicht in einer Shell sourcen.
- systemd `EnvironmentFile=` oder einen Parser verwenden, der Werte nicht ausfuehrt und nicht ausgibt.

24h Rolling Window:

- Cloudflare-Daten sind ein rollierendes 24h-Fenster.
- Nach einer Regelanderung koennen alte Treffer noch viele Stunden im Report sichtbar bleiben.
- Validierung braucht mehrere Monitor-Laeufe und Trendvergleich.
- Website wird erst `OK`, wenn Watchpoints real unter Schwellen liegen oder alte Rolling-Window-Reste separat eindeutig belegt sind.
- Fehlgeschlagene GraphQL-Monitor-Laeufe werden als Freshness-Kontext berichtet und nicht als erfolgreiche Messung gewertet.
