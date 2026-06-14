# Sentinel Master Runbook

## Architektur

Die Sentinel-Kette verbindet Website-Signale, Hetzner-Server-Signale und lokale PC-Signale zu einem zentralen Master-Report:

```text
Cloudflare Daily Monitor -> Sentinel Defense Bot -> Hetzner Local Agent -> Sentinel Master -> Daily Mail
```

Der Master liest vorhandene lokale Reports:

- `/srv/sentinel-defense/reports/latest/sentinel-defense-report.json`
- `/srv/sentinel-defense/inbox/local/local-defense-report.json`

Er schreibt:

- `/srv/sentinel-defense/reports/latest/sentinel-master-report.md`
- `/srv/sentinel-defense/reports/latest/sentinel-master-report.json`
- `/srv/sentinel-defense/reports/history/sentinel-master-history.jsonl`

`sentinel_daily_mailer.py` liest den Master-Report und sendet ihn per SMTP, wenn explizit `--send` genutzt wird.

## Schutzebenen

Website:

- Cloudflare Daily Monitor erfasst 24h-Metriken.
- Sentinel Defense Bot bewertet Watchpoints, Correlation Layer v2 und Trend Layer.
- Die aktive Cloudflare-Regel `sentinel_combined_wordpress_scanner_challenge` bleibt dauerhaft aktiv.
- Neue Regeln oder Regelanderungen werden nicht blind automatisch gesetzt.

Hetzner-Server:

- `sentinel_hetzner_local_agent.py` ueberwacht lokale Systemlast, SSH/Auth, Firewall-Lesbarkeit, fail2ban, Prozesse, Ports, Integritaets-Watchpoints und Sentinel Timer.
- Der Agent kontaktiert keine externen Hosts und aendert keine Systemkonfiguration.
- Fuer UFW/fail2ban kann ein eng allowlisteter read-only Helper genutzt werden. Die Dokumentation liegt in `SENTINEL_HETZNER_STATUS_HELPER.md`; der Zielname `SENTINEL_HETZNER_READONLY_HELPER.md` verweist darauf. sudoers wird nicht automatisch installiert oder geaendert.
- Wenn UFW/fail2ban aktiv per systemd oder Helper bestaetigt sind, ist fehlende direkte Lesbarkeit kein `WARNING` mehr.

Privater lokaler Ubuntu-PC:

- Sentinel Local Agent, UFW, fail2ban, sshd Jail und read-only Helper bilden die lokale Schutzkette.
- Der private PC hatte zuletzt `overall_status=OK` und keine Findings.
- Wenn der Rechner offline ist, bleibt sein Schutz lokal inaktiv; sobald er online ist und Timer laufen, erzeugt er wieder Reports.

## Master-Bewertung

Website-Status:

- `overall_status` aus dem Website-Sentinel-JSON
- `correlation_status` aus dem Website-Sentinel-JSON
- `correlation_v2_findings[]` fuer Details zu Treibern wie `fake_nextjs_or_secret_scans`, `xmlrpc_abuse` oder `generic_origin_pressure`

Lokaler Status:

- `hetzner_local_status` aus dem Hetzner Local Agent JSON
- `local_status` bleibt nur als Kompatibilitaets-Alias fuer `hetzner_local_status`
- fehlender Hetzner Local Report wird als `UNKNOWN` behandelt
- `UNKNOWN` allein loest keinen `CRITICAL` aus

Private PC Local Status:

- Ein vorhandener Private-PC-Report wird separat als `private_pc_local_status` bewertet.
- Wenn kein Private-PC-Report auf Hetzner vorliegt, wird der aktuelle Status nicht geraten.
- Projektinterne Dokumentation kann als `private_pc_last_known_local_confirmation` angezeigt werden, zum Beispiel `OK`.
- Daraus wird kein Passwort-Push und keine Remote-Automation abgeleitet.

Statusprioritaet:

```text
CRITICAL > WARNING > OK
```

`UNKNOWN` wird sichtbar dokumentiert, aber nicht allein zu `CRITICAL` hochgestuft.
Fehlende Pflichtquellen wie Website- oder Hetzner-Local-Report duerfen aber nicht als `OK` aggregieren; ohne lesbaren Pflichtreport bleibt der Master `UNKNOWN` oder schlechter.

## Daily Report Statuswerte

Website:

- `OK`: keine erhoehten Watchpoints
- `WARNING`: erhoeht, Review erforderlich
- `CRITICAL`: kritisch, aber weiterhin nur nach Korrelation und Safety-Gates handeln

Website Correlation Status:

- `NORMAL`: keine bestaetigte apply-safe Korrelation
- `WATCH`: kritisch beobachten, aber nicht anwenden
- `ACTION_CANDIDATE`: potenzieller Apply-Safe-Kandidat nach manueller Pruefung

Action Status:

- `OK`: keine Aktion erforderlich
- `WARNING_REVIEW`: Review noetig, aber kein Apply-Kandidat
- `APPLY_CANDIDATE`: kontrollierter Apply-Safe kann nach Review erwogen werden
- `WATCH_ONLY`: kritisch beobachten, aber keine bestaetigte Origin-Krise
- `LOCAL_ATTENTION`: lokales System braucht Aufmerksamkeit
- `UNKNOWN`: Quellen fehlen

## Warum PC OK Und Hetzner WARNING Sein Koennen

Der private PC und der Hetzner-Server sind unterschiedliche Schutzbereiche:

- Der PC kann `OK` sein, wenn UFW, fail2ban, sshd Jail, Timer und Helper sauber laufen und keine Findings vorliegen.
- Der Hetzner Local Agent kann gleichzeitig `WARNING` melden, zum Beispiel wenn `ufw status` ohne sudo nicht lesbar ist oder ein Sentinel Timer inaktiv ist.
- Ein lokales Hetzner-`WARNING` bedeutet nicht automatisch, dass der private PC unsicher ist.
- Der Master zeigt beide Quellen getrennt, damit Website-, Server- und PC-Lage nicht vermischt werden.

## Rolling Window

Cloudflare-Metriken sind 24h-Rolling-Window-Werte. Nach einer Regelverbesserung fallen alte Ereignisse nicht sofort aus den Summen.

Der Website-Sentinel schreibt deshalb `rolling_window_context`:

- Vergleich zwischen aktuellem und vorherigem Snapshot
- Delta fuer erhoehte Watchpoints
- Kennzeichnung moeglicher alter Rolling-Window-Reste
- Multi-Snapshot-Stabilitaet ueber erfolgreiche Monitor-Laeufe
- `old_window_blockers[]` mit konkretem Grund, stabilen Minuten und verbleibenden Minuten bis 24h-low-growth-Evidenz

Diese Diagnose senkt `overall_status` nicht kosmetisch. Website wird erst `OK`, wenn die Watchpoints real unter die Schwellen fallen oder eine spaeter separat belegte alte-Reste-Policy greift.

Zusaetzlich schreibt `monitor_attempt_context`, ob nach dem ausgewerteten erfolgreichen Snapshot neuere Cloudflare-GraphQL-Monitorlaeufe fehlgeschlagen sind. Der Master zeigt das als Freshness-Kontext und behaelt den letzten vollstaendigen Snapshot als Bewertungsgrundlage bei.

## Website 5xx Origin Pressure

Der Master liest `website_origin_pressure_breakdown` aus dem Website-Sentinel-JSON und rendert daraus:

- 5xx-Gesamtwert aus `status-24h.json`
- detailliert klassifizierbare 5xx-Zeilen
- Detail-Coverage in Prozent
- nur aggregierte/unknown 5xx
- statusweisen Detail-Gap fuer den nur aggregiert sichtbaren Rest
- Classification Counts
- Status-inclusive Classification Counts
- Request-Shape Counts
- Actor-Signal Counts
- Failure-Mode Counts
- Cache-Status-Interpretation
- aggregierte Status-/Country-/Cache-/User-Agent-Listen
- Top 5xx Paths
- Sentinel Combined Rule Coverage

Wenn `detail_completeness_status` z.B. `DETAIL_ROWS_LIMITED` ist, bedeutet das: Der Monitor hat nur einen Teil der 5xx als Pfad-/Cache-Gruppen vorliegen. Der Rest bleibt fuer den Master nicht OK-faehig, bis tiefere Rohdaten oder 24h-low-growth-Evidenz vorliegen.
Die status-inclusive Klassifikation ist nur Diagnose: Sie addiert konservativ statusweise erkannte Aggregate-Reste zu den Detailklassifikationen, aber sie darf kein OK begruenden, solange Pfad-/Cache-Details fehlen oder 24h-low-growth nicht vollstaendig belegt ist.

Die Master-Empfehlungen duerfen deshalb `CRITICAL` explizit mit zwei Gruenden erklaeren:

- Rest-5xx sind nur aggregiert/unknown und diagnostisch nicht erledigt.
- `old_window_blockers[]` zeigt fehlende 24h-low-growth-Evidenz pro Metrik.

Diese Hinweise sind keine Schwellenwerterhoehung und keine Statusunterdrueckung.

## Website OK Readiness

Der Master liest `website_ok_readiness` aus dem Website-Sentinel-JSON. Diese Zusammenfassung ist die kompakte Antwort auf: "Was verhindert ein echtes OK?"

- `direct_status_blockers`: Watchpoint-Metriken, die direkt in den Website-`overall_status` eingehen.
- `low_growth_blockers`: Rolling-Window-Blocker fuer alte 24h-Fensterreste.
- `aggregate_detail_blockers`: Diagnose-Luecken, bei denen nur statusweise Aggregate sichtbar sind.
- `diagnostic_nonblocking_findings`: erhoehte Correlation-v2-Findings, die Treiber erklaeren, aber den Website-`overall_status` nicht direkt berechnen.

Ein v2-Finding mit `CRITICAL` darf dadurch im Master sichtbar bleiben, ohne als versteckter OK-Blocker missverstanden zu werden. Der echte OK-Pfad bleibt: direkte Metriken OK, keine Low-Growth-Blocker, keine ungeklärten Aggregate-Detail-Luecken.

## Website Source Map 404

Der Master liest `website_source_map_404_breakdown` aus dem Website-Sentinel-JSON und rendert daraus:

- `404 auf .map` aus der Website-Metrik
- detailliert sichtbare `.map`-404-Zeilen
- Detail-Coverage in Prozent
- Classification Counts
- Top Source Map 404 Paths

Die Diagnose unterscheidet WordPress-Minify-/Core-Source-Map-Referenzen, Fake-Framework-/Scannerprobes, statische Asset-Referenzen und `unknown`. Sie ist nur Diagnose: Der Master darf daraus kein OK ableiten, solange `old_window_blockers[]` fuer `.map` noch `recent_significant_growth` oder fehlende 24h-low-growth-Evidenz meldet.

## Env-Datei

SMTP-Zugangsdaten liegen ausschliesslich in `/etc/sentinel-defense.env` oder im Prozess-Environment. Werte duerfen nicht in Logs oder Reports geschrieben werden.

Beispiel mit Platzhaltern:

```env
SENTINEL_MAIL_TO=security@example.com
SENTINEL_MAIL_FROM=sentinel@example.com
SENTINEL_MAIL_SUBJECT=Sentinel Daily Report
SENTINEL_SMTP_HOST=smtp.ionos.de
SENTINEL_SMTP_PORT=587
SENTINEL_SMTP_USER=sentinel@example.com
SENTINEL_SMTP_PASSWORD=REPLACE_WITH_SECRET
SENTINEL_SMTP_STARTTLS=true
```

Die Datei nicht mit `source /etc/sentinel-defense.env` laden. Sonderzeichen in Secrets koennen sonst als Shell-Syntax interpretiert werden. Fuer systemd `EnvironmentFile=` nutzen; fuer manuelle Tools einen Parser verwenden, der Werte nicht ausfuehrt und nicht ausgibt.

## Daily Mail

Die Daily Mail enthaelt:

- kurzen Plaintext Summary Block
- vollstaendigen Sentinel Master Markdown Report
- optionalen Website-Sentinel-Auszug

Versand erfolgt nur mit:

```bash
cd /srv/sentinel-defense
python3 sentinel_daily_mailer.py --send
```

Dry Run:

```bash
cd /srv/sentinel-defense
python3 sentinel_daily_mailer.py --dry-run
```

Der Dry Run zeigt keine Secrets. Er zeigt nur Empfaenger, Sender, Host, Port, STARTTLS ja/nein, Passwort vorhanden ja/nein und Betreff.

## Betriebskommandos

Reports lesen:

```bash
cd /srv/sentinel-defense
less reports/latest/sentinel-master-report.md
python3 -m json.tool reports/latest/sentinel-master-report.json >/dev/null
tail -n 10 reports/history/sentinel-master-history.jsonl
```

Master neu erzeugen:

```bash
cd /srv/sentinel-defense
python3 sentinel_master.py \
  --website-json /srv/sentinel-defense/reports/latest/sentinel-defense-report.json \
  --local-json /srv/sentinel-defense/inbox/local/local-defense-report.json \
  --out-md /srv/sentinel-defense/reports/latest/sentinel-master-report.md \
  --out-json /srv/sentinel-defense/reports/latest/sentinel-master-report.json \
  --history /srv/sentinel-defense/reports/history/sentinel-master-history.jsonl
```

Timer pruefen:

```bash
systemctl is-active cloudflare-daily-monitor.timer sentinel-defense.timer sentinel-master.timer sentinel-daily-mail.timer
systemctl list-timers cloudflare-daily-monitor.timer sentinel-defense.timer sentinel-master.timer sentinel-daily-mail.timer
```

Direkte Observe-Kette:

```bash
cd /srv/sentinel-defense
/bin/bash /srv/sentinel-defense/cloudflare_daily_monitor.sh
python3 sentinel_defense_bot.py --mode observe \
  --report /srv/sentinel-defense/cloudflare-monitor/latest/cloudflare-daily-monitor.md \
  --out-md /srv/sentinel-defense/reports/latest/sentinel-defense-report.md \
  --out-json /srv/sentinel-defense/reports/latest/sentinel-defense-report.json \
  --history-path /srv/sentinel-defense/reports/history/sentinel-defense-history.jsonl
python3 sentinel_master.py
```

Der Cloudflare Daily Monitor kann fuer bessere 5xx-Diagnose mit hoeheren read-only Gruppierungs-Limits laufen:

```bash
cd /srv/sentinel-defense
CLOUDFLARE_MONITOR_DETAIL_LIMIT=500 CLOUDFLARE_MONITOR_USER_AGENT_LIMIT=500 \
  /bin/bash /srv/sentinel-defense/cloudflare_daily_monitor.sh
```

## systemd Services/Timer

Die systemd-Dateien werden hier nur dokumentiert. Dieses Runbook installiert oder aendert nichts.

Typische Timer:

- `cloudflare-daily-monitor.timer`
- `sentinel-defense.timer`
- `sentinel-master.timer`
- `sentinel-daily-mail.timer`

Status ohne Veraenderung pruefen:

```bash
systemctl status sentinel-master.service --no-pager
journalctl -u sentinel-master.service -n 100 --no-pager
```

## Rollback Und Backups

Cloudflare-Apply-Safe- und Consolidation-Apply-Safe-Laeufe schreiben Backups unter:

```text
/srv/sentinel-defense/reports/latest/cloudflare-ruleset-backup-YYYYMMDD-HHMMSS.json
```

Der Rollback-Hinweis liegt hier:

```text
/srv/sentinel-defense/reports/latest/sentinel-defense-last-rollback.md
```

Rollback ist manuell und wird nicht automatisch ausgefuehrt. Vor einem Rollback muessen aktueller Ruleset-Zustand, Backup und Zielzustand verglichen werden.

## Sicherheitsgrenzen

- Nur defensive Reports.
- Keine Angriffe.
- Keine Scans fremder Systeme.
- Keine Credential-Sammlung.
- Keine Secrets in Logs, Reports oder Dry-Run-Ausgabe.
- Master und Mailer aendern keine Cloudflare-Regeln.
- `sentinel_master.py` fuehrt keine Netzwerkzugriffe aus.
- `sentinel_daily_mailer.py` nutzt Netzwerk nur fuer expliziten SMTP-Versand mit `--send`.
- Keine externen Python-Pakete; nur Python-Standardbibliothek.

## Troubleshooting

Cloudflare Rules Limit `5/5`:

- `sentinel_defense_bot.py --mode consolidate-simulate` nutzen.
- Nur SentinelDefense-Regeln duerfen ersetzt werden.
- Fremde Regeln bleiben unveraendert.

Update failed:

- Konsolidierungsreport und API-Response-Datei lesen.
- Nicht direkt einen weiteren Apply starten.
- Erst read-only verifizieren, ob Cloudflare geaendert wurde.

24h Rolling Window:

- Cloudflare-Metriken bleiben bis zu 24h im Fenster sichtbar.
- Nach einem Schutz-Apply kann `CRITICAL` noch sichtbar sein, obwohl neue Requests bereits challenged werden.
- Der Master zeigt `OK Blockers`, solange `recent_significant_growth` oder `low_growth_but_not_24h` besteht.
- `comparison_incompatible_requires_new_evidence` bedeutet, dass ein Rohdaten-/Limitwechsel neue stabile Vergleichsevidenz erfordert.
- `UNKNOWN` in der 5xx-Origin-Diagnose ist kein OK-Beweis; es markiert fehlende Detailabdeckung.

Lokaler Agent fehlt:

```bash
ls -la /srv/sentinel-defense/inbox/local/
```

Fehlt der Report, wird die Quelle `UNKNOWN`. Das ist ein Betriebszustand, kein automatischer Website-`CRITICAL`.
