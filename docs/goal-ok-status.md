# Goal: Bring Sentinel Status Reports to Real OK

## Ziel

Bringe die Statusmeldungen für Website und lokale Systeme auf echtes `OK`, ohne Warnungen kosmetisch zu verstecken.

Es geht nicht darum, Schwellenwerte blind hochzusetzen oder CRITICAL/WARNING zu unterdrücken. Ziel ist, die Ursachen zu beheben oder korrekt als INFO einzuordnen, damit der Master-Report technisch verdient `OK` erreicht.

## Aktueller Kontext

Der private lokale Rechner ist bereits lokal OK:

- Sentinel Local Agent: Overall status OK
- Findings: None
- UFW active
- fail2ban active
- sshd jail active
- read-only Helper aktiv
- Apache Port 80 bewusst erlaubt
- Datenbanken nur lokal
- keine SSH-Fehlversuche

Der Master zeigt aktuell:

- Website Status: CRITICAL
- Hetzner Local Status: OK
- Private PC Local Status: UNKNOWN mit lokal gepflegter letzter OK-Bestaetigung
- Overall Master Status: CRITICAL

Die offene Statusarbeit liegt damit primaer bei der Website-Diagnose und der 24h-low-growth-Evidenz, nicht mehr bei kosmetischer Local-WARNING-Unterdrueckung.

## Teilziel 1: Hetzner Local Agent auf echtes OK bringen

Prüfe:

- `sentinel_hetzner_local_agent.py`
- aktueller Hetzner Local Report
- `reports/latest/hetzner-local-defense-report.md`
- `reports/latest/hetzner-local-defense-report.json`
- `inbox/local/local-defense-report.json`

Historische oder bei Regression erneut zu pruefende Ursachen fuer WARNING:

- UFW-Leserecht ohne Root
- fail2ban-Status ohne Root
- `/home/deploy/.ssh/authorized_keys` fehlt
- `/etc/sentinel-defense.env` Mode 0640

Aufgaben:

1. Baue, falls sinnvoll, einen read-only Helper:
   - `sentinel_hetzner_status_helper.py`
   - `SENTINEL_HETZNER_READONLY_HELPER.md`

2. Der Helper darf nur lesen:
   - `ufw status verbose`
   - `fail2ban-client status`
   - optional `fail2ban-client status sshd`
   - `systemctl is-active` für Sentinel-Timer

3. Der Helper darf nichts ändern:
   - keine UFW-Regeln setzen/löschen
   - kein fail2ban ban/unban/restart
   - keine Secrets lesen
   - keine externen Hosts kontaktieren

4. Der Agent soll den Helper nutzen, wenn non-root Checks scheitern.

5. Wenn UFW/fail2ban aktiv sind, dürfen diese Checks nicht mehr WARNING erzeugen.

6. `/etc/sentinel-defense.env`:
   - `0640 root:deploy` soll OK oder INFO sein, wenn Daily Mailer als deploy lesen muss.
   - world-readable bleibt CRITICAL.

7. `/home/deploy/.ssh/authorized_keys`:
   - Wenn Datei fehlt, aber Login bewusst anders geregelt ist, als INFO behandeln.
   - Keine Keys erzeugen.
   - Keine Inhalte lesen.

8. Ziel:
   - Hetzner Local Agent soll bei gesunder Lage `overall_status=OK` erreichen.

9. Keine systemd- oder sudoers-Änderungen automatisch durchführen.
   - Nur dokumentieren, welche sudoers-Zeile manuell nötig wäre.

## Teilziel 2: Website Status auf echtes OK vorbereiten

Die Website wurde durch die kombinierte Cloudflare-Regel verbessert.

Aktive kombinierte Regel:

`sentinel_combined_wordpress_scanner_challenge`

Sie schützt:

- SiteLockSpider auf `/wp-login.php`
- SiteLockSpider auf `/wp-json/oembed/1.0/embed`
- `/xmlrpc.php`
- `.env`
- `phpinfo`
- `secrets`
- host-gebunden auf `electri-c-ity-studios-24-7.com` und `www.electri-c-ity-studios-24-7.com` gegen:
  - `_next`
  - `__rsc`
  - `__nextjs_action`
  - `api/auth`

Aufgaben:

1. Keine neue Cloudflare-Regel anwenden.
2. Keine apply-safe- oder consolidate-apply-safe-Ausführung.
3. Beobachte und dokumentiere, dass 24h Rolling Window bedeutet:
   - Werte fallen nicht sofort nach Apply.
4. Prüfe Rest-5xx-Diagnose:
   - `errors-5xx-24h.json`
   - `user-agents-24h.json`
   - `status-24h.json`
   - `.map`-404-Diagnose aus `notfound-404-24h.json`, falls `404 auf .map` OK blockiert
5. Verbessere, falls nötig, nur die Diagnose:
   - klarere Unterscheidung zwischen echten neuen Fehlern und alten 24h-Fensterdaten
   - klare Trennung zwischen Detailklassifikation, status-only Aggregate-Rest und status-inclusive Diagnose
   - klare OK-Readiness-Trennung zwischen direkten Statusblockern, Low-Growth-Blockern und diagnostic-only v2-Findings
   - keine Schwellenwerte kosmetisch hochsetzen
6. Website darf nur auf OK fallen, wenn die Metriken tatsächlich unter Warning/Critical-Schwellen liegen oder eindeutig als alte Rolling-Window-Reste markiert werden können.

## Teilziel 3: Master-Report klarer machen

Der Master soll klar unterscheiden:

- Website Status
- Hetzner Local Status
- Private PC Local Status, falls ein privater PC Report vorhanden oder lokal bestätigt ist

Wenn kein privater PC Report auf Hetzner vorliegt, nicht raten. Stattdessen dokumentieren:

- Private PC status is maintained locally.
- Last known local confirmation: OK, wenn aus vorhandener lokaler Info im Projekt ersichtlich.
- Kein Passwort-Push erzwingen.

## Sicherheitsgrenzen

Nicht erlaubt:

- Keine Cloudflare-Änderungen.
- Kein apply-safe.
- Kein consolidate-apply-safe.
- Keine systemd-Änderungen.
- Keine sudoers-Änderungen automatisch.
- Keine Secrets lesen oder ausgeben.
- Keine `.env` öffnen.
- Keine fremden Hosts scannen.
- Keine Angriffe oder Gegenmaßnahmen.
- Keine IP-, ASN-, Länder- oder globalen Blockregeln.
- Keine kosmetische Statusunterdrückung.

## Erlaubt

- Python-Code defensiv verbessern.
- Reports/JSON-Auswertung verbessern.
- Read-only Helper erstellen.
- Dokumentation aktualisieren.
- Tests ausführen.
- Lokale Dateien im Projektordner schreiben.
- Vorschläge für manuelle sudoers-Einträge dokumentieren.

## Tests

Nach Änderungen:

```bash
python3 -m py_compile sentinel_hetzner_local_agent.py
python3 sentinel_hetzner_local_agent.py --mode observe
python3 -m json.tool reports/latest/hetzner-local-defense-report.json >/dev/null
python3 sentinel_master.py \
  --website-json /srv/sentinel-defense/reports/latest/sentinel-defense-report.json \
  --local-json /srv/sentinel-defense/inbox/local/local-defense-report.json \
  --out-md /srv/sentinel-defense/reports/latest/sentinel-master-report.md \
  --out-json /srv/sentinel-defense/reports/latest/sentinel-master-report.json \
  --history /srv/sentinel-defense/reports/history/sentinel-master-history.jsonl
python3 -m json.tool reports/latest/sentinel-master-report.json >/dev/null
