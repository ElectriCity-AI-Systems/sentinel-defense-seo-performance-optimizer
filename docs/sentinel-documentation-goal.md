# Goal: Sentinel Documentation Update

## Ziel

Aktualisiere die Sentinel-Dokumentation vollständig und sicher auf den aktuellen Stand.

Die Dokumentation soll klar erklären, dass Website, Hetzner-Server und private lokale Maschine dauerhaft durch Bots und Schutzebenen geschützt sind.

## Aktueller technischer Stand

Das Sentinel-System besteht aus:

- Cloudflare Daily Monitor
- Sentinel Defense Bot
- Hetzner Local Defense Agent
- Sentinel Master
- Daily Mailer
- Sentinel Local Agent auf dem privaten Ubuntu-PC
- UFW Firewall lokal
- fail2ban lokal
- read-only Helper lokal für UFW/fail2ban

## Aktive Website-Schutzregel

Die aktive kombinierte Cloudflare-Regel heißt:

`sentinel_combined_wordpress_scanner_challenge`

Sie schützt per `managed_challenge` gegen:

- SiteLockSpider auf `/wp-login.php`
- SiteLockSpider auf `/wp-json/oembed/1.0/embed`
- `/xmlrpc.php`
- `.env`
- `phpinfo`
- `secrets`
- host-gebunden auf `electri-c-ity-studios-24-7.com` und `www.electri-c-ity-studios-24-7.com` zusätzlich gegen:
  - `_next`
  - `__rsc`
  - `__nextjs_action`
  - `api/auth`

Die Regelanzahl in Cloudflare wurde konsolidiert:

- Aktuell 4 Regeln
- 3 fremde Regeln bleiben unverändert
- alte SentinelDefense-Einzelregeln wurden zusammengeführt
- Backup und Rollback-Hinweis existieren

## Dauerhafter Schutz

Dokumentiere ausdrücklich:

- Die Website ist dauerhaft durch Cloudflare-Regeln und Sentinel-Monitoring geschützt.
- Der Hetzner-Server wird dauerhaft durch den Hetzner Local Defense Agent überwacht.
- Die private lokale Maschine ist dauerhaft geschützt durch:
  - UFW
  - fail2ban
  - sshd Jail
  - Sentinel Local Agent Timer
  - read-only Helper
- Der private lokale Rechner hatte zuletzt:
  - Overall status OK
  - Findings: None
- Der lokale Rechner wird geschützt, sobald er online ist und seine Timer laufen.

## Zukunftsschutz

Dokumentiere:

- Neue Angriffe werden über Reports, Correlation Layer und Trend Layer erkannt.
- Neue Maßnahmen werden nicht blind automatisch gesetzt.
- Standardzyklus:
  observe → correlate → simulate → apply-safe → validate → report
- Bestehende Schutzregeln sind dauerhaft aktiv.
- Neue Regeländerungen benötigen Simulation und kontrolliertes apply-safe.
- Keine Gegenangriffe.
- Keine fremden Scans.
- Keine Credential-Sammlung.
- Keine IP-Rache.

## Zu aktualisierende Dateien

Falls vorhanden:

- `SENTINEL_DEFENSE_RUNBOOK.md`
- `SENTINEL_MASTER_RUNBOOK.md`
- `SENTINEL_HETZNER_LOCAL_RUNBOOK.md`
- `SENTINEL_LOCAL_RUNBOOK.md`
- `SENTINEL_LOCAL_READONLY_HELPER.md`
- `README.md`
- `docs/*.md`

## Dokumentation muss enthalten

1. Architekturübersicht:
   Cloudflare Monitor → Sentinel Defense → Hetzner Local Agent → Sentinel Master → Daily Mail.

2. Lokaler Rechner:
   Sentinel Local Agent → UFW → fail2ban → read-only helper.

3. Aktive Cloudflare-Regel:
   `sentinel_combined_wordpress_scanner_challenge`.

4. Pfade und Schutzlogik:
   `/wp-login.php`, oEmbed, `/xmlrpc.php`, `.env`, `phpinfo`, `secrets`, host-gebundene NextJS/Auth-Scannerpfade.

5. Erklärung:
   apply-safe läuft nicht unkontrolliert dauerhaft automatisch.

6. Betriebsmodell:
   observe läuft regelmäßig,
   simulate prüft geplante Aktionen,
   apply-safe nur kontrolliert mit confirm,
   consolidate-apply-safe nur nach sauberer Simulation.

7. Rollback:
   Backup-Dateien,
   `sentinel-defense-last-rollback.md`,
   keine automatische Rollback-Ausführung ohne Prüfung.

8. Daily Report:
   OK, WARNING, CRITICAL,
   Website Correlation Status NORMAL/WATCH/ACTION_CANDIDATE,
   Action Status WARNING_REVIEW/APPLY_CANDIDATE.

9. Lokaler Status:
   Erkläre, warum privater PC OK sein kann, während Hetzner Local Agent WARNING zeigt.

10. Betriebskommandos:
   Reports lesen,
   Timer prüfen,
   Master neu erzeugen,
   Simulation ausführen.
   Apply-Kommandos nur in gesondertem manuellen Abschnitt mit Warnhinweis.

11. Troubleshooting:
   Cloudflare Rules Limit 5/5,
   update failed,
   `source /etc/sentinel-defense.env` vermeiden,
   sudoers read-only helper,
   24h Rolling Window.

12. Sicherheitsgrenzen:
   Keine IP-/ASN-/Country-Regeln,
   keine globalen Blocks,
   nur `managed_challenge`,
   fremde Regeln nicht ändern,
   keine Secrets in Logs/Reports.

## Nicht erlaubt

- Keine Cloudflare-Änderungen.
- Kein apply-safe.
- Kein consolidate-apply-safe.
- Keine systemd-Änderungen.
- Keine Secrets lesen oder ausgeben.
- Keine `.env` öffnen.
- Keine produktiven Konfigurationsdateien verändern.
- Keine externen Hosts scannen.
- Keine Angriffe oder Gegenmaßnahmen.
- Keine Credential-Sammlung.

## Validierung

Nach der Dokumentationsarbeit:

- Markdown-Dateien prüfen.
- Keine Secrets aufnehmen.
- Keine `.env` lesen.
- Falls Git vorhanden ist: diff anzeigen.
- Zusammenfassen:
  - geänderte Dateien
  - was dokumentiert wurde
  - was bewusst nicht geändert wurde
