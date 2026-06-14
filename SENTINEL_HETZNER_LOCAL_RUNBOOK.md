# Sentinel Hetzner Local Defense Runbook

## Zweck

`sentinel_hetzner_local_agent.py` ist der lokale defensive Agent fuer den Hetzner-Server. Er sammelt passive Systeminformationen auf dem Server selbst und schreibt lokale Reports fuer den Sentinel Master.

Es gibt keinen Push vom privaten PC, keine Passwort-Automation, keine externen Scans und keine sudo-Nutzung im Agent.

## Architektur

```text
Hetzner Local Agent -> inbox/local -> Sentinel Master -> Daily Mail
```

Der Agent liest nur lokale Systeminformationen:

- `/proc/meminfo`
- Load Average des lokalen Systems
- Disk-Nutzung fuer `/`
- lokale SSH/Auth-Logs aus `/var/log/auth.log` oder `journalctl`, falls ohne sudo lesbar
- lokale Kommandos wie `ufw status`, `fail2ban-client status`, `ps`, `ss`, `systemctl is-active`
- Datei-Metadaten fuer definierte Integritaets-Watchpoints

Er schreibt:

- `/srv/sentinel-defense/reports/latest/hetzner-local-defense-report.md`
- `/srv/sentinel-defense/reports/latest/hetzner-local-defense-report.json`
- `/srv/sentinel-defense/reports/history/hetzner-local-defense-history.jsonl`

Nach erfolgreicher Report-Erzeugung aktualisiert er per atomarer Kopie:

- `/srv/sentinel-defense/inbox/local/local-defense-report.md`
- `/srv/sentinel-defense/inbox/local/local-defense-report.json`

Damit kann `sentinel_master.py` den lokalen Hetzner-Status als `local_status` lesen.

## Dauerhafter Schutz

Der Hetzner-Server wird dauerhaft durch lokale passive Checks ueberwacht, sobald der Timer oder ein manueller Lauf aktiv ist. Der Agent nimmt keine Aenderungen am Server vor. Ein `WARNING` bedeutet Review, nicht automatische Reparatur.

Typische `WARNING`-Gruende:

- `ufw status` ist ohne sudo nicht lesbar
- ein Sentinel Timer ist inaktiv
- mehrere SSH/Auth-Events ueberschreiten den Warning-Schwellwert
- RAM, Disk oder Load liegen ueber Warning-Schwellen

## CLI

Standardlauf:

```bash
cd /srv/sentinel-defense
python3 sentinel_hetzner_local_agent.py --mode observe
```

Simulation:

```bash
cd /srv/sentinel-defense
python3 sentinel_hetzner_local_agent.py --mode simulate
```

Explizite Pfade:

```bash
python3 /srv/sentinel-defense/sentinel_hetzner_local_agent.py \
  --mode observe \
  --out-md /srv/sentinel-defense/reports/latest/hetzner-local-defense-report.md \
  --out-json /srv/sentinel-defense/reports/latest/hetzner-local-defense-report.json \
  --history-path /srv/sentinel-defense/reports/history/hetzner-local-defense-history.jsonl \
  --compat-inbox-dir /srv/sentinel-defense/inbox/local
```

`simulate` schreibt ebenfalls einen Report, wendet aber keine Massnahmen an. Die simulierten Massnahmen sind manuelle Review-Vorschlaege.

## Bewertungslogik

Statuswerte:

- `OK`
- `WARNING`
- `CRITICAL`

Schwellwerte:

- Disk `/` > 90%: `WARNING`
- Disk `/` > 97%: `CRITICAL`
- RAM > 90%: `WARNING`
- RAM > 97%: `CRITICAL`
- Load pro CPU > 1.5: `WARNING`
- Load pro CPU > 3.0: `CRITICAL`
- fehlgeschlagene SSH-Logins > 25: `WARNING`
- fehlgeschlagene SSH-Logins > 100: `CRITICAL`
- `/etc/sentinel-defense.env` world-readable: `CRITICAL`
- `/srv/sentinel-defense` world-writable: `CRITICAL`
- ein Sentinel Timer inactive/unknown/failed: `WARNING`
- mehrere Sentinel Timer inactive/unknown/failed: `CRITICAL`
- `ufw` nicht lesbar ohne sudo: `WARNING`

`CRITICAL` schlaegt `WARNING`, `WARNING` schlaegt `OK`.

## Report-Inhalte

Markdown-Sektionen:

- Summary
- Findings
- System Load
- SSH/Auth
- Firewall
- fail2ban
- Processes
- Local Listening Ports
- Integrity Watchpoints
- Sentinel Timers
- Defensive Boundaries
- Outputs

JSON-Felder:

- `overall_status`
- `warning_count`
- `critical_count`
- `findings[]`
- `metrics{}`
- `sentinel_timers{}`
- `defensive_boundaries{}`
- `generated_at`
- `mode`

## Datenschutz Im Report

SSH/Auth:

- fehlgeschlagene Logins nur als Count
- erfolgreiche Logins nur als Count
- keine IP-Adressen
- keine Usernamen
- keine Roh-Logzeilen

Prozesse:

- Top CPU und Top RAM
- nur PID, PPID, Prozessname, CPU %, RAM %
- keine Commandline-Argumente
- keine Environment-Variablen

Firewall:

- `ufw status` nur als Statuszusammenfassung
- keine Firewall-Regel-Dumps
- keine IP-Listen

Listening Ports:

- nur lokale Socket-Inventur
- keine externen Hosts werden kontaktiert
- Prozess/Service wird gekuerzt auf Prozessnamen oder systemd-Service

Secrets:

- `/etc/sentinel-defense.env` Inhalt wird nie gelesen
- Reports enthalten nur Existenz, Mode und Lesbarkeits-Metadaten

## systemd-Betrieb

Diese Snippets sind nur Beispiele. Das Runbook installiert nichts.

`/etc/systemd/system/sentinel-hetzner-local.service`:

```ini
[Unit]
Description=Sentinel Hetzner local defense report

[Service]
Type=oneshot
User=deploy
Group=deploy
WorkingDirectory=/srv/sentinel-defense
ExecStart=/usr/bin/python3 /srv/sentinel-defense/sentinel_hetzner_local_agent.py --mode observe
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=read-only
ProtectSystem=strict
ReadWritePaths=/srv/sentinel-defense/reports /srv/sentinel-defense/inbox/local
ReadOnlyPaths=/srv/sentinel-defense /etc/ssh/sshd_config /etc/sentinel-defense.env
```

Timer pruefen:

```bash
systemctl is-active sentinel-hetzner-local.timer
systemctl status sentinel-hetzner-local.service --no-pager
```

## Betriebskommandos

Reports lesen:

```bash
cd /srv/sentinel-defense
less reports/latest/hetzner-local-defense-report.md
python3 -m json.tool reports/latest/hetzner-local-defense-report.json >/dev/null
tail -n 10 reports/history/hetzner-local-defense-history.jsonl
ls -la inbox/local/
```

Master mit lokalem Status neu erzeugen:

```bash
cd /srv/sentinel-defense
python3 sentinel_master.py \
  --website-json /srv/sentinel-defense/reports/latest/sentinel-defense-report.json \
  --local-json /srv/sentinel-defense/inbox/local/local-defense-report.json \
  --out-md /srv/sentinel-defense/reports/latest/sentinel-master-report.md \
  --out-json /srv/sentinel-defense/reports/latest/sentinel-master-report.json \
  --history /srv/sentinel-defense/reports/history/sentinel-master-history.jsonl
```

## Tests

```bash
cd /srv/sentinel-defense
python3 -m py_compile sentinel_hetzner_local_agent.py
python3 sentinel_hetzner_local_agent.py --mode observe
python3 sentinel_hetzner_local_agent.py --mode simulate
python3 -m json.tool reports/latest/hetzner-local-defense-report.json >/dev/null
ls -la inbox/local/
```

## Sicherheitsgrenzen

- Nur defensive Beobachtung.
- Keine Scans fremder Systeme.
- Keine Angriffe.
- Keine Credential-Sammlung.
- Keine externen Hosts kontaktieren.
- Keine Cloudflare-Aenderungen.
- Keine Systemaenderungen.
- Keine sudo-Nutzung im Agent.
- Keine Secrets in Reports.
- Keine Commandline-Argumente von Prozessen erfassen.
- `/etc/sentinel-defense.env` wird nur per Dateimetadaten geprueft; der Inhalt wird nie gelesen.
- Nur Python-Standardbibliothek.

## Troubleshooting

`ufw` ist `WARNING`:

- Der Agent nutzt kein sudo.
- Wenn `ufw status` ohne sudo nicht lesbar ist, bleibt das bewusst ein `WARNING`.
- Loesung nur nach separatem Review, zum Beispiel ein read-only Helper.

SSH/Auth ist `WARNING`:

- `/var/log/auth.log` ist eventuell nicht lesbar.
- `journalctl` liefert eventuell ohne Zusatzrechte keine SSH-Zeilen.
- Der Agent gibt trotzdem keine Rohlogs, IPs oder Usernamen aus.

Sentinel Timer sind `CRITICAL`:

- Mehrere erwartete Timer sind nicht `active`.
- Mit `systemctl is-active <unit>` manuell pruefen.
- Der Agent nimmt keine Aenderungen an systemd vor.

Env-Datei ist `CRITICAL`:

- `/etc/sentinel-defense.env` ist world-readable oder unsicher schreibbar.
- Inhalt wird vom lokalen Agenten nicht gelesen.
- Rechte manuell pruefen und korrigieren.

24h Rolling Window:

- Website-5xx koennen noch im Master sichtbar sein, obwohl die lokale Hetzner-Lage stabil ist.
- Hetzner Local Agent bewertet Serverzustand, nicht Cloudflare-Traffic.
