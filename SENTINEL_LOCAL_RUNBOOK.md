# Sentinel Local Runbook

## Zweck

Dieses Runbook dokumentiert den Sentinel Local Agent auf dem privaten Ubuntu-PC. Der lokale Rechner ist dauerhaft durch lokale Schutzebenen geschuetzt, sobald er online ist und seine Timer laufen.

Schutzkette:

```text
Sentinel Local Agent -> UFW -> fail2ban -> read-only Helper
```

Der private lokale Rechner hatte zuletzt:

- `overall_status=OK`
- Findings: keine

## Lokale Schutzebenen

UFW:

- lokale Host-Firewall
- schuetzt eingehende Verbindungen nach lokalem Regelwerk
- Sentinel dokumentiert Status, nicht komplette Regel- oder IP-Listen

fail2ban:

- lokale Log-basierte Schutzschicht
- sshd Jail schuetzt SSH gegen wiederholte Fehlversuche
- Sentinel liest nur zusammengefasste Statusdaten

read-only Helper:

- ermoeglicht eng begrenzte, lesende Abfragen fuer UFW/fail2ban
- gibt keine Secrets aus
- darf keine Aenderungen anwenden

Sentinel Local Agent:

- erzeugt lokale defensive Reports
- sammelt nur passive lokale Informationen
- keine externen Scans
- keine Credential-Sammlung
- keine Cloudflare-Aenderungen

## Online-/Offline-Modell

Der lokale PC ist kein dauerhaft erreichbarer Server. Deshalb gilt:

- Wenn der PC offline ist, laufen lokale Timer nicht.
- Sobald der PC online ist und die Timer laufen, erzeugt der Sentinel Local Agent neue Reports.
- Ein fehlender oder alter PC-Report ist vom Hetzner-Server-Status getrennt zu bewerten.
- Der Master darf Website-, Hetzner- und PC-Lage nicht vermischen.

## Warum PC OK Und Hetzner WARNING Sein Koennen

Der private PC kann `OK` sein, waehrend der Hetzner Local Agent `WARNING` meldet. Beispiele:

- Hetzner `ufw status` ist ohne sudo nicht lesbar.
- Ein Hetzner Sentinel Timer ist inaktiv.
- Hetzner sieht andere Systemlast oder andere lokale Ports.
- Der private PC hat dagegen UFW, fail2ban, sshd Jail und Agent sauber aktiv.

Das ist kein Widerspruch. Es sind unterschiedliche Hosts mit eigenen lokalen Findings.

## Reports

Der private PC sollte seine lokalen Reports in die Sentinel-Kette liefern, wenn er online ist. Reports duerfen keine Secrets enthalten:

- keine IP-Listen aus Firewall-Regeln
- keine Usernamen aus Auth-Logs
- keine Rohlogs
- keine Prozess-Commandline mit Argumenten
- keine Environment-Variablen

Typische Felder:

- `overall_status`
- `warning_count`
- `critical_count`
- `findings[]`
- `firewall`
- `fail2ban`
- `timers`
- `defensive_boundaries`

## Betriebskommandos

Auf dem lokalen Ubuntu-PC:

```bash
systemctl --user list-timers | grep -i sentinel
systemctl --user status sentinel-local-agent.service --no-pager
journalctl --user -u sentinel-local-agent.service -n 100 --no-pager
```

UFW/fail2ban nur lesend pruefen:

```bash
sudo -n /usr/local/sbin/sentinel-local-readonly-helper ufw-status
sudo -n /usr/local/sbin/sentinel-local-readonly-helper fail2ban-status
sudo -n /usr/local/sbin/sentinel-local-readonly-helper fail2ban-sshd
```

Auf dem Hetzner-Server pruefen, ob ein lokaler Report angekommen ist:

```bash
cd /srv/sentinel-defense
ls -la inbox/local/
python3 sentinel_master.py
```

## Apply-Grenzen

Der lokale PC-Agent darf nicht:

- Firewall-Regeln aendern
- fail2ban neu starten oder Jails aendern
- SSH-Konfiguration aendern
- Passwoerter oder Tokens sammeln
- Cloudflare kontaktieren
- fremde Systeme scannen

Manuelle Aenderungen an UFW/fail2ban sind gesonderte Administrationsaufgaben und gehoeren nicht in den Sentinel-Automatikpfad.

## Troubleshooting

Timer laeuft nicht:

- PC ist eventuell offline oder im Suspend.
- User systemd Timer pruefen.
- Nach Login oder Boot Timer erneut pruefen.

Helper liefert keine Daten:

- sudoers Eintrag pruefen.
- Helper darf nur allowlistete read-only Kommandos ausfuehren.
- Keine allgemeinen sudo-Rechte fuer den Agent vergeben.

fail2ban nicht verfuegbar:

- fail2ban Service Status pruefen.
- Sentinel bleibt defensiv und dokumentiert `UNKNOWN` oder `WARNING`.

Alter Report im Master:

- Der lokale PC war eventuell offline.
- Master zeigt den letzten bekannten Stand oder `UNKNOWN`.
- Das ist von Website-`CRITICAL` oder Hetzner-`WARNING` getrennt zu bewerten.
