# Sentinel Local Read-only Helper

## Zweck

Der read-only Helper ist fuer den privaten Ubuntu-PC vorgesehen. Er gibt dem Sentinel Local Agent eng begrenzte Leserechte fuer lokale Schutzkomponenten, ohne allgemeine sudo-Rechte zu erteilen.

Er ist Teil dieser lokalen Schutzkette:

```text
Sentinel Local Agent -> UFW -> fail2ban -> read-only Helper
```

## Erlaubtes Verhalten

Der Helper darf nur zusammengefasste lokale Statusinformationen ausgeben:

- UFW Status
- fail2ban Gesamtstatus
- fail2ban sshd Jail Status
- optional systemd Status fuer lokale Sentinel Timer

Der Helper darf nicht:

- Firewall-Regeln aendern
- fail2ban konfigurieren
- Services starten, stoppen, reloaden oder restarten
- Dateien schreiben
- Secrets lesen
- Credentials ausgeben
- Rohlogs ausgeben
- externe Hosts kontaktieren

## Sicherheitsmodell

sudoers muss eng allowlistet sein:

- genaues Helper-Binary
- genau definierte Unterkommandos
- kein Shell-Zugriff
- keine Wildcards auf beliebige Programme
- keine Schreib- oder Restart-Kommandos

Beispielhafte Unterkommandos:

```text
ufw-status
fail2ban-status
fail2ban-sshd
sentinel-timers
```

Die Dokumentation ist bewusst kein sudoers-Installationsskript. Jede lokale sudoers-Aenderung muss separat geprueft werden.

## Datenminimierung

UFW:

- Status zusammenfassen
- keine vollstaendigen IP-Listen in Reports schreiben

fail2ban:

- Jail aktiv/inaktiv
- aktuelle Ban-/Failure-Zaehler
- keine Rohlog-Ausgabe
- keine IP-Listen in Sentinel Reports

Timer:

- nur `active`, `inactive`, `failed`, `unknown`
- keine Secrets aus Unit-Dateien

## Betrieb

Read-only Checks auf dem lokalen PC:

```bash
sudo -n /usr/local/sbin/sentinel-local-readonly-helper ufw-status
sudo -n /usr/local/sbin/sentinel-local-readonly-helper fail2ban-status
sudo -n /usr/local/sbin/sentinel-local-readonly-helper fail2ban-sshd
sudo -n /usr/local/sbin/sentinel-local-readonly-helper sentinel-timers
```

Wenn `sudo -n` ein Passwort verlangt, ist der Helper fuer den Agent nicht nutzbar. Dann soll Sentinel `WARNING` oder `UNKNOWN` melden, aber keine Passwort-Automation versuchen.

## Troubleshooting

`sudo -n` fragt nach Passwort:

- sudoers Eintrag fehlt oder passt nicht exakt.
- Keine Passwort-Automation einbauen.
- Helper nur nach manuellem Review korrigieren.

Helper gibt zu viele Details aus:

- Ausgabe auf aggregierte Statuswerte reduzieren.
- Keine IP-Listen, Usernamen, Tokens, Secrets oder Rohlogs.

fail2ban Status nicht lesbar:

- fail2ban Service pruefen.
- Helper-Berechtigung fuer genau den Statusbefehl pruefen.
- Keine weitergehenden sudo-Rechte vergeben.

UFW Status nicht lesbar:

- Helper-Berechtigung pruefen.
- Wenn nicht geloest, bleibt der lokale Agent bewusst bei `WARNING`.

## Grenzen

- Nur defensive lokale Lesefunktion.
- Keine Aenderungen an Firewall oder fail2ban.
- Keine Cloudflare-Aenderungen.
- Keine Scans.
- Keine Gegenmassnahmen.
- Keine Credential-Sammlung.
