# Evidence-Guided Origin Recovery (Phase 10.22)

Leitsatz:

```text
Evidence first. Repair second. Measurement third. Rollback always.
```

Keine produktive Reparatur ohne nachgewiesene Ursache, klaren Scope, messbaren
Nutzen, Health-Canary und sicheren Rollback. Keine Änderung ist besser als eine
unbeweisbare Änderung.

## Komponenten

```text
sentinel_origin_route_mapper.py   Route- und Ownership-Rekonstruktion (read-only)
sentinel_504_recovery.py          Baseline, Klassifikation, Repairability, Repair-Gate, Effekt
```

Beide erzeugen keine parallele Runtime-Zustandsmaschine. Die Ergebnisse fließen
über `sentinel_canonical_truth.py` in die kanonische Wahrheit (Phase 10.21).

## Rolling Window ist nicht aktuelle Fehlerproduktion

Der 24h-Zähler enthält alte Fehler. Direkt beobachtbar ist nur die **Änderung**
des Zählers zwischen zwei Monitor-Snapshots:

```text
C(T) - C(T-15m) = neue Fehler - Fehler, die aus dem 24h-Fenster fallen
```

Daraus folgt die einzige ehrliche starke Aussage:

```text
new_errors_lower_bound = max(0, net_delta)          # PROVEN
net_delta <= 0  ist konsistent mit "keine neuen Fehler"
net_delta  > 0  beweist, dass neue Fehler produziert werden
```

Der Monitor schreibt etwa alle 15 Minuten einen Snapshot. Deshalb:

```text
5m   -> EVIDENCE_NOT_COLLECTED   (niemals interpoliert)
15m  -> 1 Snapshot-Schritt
60m  -> 4 Snapshot-Schritte
```

## Evidence-Level

```text
PROVEN         direkte Evidence (autoritativer DNS-Record, reproduzierter Timeout, Origin-Log)
STRONG         mehrere unabhängige Signale, aber ein Kettenglied fehlt
SUGGESTIVE     plausible Richtung, keine Reparaturfreigabe
INSUFFICIENT   keine Ursachenbehauptung
CONTRADICTED   Evidence widerspricht der Hypothese
```

## Cloudflare-Zugriff

Ausschließlich read-only GET auf einer festen Pfad-Allowlist:

```text
/zones/{zone_id}
/zones/{zone_id}/dns_records
```

Keine DNS-, Proxy-Status-, Ruleset-, SSL-, Origin-Rules- oder Load-Balancer-
Änderung ist im Code vorhanden. Der Write-Canary bleibt blockiert. Credential-
Werte werden über einen sicheren Parser gelesen und niemals ausgegeben.

## Probe-Scope

Kontaktiert werden ausschließlich:

* Hostnamen innerhalb der konfigurierten First-Party-Zone,
* Pfade aus einer festen Endpoint-Allowlist,
* beim Origin-Probe nur die IPv4-Adresse, die autoritatives Cloudflare-DNS für
  genau diesen Hostnamen zurückgegeben hat.

Response-Bodies werden nie gespeichert; erfasst werden Status, Latenz,
Größenklasse, Content-Type und eine kleine Header-Allowlist.

Ein 403 vom Edge auf einen Nicht-Browser-Client ist eine Bot-Fight-Challenge und
**kein** Endpoint-Health-Signal (`EDGE_CHALLENGE_EXPECTED_FOR_NON_BROWSER`).

## Reparaturklassen

Nur diese dürfen je automatisch ausgeführt werden:

```text
R1  Sentinel-owned cache restoration
R2  Sentinel-owned stale fallback restoration
R3  exact proxy route repair
R4  cache stampede protection (proxy_cache_lock)
```

Ziel-Dateien stammen aus einer festen Allowlist
(`SENTINEL_OWNED_REPAIR_TARGETS`). Es gibt keine freien Pfade, keine freien
Hosts und keine freie Shell.

Immer Owner Review, niemals automatisch:

```text
WordPress-/Plugin-/Theme-Code, Datenbank, PHP-FPM, globales nginx/Apache,
globale Timeout-Erhöhung, Cloudflare-Regeln, DNS, TLS, Origin-Migration,
Load Balancer, API-Semantik, Frontend-Polling, /users/me-Verhalten
```

Timeout-Erhöhung maskiert 504 und ist nie ein automatischer Kandidat.

## Repair Decision Gate

```text
causality evidence = PROVEN
repairability      = SAFE
repair_class       in [R1,R2,R3,R4]
rollback_ready     = true
scope_exact        = true
```

Andernfalls:

```text
NO_SAFE_AUTOMATIC_REPAIR
```

Das ist ein gültiges, vollständiges Ergebnis.

## Effekt-Messung und False-Success-Schutz

Erfolg wird nie am 24h-Zähler allein gemessen. Geprüft werden:

```text
baseline_rate, post_apply_rate, absolute_delta, relative_delta_percent,
window_minutes, confidence
```

Guards, die einen scheinbaren Erfolg entwerten:

```text
traffic_disappeared     Verkehr ist weggebrochen
monitor_stale           Snapshot hat sich nicht bewegt
error_migration         504 sinkt, 503/522/526 wachsen entsprechend
endpoint_unreachable    keine Requests mehr
```

Ohne angewandte Reparatur ist die Fenster-Differenz **beobachteter Drift**, kein
Reparatur-Effekt (`NO_REPAIR_APPLIED_EFFECT_NOT_APPLICABLE`).

## `/wp-json/wp/v2/users/me`

Read-only. Niemals gespeichert: Cookies, Authorization-Header, Tokens,
Session-IDs, User-IDs, personenbezogene Daten. Ein `privacy_scan()` prüft die
erzeugte Evidence gegen Identitätsfelder.

Authentifizierungs-Evidence wird ausschließlich aus Antwortstatus abgeleitet:
eine 401-Antwort beweist, dass die Anfrage keine gültige Authentifizierung trug.

Ursachenklassen ranken über Akteursklassen: ein Bot-Signal ist immer nur
`secondary_signal`, nie die primäre Ursache
(`USERS_ME_PRIMARY_PRIORITY`).

Auf diesem Endpoint sind Caching, Auth-Bypass, REST-Rechteänderung, Block- oder
Challenge-Regeln grundsätzlich verboten.

## Primary Failure Focus

Rangfolge (nicht nur 24h-Summe):

```text
1. größter aktueller neuer Fehlerbeitrag
2. höchste 504-Rate
3. größter bestätigter User Impact
4. sicher reparierbare Ursache
```

Die kanonische Owner Priority bleibt `WEBSITE_ORIGIN_STABILITY`; der Focus
ergänzt sie um den konkreten Endpunkt.

## CLI

```bash
python3 sentinel_origin_route_mapper.py --self-test
python3 sentinel_origin_route_mapper.py --discover
python3 sentinel_origin_route_mapper.py --map-hosts
python3 sentinel_origin_route_mapper.py --map-endpoints
python3 sentinel_origin_route_mapper.py --validate
python3 sentinel_origin_route_mapper.py --status

python3 sentinel_504_recovery.py --self-test
python3 sentinel_504_recovery.py --collect-baseline
python3 sentinel_504_recovery.py --classify
python3 sentinel_504_recovery.py --build-failure-graph
python3 sentinel_504_recovery.py --build-repairability
python3 sentinel_504_recovery.py --prepare-repair
python3 sentinel_504_recovery.py --validate-repair
python3 sentinel_504_recovery.py --apply-approved-repair
python3 sentinel_504_recovery.py --validate-post-apply
python3 sentinel_504_recovery.py --evaluate-effect
python3 sentinel_504_recovery.py --rollback
python3 sentinel_504_recovery.py --status
```

Keine freien Hosts, URLs oder Pfade als CLI-Argumente.

## Canonical Truth Integration

Neue kanonische Felder (Phase 10.21-Resolver, Tier 5/6):

```text
origin_route_map_status
origin_recovery_status
dominant_504_endpoint
dominant_504_origin
dominant_504_share_percent
origin_504_repairability
primary_failure_focus
last_origin_repair
last_origin_repair_effect
```

## Remote Origin

Ist der tatsächliche Origin ein anderer eigener Server, gilt ohne verifiziertes
Zugriffsprofil:

```text
REMOTE_OWNER_ACTION_REQUIRED
```

Keine automatische SSH-Discovery über fremde IPs, keine Credential-Erzeugung,
keine automatisierte Passwortabfrage.
