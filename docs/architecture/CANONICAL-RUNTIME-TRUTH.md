# Canonical Runtime Truth (Phase 10.21)

Leitsatz:

```text
one operational fact
=
one canonical current value
=
one authoritative source
=
traceable provenance
```

Phase 10.21 ist eine reine **Reporting-, State-Resolution-, Source-Precedence-,
Diagnose- und Validierungs**-Phase. Kein produktives Apply, keine Cloudflare-/WAF-/DNS-/
TLS-Schreibaktion, keine systemd- oder Timer-Änderung, keine LOW_LIVE-/MEDIUM-/HIGH-
Aktivierung, keine WordPress-/DB-/Nginx-Änderung, keine Credential-Ausgabe, keine
Cookie- oder Authorization-Header-Speicherung.

## Problem

Ein Daily Report enthielt mehrere widersprüchliche operative Wahrheiten gleichzeitig:
oben Legacy-Werte aus der Level-1-Ära (`LEVEL_1_DRAFT_ONLY`, `timer=not_installed`,
`emergency_stop=True`, SEO-Checklistenpunkt als höchste Owner-Priorität, NowPlaying-504
aus dem Juni, SourceMap-Warnung aus dem Mai), weiter unten die aktuelle
Production-Pipeline-Wahrheit (`LEVEL_2_MONITORING_ACTIVE`, Timer aktiv,
`emergency_stop=false`).

## Lösung

Genau ein Resolver liefert für jedes operative Feld genau einen aktuellen Wert:

```text
sentinel_canonical_truth.py
```

Der Resolver erzeugt **keine neue Runtime-State-Maschine**. Die bestehenden
Fachkomponenten bleiben authoritative für ihre Domäne; der Resolver wählt feldweise
die autoritativste aktuelle Quelle und dokumentiert die Herkunft.

## Kette

```text
Evidence -> Freshness -> Source Precedence -> Canonical Truth -> Invariant Validation
         -> Owner Priority -> Master Report -> Daily Summary -> Public Summary
```

`sentinel_production_pipeline.py` erzwingt diese Reihenfolge. Der Daily Summary wird
niemals vor der Canonical Truth erzeugt.

## Source Precedence

| Tier | Source class | Bedeutung |
|---|---|---|
| 1 | `CURRENT_RUNTIME` | aktueller Live-Runtime-State (2-Minuten-Timer) |
| 2 | `CURRENT_SCHEDULER_STATE` | aktueller Scheduler-State |
| 3 | `CURRENT_PRODUCTION_PIPELINE` | aktuelle Production Pipeline |
| 4 | `CURRENT_WEBSITE_EVIDENCE` | aktuelle Website-Monitor-Evidence |
| 5 | `CURRENT_ORIGIN_DIAGNOSTICS` | aktuelle Origin-Diagnostics |
| 6 | `CURRENT_RECOVERY_MODULE` | aktuelle Recovery-Module |
| 7 | `CURRENT_CONSISTENCY_EVALUATION` | aktuelle Consistency-Auswertung |
| 8 | `LEGACY_HISTORICAL` | stale Legacy-Reports, nur informational |

Die Registry steht in `sentinel_canonical_truth.py`
(`SOURCE_LIST`, `canonical_source_registry()`) und wird als Playbook nach
`playbooks/sentinel-runtime-source-precedence.playbook.json` geschrieben.

## Feldweise Autorität

Nicht die Quelle als Ganzes gewinnt, sondern pro Feld (`FIELD_OWNERSHIP`):

- **Runtime** (`runtime_stage`, `autonomy_level`, `monitoring_enabled`,
  `systemd_timer_active/_enabled`, `scheduler_verification_status`,
  `guarded_live_autonomy_enabled`, `low/medium/high_live_apply_enabled`,
  `production_apply_lock`, `emergency_stop`, `circuit_breaker_status`,
  `rollback_status`, `promotion_status`, `write_canary_status`, `breach`,
  `last_cycle_id`, `last_decision`) kommen ausschließlich aus dem aktuellen
  Guarded-Runtime-State. Level-1-Module sind als Quelle strukturell ausgeschlossen
  (Self-Test `runtime_fields_never_legacy`).
- **Website** (`website_status`, `total_5xx`, `504/503/522/526`,
  `rolling_window_status`, `current_snapshot_id`, `top_failure_paths`,
  `current_growth`, `source_map_404`, `nowplaying_504`, `wp_users_me_504`) kommen
  ausschließlich aus aktuellen Monitor-Snapshots (Self-Test
  `website_fields_only_monitor`).
- **Owner Priority** wird kanonisch nach einer festen 9-stufigen Rangfolge bestimmt.

## Freshness-Vokabular

```text
CURRENT
STALE_INFORMATIONAL
STALE_EXCLUDED_FROM_MASTER_STATUS
MISSING
INVALID
SUPERSEDED   (neu in Phase 10.21)
```

`SUPERSEDED` bedeutet: die Quelle kann zeitlich noch brauchbar sein, ist aber **für
dieses Feld** durch eine autoritativere Quelle ersetzt. Beispiel: Legacy Autonomy
Policy `LEVEL_1_DRAFT_ONLY` ist historisch valide, für `current_runtime_level` aber
`SUPERSEDED` durch `LEVEL_2_MONITORING_ACTIVE`.

Das Current-Fenster hängt von der Quellenart ab (`KIND_TTL_SECONDS`):
`RUNTIME_CYCLE` 2 h, `ROLLING_METRIC` 24 h, `STATE_OF_RECORD` 30 Tage,
`LEGACY_DIAGNOSTIC` 24 h. Ein State-of-Record-Eintrag (z. B. Write-Canary-Status)
verfällt nicht nach 24 h, weil er die letzte protokollierte Zustandsänderung abbildet,
keine rollierende Messung.

## Provenance

Jedes kanonische Feld trägt:

```json
{
  "value": "LEVEL_2_MONITORING_ACTIVE",
  "source": "reports/latest/sentinel-guarded-autonomy.json",
  "source_class": "CURRENT_RUNTIME",
  "generated_at": "2026-08-12T...",
  "freshness": "CURRENT",
  "operational_effect": true
}
```

Legacy-Ansprüche auf dasselbe Feld bleiben erhalten, aber mit
`freshness=SUPERSEDED`, `superseded_by=<Quelle>` und `operational_effect=false`.

## Fail-Closed

Fehlt eine aktuelle autoritative Quelle für ein Pflichtfeld, gilt:

```text
CANONICAL_TRUTH_INCOMPLETE
runtime_status=UNKNOWN
missing_fields=[...]
```

Es wird **kein** Legacy-Wert eingesetzt, um eine Lücke zu füllen.

## Owner-Priority-Hierarchie

```text
1 SAFETY_BREACH_ESCALATION          breach oder Emergency-Zustand
2 WEBSITE_ORIGIN_STABILITY          Website-Ausfall / CRITICAL
3 WEBSITE_ORIGIN_STABILITY          dominante aktuelle Origin-Fehler
4 RUNTIME_STABILITY_REVIEW          Runtime- oder Scheduler-Fehler
5 ORIGIN_TLS_REVIEW                 aktueller TLS-Fehler
6 AI_RADIO_NOWPLAYING_RECOVERY      NowPlaying / API-Origin-Stabilität
7 PERFORMANCE_DEGRADATION_REVIEW    Performance-Degradation
8 SECURITY_DIAGNOSTIC_REVIEW        Security-Diagnose-Review
9 SEO_TITLE_REVIEW                  SEO / redaktionelle Arbeit
```

Der Legacy-Checklistenpunkt `manual_check:draft-exec-seo-title` darf nur führen, wenn
`website_status=OK`, die Runtime gesund ist und keine höhere operative Priorität
existiert (`legacy_seo_checklist_allowed`).

## Invariant Validator

`sentinel_canonical_invariants.py` prüft gegen die Canonical Truth:

| Invariant | Unzulässig |
|---|---|
| `runtime` | Header `LEVEL_1_DRAFT_ONLY` bei Pipeline `LEVEL_2_MONITORING_ACTIVE` |
| `emergency_stop` | Header `true` bei Runtime `false` |
| `timer` | Header `not_installed` bei aktivem systemd-Timer |
| `nowplaying` | Header `504=0` bei aktuellem Wert `> 0` |
| `sourcemap` | Stale `.map`-Warning als aktueller Status bei `map_404=0` |
| `owner_priority` | SEO führend bei `website_status` in `{WARNING, CRITICAL}` |
| `overall_status` | Master-Status niedriger als kanonischer Status (Eskalation erlaubt) |
| `executive_table` | Legacy-Wert in einer nicht als Legacy gekennzeichneten Zeile |
| `daily_header` | Superseded Wert im aktuellen Kopfteil |

Zusätzlich prüft `sentinel-daily-summary-consistency.json`, dass
`daily header runtime = master runtime = pipeline runtime` gilt — ebenso für `timer`,
`emergency_stop`, `breach`, `owner_priority`, `website_status`, `total_5xx`,
`nowplaying_504`, `low_live_enabled`.

## Legacy-Erhalt

Nichts wird gelöscht: keine historische Komponente, kein alter Report, keine alte
State-Datei. Legacy-Module erscheinen weiterhin, aber ausschließlich unter
`Legacy / Historical Modules` mit `legacy status`, `generated_at`, `freshness`,
`superseded_by` und `operational_effect=false`.

## `/wp-json/wp/v2/users/me`

`sentinel_origin_failure_diagnostics.py` klassifiziert diesen Pfad read-only aus
vorhandenen Aggregaten (Request-Frequenz, Actor-Klasse, User-Agent-Klasse,
Country-Verteilung, Cache-Status, Response-Status, Referer-Klasse falls erhoben):

```text
WP_USERS_ME_EXPECTED_ADMIN_TRAFFIC
WP_USERS_ME_FRONTEND_DEPENDENCY
WP_USERS_ME_BOT_OR_SCANNER
WP_USERS_ME_PLUGIN_POLLING
WP_USERS_ME_ORIGIN_TIMEOUT
WP_USERS_ME_EVIDENCE_INSUFFICIENT
```

Keine Cookies, keine Authorization-Header, keine Tokens, keine User-IDs — ein
`privacy_scan()` prüft die erzeugte Evidence gegen Identitätsfelder. Zeitliche
Clusterung wird als `EVIDENCE_NOT_COLLECTED` gemeldet, weil der Cloudflare-Snapshot
diesen Pfad ohne Zeitdimension aggregiert. Keine produktive Regel, kein Rate-Limit,
keine WAF-Änderung.

## CLI

```bash
python3 sentinel_canonical_truth.py --self-test
python3 sentinel_canonical_truth.py --discover
python3 sentinel_canonical_truth.py --resolve
python3 sentinel_canonical_truth.py --validate
python3 sentinel_canonical_truth.py --status

python3 sentinel_canonical_invariants.py --self-test
python3 sentinel_canonical_invariants.py --validate
python3 sentinel_canonical_invariants.py --status

python3 sentinel_production_pipeline.py --run
python3 sentinel_production_pipeline.py --validate-output
python3 sentinel_production_pipeline.py --status

python3 sentinel_origin_failure_diagnostics.py --analyze-wp-users-me
```

## Outputs

```text
reports/latest/sentinel-canonical-truth.json|.md
reports/latest/sentinel-canonical-invariants.json|.md
reports/latest/sentinel-legacy-supersession.json|.md
reports/latest/sentinel-daily-summary-consistency.json|.md
reports/latest/sentinel-canonical-daily-header.md
reports/latest/sentinel-origin-wp-users-me-classification.md
state/adaptive-learning/canonical_truth.json
state/adaptive-learning/canonical_truth_history.json
audit/sentinel-canonical-truth.jsonl
audit/sentinel-canonical-invariants.jsonl
playbooks/sentinel-canonical-runtime-truth.playbook.json
playbooks/sentinel-legacy-supersession.playbook.json
playbooks/sentinel-daily-summary-consistency.playbook.json
playbooks/sentinel-runtime-source-precedence.playbook.json
```

## Timer-Unabhängigkeit

`sentinel-master.timer` und `sentinel-daily-mail.timer` laufen unabhängig von der
Pipeline. Master-Report und Mailer verwenden deshalb
`canonical_truth.load_or_resolve()`: ein persistierter Snapshot älter als
`SNAPSHOT_MAX_AGE_SECONDS` (10 Minuten) wird in-memory neu aufgelöst statt als aktuell
ausgegeben. Das Neuauflösen schreibt nichts — die kanonischen Artefakte gehören der
Pipeline.

## Module-Boundary vs. Runtime-State

`SAFETY_FLAGS["emergency_stop"] = True` in `sentinel_origin_failure_diagnostics.py` und
`sentinel_master_report_consistency.py` ist eine **Modulgrenze** ("dieses Modul
verhält sich, als sei produktives Apply gesperrt"), kein Runtime-Zustand. Der echte
Runtime-Zustand steht in denselben Reports als `runtime_emergency_stop`,
`runtime_breach`, `runtime_autonomy_level` usw. und stammt aus
`canonical_truth.resolve_runtime_flags()`.

**Legacy-Historie darf niemals wieder die aktuelle operative Wahrheit überschreiben.**
