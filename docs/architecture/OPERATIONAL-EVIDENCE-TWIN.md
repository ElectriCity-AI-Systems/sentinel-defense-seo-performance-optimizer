# Sentinel Operational Evidence Twin

## Decision

The next system-level capability is a local operational evidence twin with counterfactual shadow replay.

The twin converts heterogeneous local observations into a common event stream, represents incident states and transitions as stable fingerprints, detects robust regime changes, evaluates a provisional technical reliability reference, and replays action policy without executing a productive action.

This closes the gap between "more reports" and evidence-based autonomous operations. Sentinel can learn which decisions would have been eligible under historical conditions before any action class is considered for live use.

## Standards Basis

### OpenTelemetry

The [OpenTelemetry Logs Data Model](https://opentelemetry.io/docs/specs/otel/logs/data-model/) defines a stable common representation for logs and events from heterogeneous sources. Sentinel uses an aligned subset:

- event name
- source timestamp
- observed timestamp
- severity
- body metadata
- resource context
- attributes
- provenance

The twin does not emit OTLP and does not require an OpenTelemetry dependency. The JSON representation preserves the distinction between event time and observation time, including unknown source timestamps.

### OCSF

The [Open Cybersecurity Schema Framework](https://ocsf.io/) provides a vendor-neutral JSON-oriented taxonomy for security events. Sentinel records a conceptual HTTP activity mapping while explicitly setting `normative_ocsf_event=false`. This avoids claiming conformance to an event class that has not been fully mapped and validated.

### Digital Twin Trust

[NIST IR 8356](https://doi.org/10.6028/NIST.IR.8356) describes digital twins as electronic representations of real entities and their state transitions, with security and trust considerations. Sentinel's twin represents operational evidence only. It cannot control the represented production system.

### Reliability Budgets

The [Google SRE error budget policy](https://sre.google/workbook/error-budget-policy/) uses reliability budgets to balance innovation and stability. Sentinel computes a provisional technical edge SLI reference from local aggregates. It is not an owner-approved SLO and is not evidence of human-user impact.

The [Google SRE guidance on alerting from SLOs](https://sre.google/workbook/alerting-on-slos/) describes multiwindow, multi-burn-rate alerting. Those claims require suitable denominator windows; overlapping rolling 24-hour snapshots are not treated as sufficient for that calculation.

The technical ratio uses 5xx responses and the total response count from the same status-code aggregate. A separate request total is retained as provenance and any denominator mismatch is reported rather than silently mixed into the calculation.

### Governed Autonomy

The [NIST AI RMF Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/) emphasizes continuous govern, map, measure, and manage activities, documented human oversight, post-deployment monitoring, and mechanisms to disengage systems with unintended outcomes. The twin operationalizes these ideas as immutable policy, provenance, shadow decisions, and zero execution capability.

### Incident Response

[NIST SP 800-61 Revision 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) integrates incident response into cybersecurity risk management. Sentinel therefore preserves source provenance, evidence gaps, owner priorities, and decision auditability instead of treating a telemetry correlation as a repair authorization.

### Regime Awareness

[Bayesian Online Changepoint Detection](https://arxiv.org/abs/0710.3742) motivates online reasoning about state changes. Sentinel currently uses a transparent median/MAD replay detector because the available observations are sparse rolling aggregates. It makes no Bayesian posterior or probability claim.

## Data Flow

1. Read only fixed local Sentinel reports and a bounded number of local telemetry snapshots.
2. Validate every path against the project root and reject symlinks.
3. Normalize snapshots into provenance-bearing event records.
4. Create a stable incident fingerprint from status bands, trends, TLS signals, scanner volume, and path classes.
5. Detect robust deviations from recent median/MAD baselines and coalesce adjacent points into bounded change episodes.
6. Build a graph of sources, events, fingerprints, regime changes, and shadow action candidates.
7. Compute a provisional technical reliability reference.
8. Replay policy gates against historical observations.
9. Produce owner-only reports and one sanitized public summary.

## Counterfactual Boundary

The replay answers:

> Given the evidence available at that point, which policy decision would have been eligible?

It does not answer:

> What would have happened if the action had been applied?

The second question requires treatment and outcome evidence. Aggregate observational telemetry cannot establish that causal effect.

## Safety Invariants

- mode is always `SHADOW_ONLY`
- no runtime network access
- no shell or subprocess execution
- no arbitrary paths or URLs
- no credentials or response bodies
- no live apply or remote write
- no scheduler installation
- no LOW_LIVE, MEDIUM, or HIGH execution
- no policy self-expansion
- `verified_user_impact=unknown` without direct evidence
- `causality_proven=false` for aggregate correlations
- reports, state, audit, and telemetry snapshots are excluded from Git recommendations

## Promotion Criteria

The twin itself is useful immediately in shadow mode. A future action class may only use its results after independent adapter validation, direct evidence, canary validation, rollback proof, and explicit owner policy. Twin scores alone never authorize production execution.
