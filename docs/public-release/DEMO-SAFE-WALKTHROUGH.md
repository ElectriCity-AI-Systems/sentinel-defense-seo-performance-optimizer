# Demo Safe Walkthrough

This walkthrough uses `example.com` as a placeholder. It does not contact `example.com`, does not use customer data and does not perform live changes.

## Step 1: Status

```bash
python3 sentinel_autonomy.py status
```

## Step 2: Preflight

```bash
python3 sentinel_autonomy.py preflight
```

## Step 3: Operation Governor

```bash
python3 sentinel_autonomy.py operation-governor-status
```

## Step 4: Safe Batch

```bash
python3 sentinel_autonomy.py run-safe-batch 3
```

## Step 5: Soak Status

```bash
python3 sentinel_autonomy.py soak-status
```

## Step 6: Release Candidate Status

```bash
python3 sentinel_autonomy.py rc-status
```

## Step 7: Public Pack

```bash
python3 sentinel_autonomy.py public-release-status
```

All steps are local and bounded. The walkthrough demonstrates status, preflight, operation selection, safe batches, soak review, release status and evidence review.
