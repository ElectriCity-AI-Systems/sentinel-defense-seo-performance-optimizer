#!/bin/sh
# REVIEW ONLY - DO NOT RUN WITHOUT OWNER FINAL CONFIRMATION.
# This draft is read-only monitoring only.
# It does not enable live apply and does not change production systems.
# Inspect the service and timer draft files manually before any separate future owner decision.

cd /srv/sentinel-defense || exit 1
python3 sentinel_performance_trend_accumulator.py --collect-now
python3 sentinel_performance_trend_accumulator.py --analyze-trends
python3 sentinel_performance_trend_accumulator.py --status
