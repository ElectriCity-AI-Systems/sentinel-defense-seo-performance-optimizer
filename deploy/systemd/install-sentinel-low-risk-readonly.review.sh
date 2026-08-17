#!/usr/bin/env bash
# REVIEW ONLY - DO NOT RUN WITHOUT OWNER FINAL CONFIRMATION
# read-only only
# no live apply
# owner must inspect before running
# emergency stop for write actions remains active
cat <<'REVIEW_ONLY'
# REVIEW ONLY - DO NOT RUN WITHOUT OWNER FINAL CONFIRMATION
# Manual commands for a future owner-approved install review:
sudo install -m 0644 /srv/sentinel-defense/deploy/systemd/sentinel-low-risk-readonly.service /etc/systemd/system/sentinel-low-risk-readonly.service
sudo install -m 0644 /srv/sentinel-defense/deploy/systemd/sentinel-low-risk-readonly.timer /etc/systemd/system/sentinel-low-risk-readonly.timer
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-low-risk-readonly.timer
sudo systemctl list-timers sentinel-low-risk-readonly.timer
REVIEW_ONLY
echo "Review-only file. This script intentionally does not install or enable anything."
exit 1
