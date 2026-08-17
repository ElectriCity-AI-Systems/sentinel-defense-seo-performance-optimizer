#!/usr/bin/env bash
# REVIEW ONLY - DO NOT RUN WITHOUT OWNER FINAL CONFIRMATION
# read-only timer rollback review only
cat <<'REVIEW_ONLY'
# REVIEW ONLY - DO NOT RUN WITHOUT OWNER FINAL CONFIRMATION
# Manual commands for a future owner-approved uninstall review:
sudo systemctl disable --now sentinel-low-risk-readonly.timer
sudo rm /etc/systemd/system/sentinel-low-risk-readonly.timer
sudo rm /etc/systemd/system/sentinel-low-risk-readonly.service
sudo systemctl daemon-reload
REVIEW_ONLY
echo "Review-only file. This script intentionally does not uninstall anything."
exit 1
