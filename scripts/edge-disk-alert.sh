#!/usr/bin/env bash
# Host-level disk alert: log when root filesystem crosses DISK_ALERT_THRESHOLD_PCT.
# Install via cron, e.g. every 5 minutes:
#   */5 * * * * DISK_ALERT_THRESHOLD_PCT=85 /home/edgex/sensel-ot-edge-sensor/scripts/edge-disk-alert.sh
set -euo pipefail

THRESH="${DISK_ALERT_THRESHOLD_PCT:-85}"
USED=$(df -P / | awk 'NR==2 {gsub(/%/,"",$5); print $5}')
FREE_GB=$(df -BG / | awk 'NR==2 {gsub(/G/,"",$4); print $4}')

if [[ -z "$USED" ]]; then
  exit 0
fi

if (( USED >= THRESH )); then
  logger -t sensel-disk-alert "WARNING root disk ${USED}% used (free ${FREE_GB}G) >= threshold ${THRESH}% on $(hostname -s)"
fi
