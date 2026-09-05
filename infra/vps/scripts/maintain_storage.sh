#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "maintain_storage.sh must run as root" >&2
  exit 1
fi

dionaea_root=/var/lib/docker/volumes/cti-vps_dionaea_data/_data
if [[ -d "${dionaea_root}/bistreams" ]]; then
  find "${dionaea_root}/bistreams" -type f -mtime +7 -delete
  find "${dionaea_root}/bistreams" -depth -type d -empty -delete
fi
if [[ -d "${dionaea_root}/binaries" ]]; then
  find "${dionaea_root}/binaries" -type f -mtime +30 -delete
fi

logrotate /etc/logrotate.d/cti-dionaea-container
logger -t cti-storage-maintenance "completed available_kb=$(df --output=avail / | tail -1 | tr -d ' ')"
