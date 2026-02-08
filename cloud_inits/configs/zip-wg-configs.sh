#!/bin/bash
set -euo pipefail
mkdir -p /root
if ls /srv/wg-configs/admin-*.conf >/dev/null 2>&1; then
  zip -j /root/admin.zip /srv/wg-configs/admin-*.conf
fi
for TEAM in $(seq 1 {{ n_teams }}); do
  if ls /srv/wg-configs/team${TEAM}-player*.conf >/dev/null 2>&1; then
    zip -j /root/team${TEAM}.zip /srv/wg-configs/team${TEAM}-player*.conf
  fi
done
