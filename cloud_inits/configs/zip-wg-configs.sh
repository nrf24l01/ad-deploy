#!/bin/bash
set -euo pipefail
mkdir -p /root
if ls /srv/wg-configs/admin-*.conf >/dev/null 2>&1; then
  zip -j /root/admin.zip /srv/wg-configs/admin-*.conf
fi
{% for t in teams %}
if ls /srv/wg-configs/team{{ t.team }}-player*.conf >/dev/null 2>&1; then
  cat > /root/info.txt <<EOF
Team {{ t.team }}
IP: {{ t.ip }}
User: {{ t.user }}
Password: {{ t.password }}
EOF
  zip -j /root/team{{ t.team }}.zip /srv/wg-configs/team{{ t.team }}-player*.conf /root/info.txt
fi
{% endfor %}
