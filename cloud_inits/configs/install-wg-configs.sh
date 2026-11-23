#!/bin/bash
# Install WireGuard configs generated on the deploy host.
# The bundle arrives on the cloud-init ISO as wg-configs.zip.
set -euo pipefail
exec > /var/log/wg-configs-install.log 2>&1

echo "Installing WireGuard configs at $(date)"

mkdir -p /etc/wireguard /srv/wg-configs /mnt/cidata

CIDATA_DEV=$(blkid -L cidata 2>/dev/null || true)
if [ -z "$CIDATA_DEV" ] && [ -e /dev/disk/by-label/cidata ]; then CIDATA_DEV=/dev/disk/by-label/cidata; fi
if [ -z "$CIDATA_DEV" ] && [ -e /dev/sr0 ]; then CIDATA_DEV=/dev/sr0; fi
if [ -z "$CIDATA_DEV" ] && [ -e /dev/cdrom ]; then CIDATA_DEV=/dev/cdrom; fi
if [ -n "$CIDATA_DEV" ]; then mount -o ro "$CIDATA_DEV" /mnt/cidata || true; fi

if [ ! -f /mnt/cidata/wg-configs.zip ]; then
  echo "ERROR: wg-configs.zip not found on the cloud-init ISO" >&2
  umount /mnt/cidata 2>/dev/null || true
  exit 1
fi
cp /mnt/cidata/wg-configs.zip /root/wg-configs.zip
umount /mnt/cidata 2>/dev/null || true

rm -rf /root/wg-bundle
mkdir -p /root/wg-bundle
unzip -o -q /root/wg-configs.zip -d /root/wg-bundle

install -m 600 /root/wg-bundle/server/wg0.conf /etc/wireguard/wg0.conf

cp -r /root/wg-bundle/admin/. /srv/wg-configs/
for dir in /root/wg-bundle/team*/; do
  [ -d "$dir" ] || continue
  cp "$dir"*.conf /srv/wg-configs/
done

cp /root/wg-bundle/admin.zip /root/admin.zip
cp /root/wg-bundle/team*.zip /root/

chmod 700 /srv/wg-configs
chmod 600 /srv/wg-configs/*.conf 2>/dev/null || true
chmod 600 /root/admin.zip /root/team*.zip 2>/dev/null || true

systemctl enable --now wg-quick@wg0

echo "WireGuard install completed at $(date)"
wg show wg0 || true
touch /root/.wg-configs-ready
