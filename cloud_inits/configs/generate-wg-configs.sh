#!/bin/bash
set -euo pipefail
exec > /var/log/wg-config-gen.log 2>&1

echo "Starting WireGuard config generation at $(date)"
mkdir -p /srv/wg-configs
chmod 700 /srv/wg-configs

cd /etc/wireguard
umask 077

# Generate server keys once
if [[ ! -f server.key ]]; then
  wg genkey | tee server.key | wg pubkey > server.pub
fi
SERVER_PRIV="$(cat server.key)"
SERVER_PUB="$(cat server.pub)"

# Allowed IPs that clients can reach through the tunnel
# 10.58.57.0/24  - team VMs
# 10.10.10.0/24  - ForcAD + infra
# 10.57.0.0/16   - other WG players (if needed)
CLIENT_ALLOWED="10.58.57.0/24, 10.10.10.0/24, 10.57.0.0/16"

# Write server config
# Use /32 so the kernel does NOT claim 10.10.0.0/16 via wg0.
# Explicit PostUp routes send only WG-client subnets into the tunnel.
cat > wg0.conf <<EOF
[Interface]
Address = {{ wg_gw_ip }}/32
ListenPort = {{ wg_port }}
PrivateKey = $SERVER_PRIV
PostUp   = ip route add 10.57.0.0/16 dev %i; ip route add 10.10.10.0/29 dev %i
PostDown = ip route del 10.57.0.0/16 dev %i 2>/dev/null; ip route del 10.10.10.0/29 dev %i 2>/dev/null
EOF

# Admin configs: 10.10.10.2-10.10.10.9
for IP_LAST in $(seq 2 9); do
  NAME="admin-$IP_LAST"
  wg genkey | tee "/srv/wg-configs/$NAME.key" | wg pubkey > "/srv/wg-configs/$NAME.pub"
  PEER_PUB="$(cat "/srv/wg-configs/$NAME.pub")"
  PEER_PRIV="$(cat "/srv/wg-configs/$NAME.key")"

  cat >> wg0.conf <<EOF

[Peer]
PublicKey = $PEER_PUB
AllowedIPs = 10.10.10.$IP_LAST/32
EOF

  cat > "/srv/wg-configs/$NAME.conf" <<EOF
[Interface]
Address = 10.10.10.$IP_LAST/32
PrivateKey = $PEER_PRIV

[Peer]
PublicKey = $SERVER_PUB
Endpoint = {{ wg_endpoint }}
AllowedIPs = $CLIENT_ALLOWED
PersistentKeepalive = 25
EOF
done

# Team configs: 11 per team  (10.57.<team>.3 .. 10.57.<team>.13)
for TEAM in $(seq 1 {{ n_teams }}); do
  for IP_LAST in $(seq 3 13); do
    NAME="team${TEAM}-player${IP_LAST}"
    wg genkey | tee "/srv/wg-configs/$NAME.key" | wg pubkey > "/srv/wg-configs/$NAME.pub"
    PEER_PUB="$(cat "/srv/wg-configs/$NAME.pub")"
    PEER_PRIV="$(cat "/srv/wg-configs/$NAME.key")"

    cat >> wg0.conf <<EOF

[Peer]
PublicKey = $PEER_PUB
AllowedIPs = 10.57.$TEAM.$IP_LAST/32
EOF

    cat > "/srv/wg-configs/$NAME.conf" <<EOF
[Interface]
Address = 10.57.$TEAM.$IP_LAST/32
PrivateKey = $PEER_PRIV

[Peer]
PublicKey = $SERVER_PUB
Endpoint = {{ wg_endpoint }}
AllowedIPs = $CLIENT_ALLOWED
PersistentKeepalive = 25
EOF
  done
done

chmod 600 /etc/wireguard/wg0.conf
chmod 600 /srv/wg-configs/*.key
chmod 644 /srv/wg-configs/*.conf /srv/wg-configs/*.pub

echo "WireGuard config generation completed at $(date)"
echo "Generated $(ls -1 /srv/wg-configs/*.conf 2>/dev/null | wc -l) client configs"
touch /root/.wg-configs-ready
