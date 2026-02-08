#!/usr/bin/env python3
import os
import time
import json
import secrets
import string
import subprocess
import tempfile
import shutil
import zipfile
from datetime import datetime
from urllib.parse import urljoin
from dotenv import load_dotenv
load_dotenv()

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from proxmoxer import ProxmoxAPI

# ===================== Proxmox API =====================
PVE_HOST = os.environ["PVE_HOST"]              # e.g. https://192.168.1.89:8006
PVE_PORT = int(os.environ.get("PVE_PORT", "8006"))
PVE_HOST_CLEAN = PVE_HOST.replace("https://", "").replace("http://", "").split(":")[0]
PVE_NODE = os.environ.get("PVE_NODE", "pve")
TOKEN_ID = os.environ["PVE_TOKEN_ID"]
TOKEN_SECRET = os.environ["PVE_TOKEN_SECRET"]
VERIFY_TLS = os.environ.get("VERIFY_TLS", "0") == "1"

TEMPLATE_VMID = int(os.environ.get("TEMPLATE_VMID", "9000"))

# Storage for cloud-init ISOs
ISO_STORAGE = os.environ.get("ISO_STORAGE", "local")
ISO_DIR = os.environ.get("ISO_DIR", "/var/lib/vz/template/iso")

# ===================== Lab config =====================
N_TEAMS = int(os.environ.get("N_TEAMS", "5"))
BR_CTF = os.environ.get("BR_CTF", "vmbr10")  # Single bridge for all CTF traffic (10.0.0.0/8)
ORG_HOST_IP = os.environ.get("ORG_HOST_IP", "10.10.10.254/8")
ORG_HOST_ADDR = ORG_HOST_IP.split("/")[0]
DNS_SERVERS = [s.strip() for s in os.environ.get("DNS_SERVERS", "1.1.1.1,8.8.8.8").split(",") if s.strip()]
CTF_NET_CIDR = os.environ.get("CTF_NET_CIDR", "10.0.0.0/8")  # Combined CTF network

# External network on net1 (VLAN)
EXT_BRIDGE = os.environ.get("EXT_BRIDGE", "vmbr1")  # External bridge name
EXT_VLAN = os.environ.get("EXT_VLAN", "")  # VLAN tag (optional)
EXT_GW_IP = os.environ.get("EXT_GW_IP", "")  # Gateway VM external IP (e.g. 192.168.1.100/24)
EXT_GW_GATEWAY = os.environ.get("EXT_GW_GATEWAY", "")  # External gateway (e.g. 192.168.1.1)

VMID_GW = int(os.environ.get("VMID_GW", "100"))
VMID_FORCAD = int(os.environ.get("VMID_FORCAD", "110"))
VMID_TEAM_BASE = int(os.environ.get("VMID_TEAM_BASE", "200"))

# Root passwords for participants (team VMs)
ALLOW_ROOT_SSH = os.environ.get("ALLOW_ROOT_SSH", "1") == "1"

# Resources (tune as needed)
TEAM_CORES = int(os.environ.get("TEAM_CORES", "2"))
TEAM_RAM_MB = int(os.environ.get("TEAM_RAM_MB", "4096"))

FORCAD_CORES = int(os.environ.get("FORCAD_CORES", "2"))
FORCAD_RAM_MB = int(os.environ.get("FORCAD_RAM_MB", "4096"))

GW_CORES = int(os.environ.get("GW_CORES", "2"))
GW_RAM_MB = int(os.environ.get("GW_RAM_MB", "1024"))

# IP plan (all on 10.0.0.0/8 network)
GW_CTF_IP = os.environ.get("GW_CTF_IP", "10.10.10.1/8")  # Gateway internal CTF IP
GW_CTF_ADDR = GW_CTF_IP.split("/")[0]
FORCAD_IP = os.environ.get("FORCAD_IP", "10.10.10.10/8")
FORCAD_GW = os.environ.get("FORCAD_GW", GW_CTF_ADDR)

# WireGuard + FRP (only WG UDP port forward)
WG_PORT = int(os.environ.get("WG_PORT", "51820"))
WG_ENDPOINT = os.environ.get("WG_ENDPOINT", "")       # PUBLIC_VPS_IP:51820

FRP_ENABLED = os.environ.get("FRP_ENABLED", "1") == "1"
FRP_SERVER = os.environ.get("FRP_SERVER", "") if FRP_ENABLED else ""
FRP_PORT = int(os.environ.get("FRP_PORT", "7000"))
FRP_VER = os.environ.get("FRP_VER", "0.52.3")

# Resource pool
POOL_ID = os.environ.get("POOL_ID", "ctf")
CLONE_FULL = os.environ.get("CLONE_FULL", "0") == "1"

# MAC addresses
MAC_GW_NET0 = os.environ.get("MAC_GW_NET0", "02:00:00:02:BC:00")
MAC_GW_NET1 = os.environ.get("MAC_GW_NET1", "02:00:00:02:BC:01")
MAC_FORCAD_NET0 = os.environ.get("MAC_FORCAD_NET0", "02:00:00:02:C6:00")
MAC_TEAM_BASE = os.environ.get("MAC_TEAM_BASE", "02:00:00:02:D0")



def hdr():
    return {"Authorization": f"PVEAPIToken={TOKEN_ID}={TOKEN_SECRET}"}


def api_url(path: str) -> str:
    return urljoin(PVE_HOST.rstrip("/") + "/", f"api2/json/{path.lstrip('/')}")


def api_get(path: str, params=None):
    r = requests.get(api_url(path), headers=hdr(), params=params, verify=VERIFY_TLS, timeout=60)
    r.raise_for_status()
    return r.json()["data"]


def api_post(path: str, data=None, timeout=600):
    r = requests.post(api_url(path), headers=hdr(), data=data, verify=VERIFY_TLS, timeout=timeout)
    if not r.ok:
        print("\n--- Proxmox API error ---")
        print("URL:", r.url)
        print("STATUS:", r.status_code)
        print("SENT DATA:", data)
        print("RESPONSE TEXT:", r.text)
        print("------------------------\n")
    r.raise_for_status()
    return r.json()["data"]


def api_put(path: str, data=None, timeout=600):
    r = requests.put(api_url(path), headers=hdr(), data=data, verify=VERIFY_TLS, timeout=timeout)
    if not r.ok:
        print("\n--- Proxmox API error ---")
        print("URL:", r.url)
        print("STATUS:", r.status_code)
        print("SENT DATA:", data)
        print("RESPONSE TEXT:", r.text)
        print("------------------------\n")
    r.raise_for_status()
    return r.json().get("data")



def wait_task(upid: str, poll=2):
    while True:
        st = api_get(f"nodes/{PVE_NODE}/tasks/{upid}/status")
        if st.get("status") == "stopped":
            if st.get("exitstatus") != "OK":
                log = api_get(f"nodes/{PVE_NODE}/tasks/{upid}/log")
                raise RuntimeError(f"Task failed: {upid}\nExit: {st.get('exitstatus')}\nLog tail: {log[-10:]}")
            return
        time.sleep(poll)


def vm_exists(vmid: int) -> bool:
    # Robust: Proxmox can return 500 for missing VM config files.
    vms = api_get(f"nodes/{PVE_NODE}/qemu")
    return any(int(v.get("vmid")) == int(vmid) for v in vms)

def api_delete(path: str, params=None, timeout=600):
    r = requests.delete(api_url(path), headers=hdr(), params=params, verify=VERIFY_TLS, timeout=timeout)
    r.raise_for_status()
    return r.json()["data"]

def destroy_vm_if_exists(vmid: int):
    if not vm_exists(vmid):
        return
    print(f"[→] Destroying existing VM {vmid}...")
    try:
        upid = api_post(f"nodes/{PVE_NODE}/qemu/{vmid}/status/stop", timeout=120)
        wait_task(upid)
        print(f"[✓] VM {vmid} stopped")
    except Exception:
        pass

    upid = api_delete(f"nodes/{PVE_NODE}/qemu/{vmid}", params={"purge": 1}, timeout=600)
    wait_task(upid)
    print(f"[✓] VM {vmid} destroyed")

def clone_vm(new_vmid: int, name: str):
    clone_type = "full" if CLONE_FULL else "link"
    print(f"[→] Cloning VM {new_vmid} ({name}) from template {TEMPLATE_VMID} ({clone_type})...")
    clone_data = {
        "newid": new_vmid,
        "name": name,
        "full": 1 if CLONE_FULL else 0,
        "pool": POOL_ID
    }
    upid = api_post(
        f"nodes/{PVE_NODE}/qemu/{TEMPLATE_VMID}/clone",
        data=clone_data,
        timeout=1200
    )
    wait_task(upid)
    print(f"[✓] VM {new_vmid} ({name}) cloned ({clone_type})")


def set_vm_config(vmid: int, **kwargs):
    print(f"[→] Configuring VM {vmid}...")
    upid = api_post(f"nodes/{PVE_NODE}/qemu/{vmid}/config", data=kwargs, timeout=600)
    wait_task(upid)
    print(f"[✓] VM {vmid} configured")


def start_vm(vmid: int):
    print(f"[→] Starting VM {vmid}...")
    upid = api_post(f"nodes/{PVE_NODE}/qemu/{vmid}/status/start", timeout=120)
    wait_task(upid)
    print(f"[✓] VM {vmid} started")


def ensure_pool(pool_id: str):
    try:
        api_get(f"pools/{pool_id}")
        return
    except Exception:
        pass
    try:
        api_post("pools", data={"poolid": pool_id})
        print(f"[✓] Created pool {pool_id}")
    except Exception:
        # Pool might already exist or user lacks permission; continue.
        print(f"[!] Could not create pool {pool_id}; will try to add VMs anyway")


def add_vm_to_pool(vmid: int, pool_id: str):
    print(f"[→] Adding VM {vmid} to pool {pool_id}...")
    api_put(f"pools/{pool_id}", data={"vms": str(vmid)})
    print(f"[✓] VM {vmid} added to pool {pool_id}")


def random_password(length: int = 24) -> str:
    # Use ONLY alphanumeric characters for maximum compatibility with serial console
    # Longer length (24) compensates for reduced character set
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_mac_address(vmid: int, interface: int = 0) -> str:
    """
    Generate a static MAC address for a team VM interface.
    Uses MAC_TEAM_BASE from environment and adds team number as last byte.
    For non-team VMs, use the specific MAC_ environment variables.
    """
    if vmid == VMID_GW:
        return MAC_GW_NET0 if interface == 0 else MAC_GW_NET1
    elif vmid == VMID_FORCAD:
        return MAC_FORCAD_NET0
    else:
        # Team VM - calculate offset from base
        team_num = vmid - VMID_TEAM_BASE
        # Parse MAC_TEAM_BASE and add team number to last byte
        base_parts = MAC_TEAM_BASE.split(':')
        last_byte = int(base_parts[-1], 16) + team_num
        mac_parts = base_parts[:-1] + [f"{last_byte:02x}"]
        return ":".join(mac_parts)


# ---------------- cloud-init content builders ----------------

def gw_network_config() -> str:
    dns_block = ", ".join(DNS_SERVERS) if DNS_SERVERS else "1.1.1.1"

    if EXT_GW_IP and EXT_GW_GATEWAY:
        ens19_block = f"""
  ens19:
    addresses: [{EXT_GW_IP}]
    routes:
      - to: default
        via: {EXT_GW_GATEWAY}
    nameservers:
      addresses: [{dns_block}]"""
    else:
        ens19_block = """
  ens19:
    dhcp4: false"""

    return f"""version: 2
ethernets:
  ens18:
    addresses: [{GW_CTF_IP}]
    nameservers:
      addresses: [{dns_block}]{ens19_block}
""".rstrip()


def gw_user_data(n_teams: int, root_pw: str) -> str:
    """
    Cloud-init user-data for the Gateway VM.
    
    Network layout:
    - eth0: CTF internal network (10.0.0.0/8) - all VMs on same flat network
    - eth1: External network (optional, for internet access via EXT_BRIDGE)
    """
    dns_block = ", ".join(DNS_SERVERS) if DNS_SERVERS else "1.1.1.1"
    dns_lines = "\n".join(f"      nameserver {dns}" for dns in DNS_SERVERS) or "      nameserver 1.1.1.1"
    resolvectl_dns = " ".join(DNS_SERVERS) if DNS_SERVERS else "1.1.1.1"
    
    # Build eth1 (external) config if provided
    eth1_config = ""
    ext_route_cmd = ""
    if EXT_GW_IP and EXT_GW_GATEWAY:
        ext_route_cmd = f"  - ip route replace default via {EXT_GW_GATEWAY} dev ens19"
    else:
        ext_route_cmd = f"  - ip route replace default via {ORG_HOST_ADDR} dev ens18"

    frp_files = ""
    frp_runcmd = ""
    if FRP_ENABLED:
        frp_files = f"""

  - path: /etc/frp/frpc.ini
    permissions: "0644"
    content: |
      [common]
      server_addr = {FRP_SERVER}
      server_port = {FRP_PORT}

      [wg]
      type = udp
      local_ip = 0.0.0.0
      local_port = {WG_PORT}
      remote_port = {WG_PORT}
"""
        frp_runcmd = f"""

  # FRP client install + service
  - sh -lc 'set -e; cd /tmp;
            curl -fsSL https://github.com/fatedier/frp/releases/download/v{FRP_VER}/frp_{FRP_VER}_linux_amd64.tar.gz -o frp.tgz;
            tar -xzf frp.tgz;
            install -m 0755 frp_{FRP_VER}_linux_amd64/frpc /usr/local/bin/frpc'
  - sh -lc 'cat > /etc/systemd/system/frpc.service <<EOF
            [Unit]
            Description=FRP Client
            After=network-online.target
            Wants=network-online.target

            [Service]
            ExecStart=/usr/local/bin/frpc -c /etc/frp/frpc.ini
            Restart=always
            RestartSec=2

            [Install]
            WantedBy=multi-user.target
            EOF'
  - systemctl daemon-reload
  - systemctl enable --now frpc
"""

    return f"""#cloud-config
hostname: ctf-gw
manage_etc_hosts: true

users:
  - name: root
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: {root_pw}
  - name: user
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: user

ssh_pwauth: true
disable_root: false

package_update: true
package_upgrade: false
packages:
  - nftables
  - wireguard
  - wireguard-tools
  - iproute2
  - curl
  - zip

write_files:
  - path: /root/zip-wg-configs.sh
    permissions: "0755"
    content: |
      #!/bin/bash
      set -euo pipefail
      mkdir -p /root
      if ls /srv/wg-configs/admin-*.conf >/dev/null 2>&1; then
        zip -j /root/admin.zip /srv/wg-configs/admin-*.conf
      fi
      for TEAM in $(seq 1 {n_teams}); do
        if ls /srv/wg-configs/team${{TEAM}}-player*.conf >/dev/null 2>&1; then
          zip -j /root/team${{TEAM}}.zip /srv/wg-configs/team${{TEAM}}-player*.conf
        fi
      done
  - path: /etc/ssh/sshd_config
    permissions: "0644"
    content: |
      Port 22
      Protocol 2
      HostKey /etc/ssh/ssh_host_rsa_key
      HostKey /etc/ssh/ssh_host_ecdsa_key
      HostKey /etc/ssh/ssh_host_ed25519_key
      PermitRootLogin yes
      PasswordAuthentication yes
      PubkeyAuthentication yes
      KbdInteractiveAuthentication yes
      ChallengeResponseAuthentication no
      UsePAM yes
      AllowTcpForwarding yes
      X11Forwarding no
      PrintMotd no
      AcceptEnv LANG LC_*
      Subsystem sftp /usr/lib/openssh/sftp-server

  - path: /etc/resolv.conf
    permissions: "0644"
    content: |
{dns_lines}

  - path: /etc/sysctl.d/99-ipforward.conf
    permissions: "0644"
    content: |
      net.ipv4.ip_forward=1

  - path: /etc/nftables.conf
    permissions: "0644"
    content: |
      flush ruleset
      table inet filter {{
        chain forward {{
          type filter hook forward priority 0;
          policy drop;

          ct state established,related accept

          # All CTF traffic on 10.0.0.0/8 allowed to each other
          ip saddr 10.0.0.0/8 ip daddr 10.0.0.0/8 accept

          # Outbound to internet from CTF network
          ip saddr 10.0.0.0/8 ip daddr != 10.0.0.0/8 accept
        }}
      }}
      table inet nat {{
        chain postrouting {{
          type nat hook postrouting priority srcnat;
          # NAT for external interface (if configured)
          oifname "ens19" ip saddr 10.0.0.0/8 masquerade
        }}
      }}

{frp_files}

  - path: /root/generate-wg-configs.sh
    permissions: "0755"
    content: |
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

      # Write server config
      cat > wg0.conf <<EOF
      [Interface]
      Address = 10.10.10.1/8
      ListenPort = {WG_PORT}
      PrivateKey = $SERVER_PRIV
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
      Endpoint = {WG_ENDPOINT}
      AllowedIPs = 10.0.0.0/8
      PersistentKeepalive = 25
      EOF
      done

      # Team configs: 11 per team (10.60.<team>.3-13)
      for TEAM in $(seq 1 {n_teams}); do
        for IP_LAST in $(seq 3 13); do
          NAME="team${{TEAM}}-player${{IP_LAST}}"
          wg genkey | tee "/srv/wg-configs/$NAME.key" | wg pubkey > "/srv/wg-configs/$NAME.pub"
          PEER_PUB="$(cat "/srv/wg-configs/$NAME.pub")"
          PEER_PRIV="$(cat "/srv/wg-configs/$NAME.key")"

          cat >> wg0.conf <<EOF

      [Peer]
      PublicKey = $PEER_PUB
      AllowedIPs = 10.60.$TEAM.$IP_LAST/32
      EOF

          cat > "/srv/wg-configs/$NAME.conf" <<EOF
      [Interface]
      Address = 10.60.$TEAM.$IP_LAST/32
      PrivateKey = $PEER_PRIV

      [Peer]
      PublicKey = $SERVER_PUB
      Endpoint = {WG_ENDPOINT}
      AllowedIPs = 10.0.0.0/8
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

runcmd:
  - systemctl daemon-reload
  - sysctl --system
  - netplan apply
{ext_route_cmd}
  - resolvectl dns ens18 {resolvectl_dns} || true
  - systemctl disable --now systemd-resolved tailscaled 2>/dev/null || true
  - rm -f /etc/ssh/sshd_config.d/50-cloud-init.conf /etc/ssh/sshd_config.d/60-cloud-init.conf || true
  - systemctl daemon-reload
  - systemctl restart serial-getty@ttyS0.service
  - systemctl restart ssh || systemctl restart sshd || true
  - systemctl enable --now nftables
  - nft -f /etc/nftables.conf

  # WireGuard: install, generate configs then start wg0
  - apt update
  - apt install -y wireguard
  - mkdir -p /etc/wireguard
  - /root/generate-wg-configs.sh
  - systemctl enable --now wg-quick@wg0
  - /root/zip-wg-configs.sh
{frp_runcmd}
""".rstrip()


def forcad_user_data(root_pw: str, config_yaml: str) -> str:
    dns_lines = "\n".join(f"      nameserver {dns}" for dns in DNS_SERVERS) or "      nameserver 1.1.1.1"
    return f"""#cloud-config
users:
  - name: root
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: {root_pw}

ssh_pwauth: true
disable_root: false

package_update: true
package_upgrade: false
packages:
  - git
  - python3
  - python3-pip
  - python3-venv
  - python3-full
  - curl
  - ca-certificates
  - unzip

write_files:
  - path: /root/forcad-config.yml
    permissions: "0600"
    content: |
{indent_block(config_yaml.rstrip(), 6)}
  - path: /etc/netplan/01-forcad.yaml
    permissions: "0600"
    content: |
      network:
        version: 2
        ethernets:
          ens18:
            addresses: [{FORCAD_IP}]
            gateway4: {FORCAD_GW}
            nameservers:
              addresses: [{', '.join(DNS_SERVERS) if DNS_SERVERS else '1.1.1.1'}]
  - path: /etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf
    content: |
      [Service]
      ExecStart=
      ExecStart=-/sbin/agetty --autologin root --noclear %I $TERM
  - path: /etc/ssh/sshd_config.d/99-ctf-forcad.conf
    permissions: "0644"
    content: |
      PasswordAuthentication yes
      PermitRootLogin yes
      SyslogFacility AUTHPRIV
      LogLevel VERBOSE
  - path: /etc/resolv.conf
    permissions: "0644"
    content: |
{dns_lines}

runcmd:
  - systemctl daemon-reload
  - netplan apply
  - systemctl restart serial-getty@ttyS0.service
  - sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
  - sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
  - systemctl restart sshd
  - apt-get update
  - apt-get install -y python3-pip python3-venv python3-full unzip
  - curl -fsSL https://get.docker.com | sh
  - systemctl enable --now docker
  - cd /root && git clone https://github.com/pomo-mondreganto/ForcAD.git && cd ForcAD && git checkout master
  - cd /root/ForcAD && pip3 install --break-system-packages -r cli/requirements.txt
  - cd /root/ForcAD && python3 ./control.py setup
  - cd /root/ForcAD && python3 ./control.py start --fast
  - mkdir -p /root/ForcAD/checkers
  - mkdir -p /mnt/cidata
  - CIDATA_DEV=$(blkid -L cidata 2>/dev/null || true)
  - if [ -z "$CIDATA_DEV" ] && [ -e /dev/disk/by-label/cidata ]; then CIDATA_DEV=/dev/disk/by-label/cidata; fi
  - if [ -z "$CIDATA_DEV" ] && [ -e /dev/sr0 ]; then CIDATA_DEV=/dev/sr0; fi
  - if [ -z "$CIDATA_DEV" ] && [ -e /dev/cdrom ]; then CIDATA_DEV=/dev/cdrom; fi
  - if [ -n "$CIDATA_DEV" ]; then mount -o ro "$CIDATA_DEV" /mnt/cidata || true; fi
  - if [ -f /mnt/cidata/forcad-checkers.zip ]; then cp /mnt/cidata/forcad-checkers.zip /root/forcad-checkers.zip; fi
  - if [ -f /root/forcad-checkers.zip ]; then unzip -o /root/forcad-checkers.zip -d /root/ForcAD/checkers || true; fi
  - if [ -d /root/ForcAD/checkers/checkers ]; then mv /root/ForcAD/checkers/checkers/* /root/ForcAD/checkers/; rmdir /root/ForcAD/checkers/checkers || true; fi
  - umount /mnt/cidata 2>/dev/null || true
  - mv /root/forcad-config.yml /root/ForcAD/config.yml
""".rstrip()


def team_user_data(root_pw: str, allow_root_ssh: bool, team_ip: str, gateway_ip: str) -> str:
    ssh_pwauth = "true" if allow_root_ssh else "false"
    dns_lines = "\n".join(f"      nameserver {dns}" for dns in DNS_SERVERS) or "      nameserver 1.1.1.1"
    extra_write = ""
    extra_runcmd = ""
    if allow_root_ssh:
        extra_write = """
  - path: /etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf
    content: |
      [Service]
      ExecStart=
      ExecStart=-/sbin/agetty --autologin root --noclear %I $TERM
  - path: /etc/ssh/sshd_config.d/50-cloud-init.conf
    content: |
      PasswordAuthentication yes
      PermitRootLogin yes
      PubkeyAuthentication yes
"""
        extra_runcmd = """
  - systemctl daemon-reload
  - systemctl restart serial-getty@ttyS0.service
  - systemctl restart sshd
"""
    return f"""#cloud-config
users:
  - name: root
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: {root_pw}

ssh_pwauth: {ssh_pwauth}
disable_root: false

network:
  config: disabled

package_update: true
package_upgrade: false
packages:
  - curl
  - ca-certificates

write_files:
  - path: /etc/netplan/01-team.yaml
    permissions: "0600"
    content: |
      network:
        version: 2
        ethernets:
          ens18:
            addresses: [{team_ip}]
            gateway4: {gateway_ip}
            nameservers:
              addresses: [{', '.join(DNS_SERVERS) if DNS_SERVERS else '1.1.1.1'}]
  - path: /etc/resolv.conf
    permissions: "0644"
    content: |
{dns_lines}{extra_write}

runcmd:
  - netplan apply
  - curl -fsSL https://get.docker.com | sh
  - systemctl enable --now docker
  - mkdir -p /mnt/cidata
  - CIDATA_DEV=$(blkid -L cidata 2>/dev/null || true)
  - if [ -z "$CIDATA_DEV" ] && [ -e /dev/disk/by-label/cidata ]; then CIDATA_DEV=/dev/disk/by-label/cidata; fi
  - if [ -z "$CIDATA_DEV" ] && [ -e /dev/sr0 ]; then CIDATA_DEV=/dev/sr0; fi
  - if [ -z "$CIDATA_DEV" ] && [ -e /dev/cdrom ]; then CIDATA_DEV=/dev/cdrom; fi
  - if [ -n "$CIDATA_DEV" ]; then mount -o ro "$CIDATA_DEV" /mnt/cidata || true; fi
  - if [ -f /mnt/cidata/services.zip ]; then cp /mnt/cidata/services.zip /root/services.zip; fi
  - umount /mnt/cidata 2>/dev/null || true{extra_runcmd}""".rstrip()


def indent_block(text: str, spaces: int) -> str:
    pad = " " * spaces
    return "\n".join(pad + line if line else pad for line in text.splitlines())


def zip_dir_to_file(dir_path: str, out_path: str) -> None:
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(dir_path):
            for name in files:
                full_path = os.path.join(root, name)
                rel_path = os.path.relpath(full_path, dir_path)
                zf.write(full_path, rel_path)


def build_forcad_config(base_config: str, n_teams: int) -> str:
    if "\nteams:" in base_config or base_config.strip().startswith("teams:"):
        base_config = base_config.split("\nteams:", 1)[0].rstrip() + "\n"

    lines = [base_config.rstrip(), "", "teams:"]
    for team in range(1, n_teams + 1):
        lines.append(f"  - ip: 10.60.{team}.2")
        lines.append(f"    name: \"Team {team}\"")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_local(path: str, content: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def create_cloud_init_iso(user_data: str, vm_name: str, output_dir: str, extra_files=None, network_config: str = None) -> str:
    """Create a NoCloud cloud-init ISO image."""
    iso_name = f"{vm_name}-cloud-init.iso"
    iso_path = os.path.join(output_dir, iso_name)
    
    # Create temp directory for cloud-init files
    with tempfile.TemporaryDirectory() as tmpdir:
        # Write user-data
        user_data_path = os.path.join(tmpdir, "user-data")
        with open(user_data_path, "w", encoding="utf-8") as f:
            f.write(user_data)
        
        # Write minimal meta-data
        meta_data_path = os.path.join(tmpdir, "meta-data")
        with open(meta_data_path, "w", encoding="utf-8") as f:
            f.write(f"instance-id: {vm_name}\nlocal-hostname: {vm_name}\n")

        network_config_path = None
        if network_config:
          network_config_path = os.path.join(tmpdir, "network-config")
          with open(network_config_path, "w", encoding="utf-8") as f:
            f.write(network_config)

        if extra_files:
            for src_path, dest_name in extra_files:
                shutil.copyfile(src_path, os.path.join(tmpdir, dest_name))
        
        # Create ISO using genisoimage or mkisofs
        cmd = None
        for tool in ["genisoimage", "mkisofs"]:
            if shutil.which(tool):
                cmd = [
                    tool,
                    "-output", iso_path,
                    "-volid", "cidata",
                    "-joliet",
                    "-rock",
                    user_data_path,
                    meta_data_path
                ]
                if network_config_path:
                    cmd.append(network_config_path)
                if extra_files:
                  for _, dest_name in extra_files:
                    cmd.append(os.path.join(tmpdir, dest_name))
                break
        
        if not cmd:
            raise RuntimeError("Neither genisoimage nor mkisofs found. Install: apt-get install genisoimage")
        
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    return iso_path


def get_proxmox_connection():
    """Create and return a proxmoxer ProxmoxAPI connection."""
    user, tokenid = TOKEN_ID.rsplit("!", 1)
    return ProxmoxAPI(
        PVE_HOST_CLEAN,
        user=user,
        token_name=tokenid,
        token_value=TOKEN_SECRET,
        verify_ssl=VERIFY_TLS,
        port=PVE_PORT,
        timeout=300
    )


def upload_iso(file_path: str, storage: str = None, retries: int = 3) -> bool:
    """Upload an ISO file to Proxmox storage via API using proxmoxer."""
    if storage is None:
        storage = ISO_STORAGE
    
    filename = os.path.basename(file_path)
    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
    
    for attempt in range(retries):
        try:
            if attempt > 0:
                print(f" (retry {attempt}/{retries-1})...", end=" ", flush=True)
            
            proxmox = get_proxmox_connection()
            
            with open(file_path, 'rb') as f:
                proxmox.nodes(PVE_NODE).storage(storage).upload.post(
                    content='iso',
                    filename=f
                )
            
            return True
        except Exception as e:
            error_msg = f"{type(e).__name__}: {e}"
            if attempt < retries - 1:
                print(f"\n[!] Upload failed (attempt {attempt + 1}): {error_msg}")
                print(f"[→] Retrying {filename}...", end=" ", flush=True)
                time.sleep(2)
            else:
                print(f"[!] Upload error for {filename} after {retries} attempts: {error_msg}")
                return False
    
    return False


def main():
    print("="*60)
    print("CTF Lab Setup Script")
    print("="*60)
    print(f"\n[*] Configuration:")
    print(f"    Teams: {N_TEAMS}")
    print(f"    Proxmox: {PVE_HOST} (node: {PVE_NODE})")
    print(f"    CTF Bridge: {BR_CTF} (10.0.0.0/8)")
    if EXT_BRIDGE and EXT_GW_IP:
        print(f"    External Bridge: {EXT_BRIDGE} (VLAN: {EXT_VLAN or 'none'}, IP: {EXT_GW_IP})")
    print(f"    VMIDs: GW={VMID_GW}, ForcAD={VMID_FORCAD}, Teams={VMID_TEAM_BASE}+")
    
    print("\n[*] Cloud-init will be created as ISO images")
    print(f"    - ISO storage: {ISO_STORAGE}")
    print(f"    - CTF bridge: {BR_CTF}")
    print(f"    - Host NAT configured for {CTF_NET_CIDR} (if required)")
    
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    creds_path = f"creds_{ts}.json"
    print(f"\n[*] Timestamp: {ts}")

    # Ensure pool exists before creating VMs
    ensure_pool(POOL_ID)

    # Create local temp directory for ISOs
    tmpdir = os.path.abspath(f"./cloud-init_{ts}")
    os.makedirs(tmpdir, exist_ok=True)
    print(f"[✓] Local cloud-init directory: {tmpdir}")

    # Prepare payloads for cloud-init
    data_dir = os.path.abspath("./data")
    payload_dir = os.path.join(tmpdir, "payloads")
    os.makedirs(payload_dir, exist_ok=True)
    forcad_checkers_zip = os.path.join(payload_dir, "forcad-checkers.zip")
    services_zip = os.path.join(payload_dir, "services.zip")
    zip_dir_to_file(os.path.join(data_dir, "checkers"), forcad_checkers_zip)
    zip_dir_to_file(os.path.join(data_dir, "services"), services_zip)
    with open(os.path.join(data_dir, "config.yaml"), "r", encoding="utf-8") as f:
      base_config = f.read()
    forcad_config = build_forcad_config(base_config, N_TEAMS)

    # Generate team passwords + files
    print(f"\n[*] Generating cloud-init configs for {N_TEAMS} teams...")
    
    # Generate passwords for infrastructure VMs
    gw_password = random_password(20)
    forcad_password = random_password(20)
    
    creds = {
        "generated_at_utc": ts,
        "n_teams": N_TEAMS,
        "allow_root_ssh_password": ALLOW_ROOT_SSH,
        "gateway": {
            "vm_name": "ctf-gw",
            "vmid": VMID_GW,
            "ctf_ip": GW_CTF_IP,
            "ext_ip": EXT_GW_IP or "none",
            "root_password": gw_password
        },
        "forcad": {
            "vm_name": "forcad",
            "vmid": VMID_FORCAD,
            "ip": FORCAD_IP,
            "root_password": forcad_password
        },
        "teams": []
    }

    creds["teams"] = []
    
    # Create cloud-init ISOs
    print(f"\n[*] Creating cloud-init ISO images...")
    
    gw_iso = create_cloud_init_iso(
      gw_user_data(N_TEAMS, gw_password),
      "ctf-gw",
      tmpdir,
      network_config=gw_network_config()
    )
    print(f"[✓] Created gateway ISO: {os.path.basename(gw_iso)}")
    
    fc_iso = create_cloud_init_iso(
      forcad_user_data(forcad_password, forcad_config),
      "forcad",
      tmpdir,
      extra_files=[(forcad_checkers_zip, "forcad-checkers.zip")]
    )
    print(f"[✓] Created ForcAD ISO: {os.path.basename(fc_iso)}")
    
    team_isos = {}
    for team in range(1, N_TEAMS + 1):
        pw = random_password(20)
        team_ip = f"10.60.{team}.2/8"
        team_iso = create_cloud_init_iso(
          team_user_data(pw, ALLOW_ROOT_SSH, team_ip, GW_CTF_ADDR),
          f"team-{team}",
          tmpdir,
          extra_files=[(services_zip, "services.zip")]
        )
        team_isos[team] = team_iso
        print(f"[✓] Created team {team} ISO: {os.path.basename(team_iso)}")
        
        creds["teams"].append({
            "team": team,
            "vm_name": f"team-{team}",
            "vmid": VMID_TEAM_BASE + team,
            "ip": team_ip,
            "gateway": GW_CTF_ADDR,
            "root_password": pw
        })

    # Upload ISOs to Proxmox
    print(f"\n[*] Uploading cloud-init ISOs to Proxmox storage '{ISO_STORAGE}'...")
    all_iso_files = [gw_iso, fc_iso] + list(team_isos.values())
    
    upload_failed = False
    for iso_file in all_iso_files:
        filename = os.path.basename(iso_file)
        print(f"[→] Uploading {filename}...", end=" ")
        if upload_iso(iso_file):
            print("✓")
        else:
            print("✗")
            upload_failed = True
    
    if upload_failed:
        print(f"\n[!] Some ISOs failed to upload. Check permissions:")
        print(f"    - Storage '{ISO_STORAGE}' must have 'ISO image' content type enabled")
        print(f"    - API token needs Datastore.AllocateSpace permission on /storage/{ISO_STORAGE}")
        print(f"\n[*] You can manually upload from: {tmpdir}")
        return
    
    print(f"[✓] All ISOs uploaded to Proxmox")

    # Write creds JSON locally
    with open(creds_path, "w", encoding="utf-8") as f:
        json.dump(creds, f, ensure_ascii=False, indent=2)
    os.chmod(creds_path, 0o600)

    print(f"\n[✓] Snippet files ready in {tmpdir}")
    print(f"[✓] Credentials written to {creds_path}")

    # Destroy old VMs if exist
    print(f"\n[*] Cleaning up existing VMs...")
    all_vmids = [VMID_GW, VMID_FORCAD] + [VMID_TEAM_BASE + i for i in range(1, N_TEAMS + 1)]
    for vmid in all_vmids:
        destroy_vm_if_exists(vmid)
    print(f"[✓] Cleanup complete")

    # Create GW
    print(f"\n[*] Creating Gateway VM (VMID {VMID_GW})...")
    clone_vm(VMID_GW, "ctf-gw")
    
    # Build net1 config for external network
    net1_config = f"virtio,bridge={EXT_BRIDGE}"
    if EXT_VLAN:
        net1_config += f",tag={EXT_VLAN}"
    
    # Build ipconfig1 for external interface
    ipconfig1 = ""
    if EXT_GW_IP:
        ipconfig1 = f"ip={EXT_GW_IP}"
        if EXT_GW_GATEWAY:
            ipconfig1 += f",gw={EXT_GW_GATEWAY}"
    
    gw_config = {
        "cores": GW_CORES,
        "memory": GW_RAM_MB,
        "net0": f"virtio,bridge={BR_CTF},macaddr={generate_mac_address(VMID_GW, 0)}",
        "net1": f"{net1_config},macaddr={generate_mac_address(VMID_GW, 1)}",
        "ipconfig0": f"ip={GW_CTF_IP}",
        "ide2": f"{ISO_STORAGE}:iso/{os.path.basename(gw_iso)},media=cdrom",
        "agent": "enabled=1",
        "serial0": "socket"
    }
    if ipconfig1:
        gw_config["ipconfig1"] = ipconfig1
    
    set_vm_config(VMID_GW, **gw_config)
    
    # Verify VM config
    print(f"[*] Verifying gateway VM config...")
    vm_config = api_get(f"nodes/{PVE_NODE}/qemu/{VMID_GW}/config")
    print(f"    ide2 (cloud-init): {vm_config.get('ide2', 'NOT SET')}")

    # Create ForcAD
    print(f"\n[*] Creating ForcAD VM (VMID {VMID_FORCAD})...")
    clone_vm(VMID_FORCAD, "forcad")
    set_vm_config(
        VMID_FORCAD,
        cores=FORCAD_CORES, memory=FORCAD_RAM_MB,
        net0=f"virtio,bridge={BR_CTF},macaddr={generate_mac_address(VMID_FORCAD, 0)}",
        ipconfig0=f"ip={FORCAD_IP},gw={FORCAD_GW}",
        ide2=f"{ISO_STORAGE}:iso/{os.path.basename(fc_iso)},media=cdrom",
        agent="enabled=1"
    )

    # Create Teams
    print(f"\n[*] Creating {N_TEAMS} Team VMs...")
    for team in range(1, N_TEAMS + 1):
        vmid = VMID_TEAM_BASE + team
        team_pw = creds["teams"][team - 1]["root_password"]
        print(f"\n[*] Creating Team {team} VM (VMID {vmid})...")
        clone_vm(vmid, f"team-{team}")
        set_vm_config(
            vmid,
            cores=TEAM_CORES, memory=TEAM_RAM_MB,
            net0=f"virtio,bridge={BR_CTF},macaddr={generate_mac_address(vmid, 0)}",
            ipconfig0=f"ip=10.60.{team}.2/8,gw={GW_CTF_ADDR}",
            ide2=f"{ISO_STORAGE}:iso/{os.path.basename(team_isos[team])},media=cdrom",
            agent="enabled=1"
        )

    # Start all
    print(f"\n[*] Starting all VMs...")
    start_vm(VMID_GW)
    start_vm(VMID_FORCAD)
    for team in range(1, N_TEAMS + 1):
        start_vm(VMID_TEAM_BASE + team)

    print("\n" + "="*60)
    print("[+] Setup Complete!")
    print("="*60)
    print(f"    Credentials: {creds_path}")
    print(f"    WireGuard configs: NOT DOWNLOADED")
    print(f"      Check on gateway: /var/log/wg-config-gen.log")
    print(f"      Configs will be in: /srv/wg-configs/")
    print("    FRP client on GW forwards only UDP WireGuard port.")


if __name__ == "__main__":
    main()
