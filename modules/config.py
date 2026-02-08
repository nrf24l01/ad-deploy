"""Centralised configuration — all values loaded from environment once."""
import os
from dotenv import load_dotenv

load_dotenv()

# ===================== Proxmox API =====================
PVE_HOST: str = os.environ["PVE_HOST"]
PVE_PORT: int = int(os.environ.get("PVE_PORT", "8006"))
PVE_HOST_CLEAN: str = PVE_HOST.replace("https://", "").replace("http://", "").split(":")[0]
PVE_NODE: str = os.environ.get("PVE_NODE", "pve")
TOKEN_ID: str = os.environ["PVE_TOKEN_ID"]
TOKEN_SECRET: str = os.environ["PVE_TOKEN_SECRET"]
VERIFY_TLS: bool = os.environ.get("VERIFY_TLS", "0") == "1"

TEMPLATE_VMID: int = int(os.environ.get("TEMPLATE_VMID", "9000"))

# Storage for cloud-init ISOs
ISO_STORAGE: str = os.environ.get("ISO_STORAGE", "local")
ISO_DIR: str = os.environ.get("ISO_DIR", "/var/lib/vz/template/iso")

# ===================== Lab config =====================
N_TEAMS: int = int(os.environ.get("N_TEAMS", "5"))
BR_CTF: str = os.environ.get("BR_CTF", "vmbr10")
DNS_SERVERS: list[str] = [
    s.strip()
    for s in os.environ.get("DNS_SERVERS", "1.1.1.1,8.8.8.8").split(",")
    if s.strip()
]

# External network on net1 (VLAN)
EXT_BRIDGE: str = os.environ.get("EXT_BRIDGE", "vmbr1")
EXT_VLAN: str = os.environ.get("EXT_VLAN", "")
EXT_GW_IP: str = os.environ.get("EXT_GW_IP", "")
EXT_GW_GATEWAY: str = os.environ.get("EXT_GW_GATEWAY", "")

# VM IDs
VMID_GW: int = int(os.environ.get("VMID_GW", "100"))
VMID_FORCAD: int = int(os.environ.get("VMID_FORCAD", "110"))
VMID_TEAM_BASE: int = int(os.environ.get("VMID_TEAM_BASE", "720"))

# Root passwords for participants (team VMs)
ALLOW_ROOT_SSH: bool = os.environ.get("ALLOW_ROOT_SSH", "1") == "1"

# Resources
TEAM_CORES: int = int(os.environ.get("TEAM_CORES", "2"))
TEAM_RAM_MB: int = int(os.environ.get("TEAM_RAM_MB", "4096"))
FORCAD_CORES: int = int(os.environ.get("FORCAD_CORES", "2"))
FORCAD_RAM_MB: int = int(os.environ.get("FORCAD_RAM_MB", "4096"))
GW_CORES: int = int(os.environ.get("GW_CORES", "2"))
GW_RAM_MB: int = int(os.environ.get("GW_RAM_MB", "1024"))

# IP plan — isolated /31 point-to-point links
FORCAD_IP: str = os.environ.get("FORCAD_IP", "10.10.10.10/31")
FORCAD_GW_SIDE: str = os.environ.get("FORCAD_GW_SIDE", "10.10.10.11/31")
FORCAD_GW: str = FORCAD_GW_SIDE.split("/")[0]
WG_GW_IP: str = os.environ.get("WG_GW_IP", "10.10.10.1")

# WireGuard + FRP
WG_PORT: int = int(os.environ.get("WG_PORT", "51820"))
WG_ENDPOINT: str = os.environ.get("WG_ENDPOINT", "")

FRP_ENABLED: bool = os.environ.get("FRP_ENABLED", "1") == "1"
FRP_SERVER: str = os.environ.get("FRP_SERVER", "") if FRP_ENABLED else ""
FRP_PORT: int = int(os.environ.get("FRP_PORT", "7000"))
FRP_VER: str = os.environ.get("FRP_VER", "0.52.3")

# Resource pool
POOL_ID: str = os.environ.get("POOL_ID", "ctf")
CLONE_FULL: bool = os.environ.get("CLONE_FULL", "0") == "1"

# MAC addresses
MAC_GW_NET0: str = os.environ.get("MAC_GW_NET0", "02:00:00:02:BC:00")
MAC_GW_NET1: str = os.environ.get("MAC_GW_NET1", "02:00:00:02:BC:01")
MAC_FORCAD_NET0: str = os.environ.get("MAC_FORCAD_NET0", "02:00:00:02:C6:00")
MAC_TEAM_BASE: str = os.environ.get("MAC_TEAM_BASE", "02:00:00:02:D0")
