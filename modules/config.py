"""Centralised configuration — all values loaded from deploy.yaml once."""
from __future__ import annotations

import os
from pathlib import Path

import yaml

_REPO_DIR = Path(__file__).resolve().parent.parent


def _find_config() -> Path:
    for candidate in (Path.cwd() / "deploy.yaml", _REPO_DIR / "deploy.yaml"):
        if candidate.is_file():
            return candidate
    return _REPO_DIR / "deploy.yaml"


_CONFIG_PATH = _find_config()


def _load_config() -> dict:
    if not _CONFIG_PATH.is_file():
        raise SystemExit(
            f"Configuration file not found: {_CONFIG_PATH}\n"
            "Copy deploy.example.yaml to deploy.yaml and fill in your values."
        )
    with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    return cfg


_cfg = _load_config()


def _req(section: str, key: str) -> str:
    value = _cfg.get(section, {}).get(key)
    if value is None:
        raise SystemExit(
            f"Missing required key '{section}.{key}' in {_CONFIG_PATH}"
        )
    return str(value)


# ===================== Proxmox API =====================
PVE_HOST: str = _req("proxmox", "host")
PVE_PORT: int = int(_cfg.get("proxmox", {}).get("port", 8006))
PVE_HOST_CLEAN: str = PVE_HOST.replace("https://", "").replace("http://", "").split(":")[0]
PVE_NODE: str = str(_cfg.get("proxmox", {}).get("node", "pve"))
TOKEN_ID: str = _req("proxmox", "token_id")
TOKEN_SECRET: str = _req("proxmox", "token_secret")
VERIFY_TLS: bool = bool(_cfg.get("proxmox", {}).get("verify_tls", False))

TEMPLATE_VMID: int = int(_cfg.get("template", {}).get("vmid", 9000))
CLONE_FULL: bool = bool(_cfg.get("template", {}).get("clone_full", False))

# Storage for cloud-init ISOs
ISO_STORAGE: str = str(_cfg.get("storage", {}).get("iso", "local"))
ISO_DIR: str = str(_cfg.get("storage", {}).get("iso_dir", "/var/lib/vz/template/iso"))

# ===================== Lab config =====================
N_TEAMS: int = int(_cfg.get("lab", {}).get("n_teams", 5))
BR_CTF: str = str(_cfg.get("network", {}).get("ctf_bridge", "vmbr10"))
DNS_SERVERS: list[str] = [str(s) for s in _cfg.get("network", {}).get("dns_servers", ["1.1.1.1", "8.8.8.8"])]

# External network on net1 (VLAN)
_ext = _cfg.get("network", {}).get("external", {})
EXT_BRIDGE: str = str(_ext.get("bridge", "vmbr1"))
EXT_VLAN: str = str(_ext.get("vlan", "") or "")
EXT_GW_IP: str = str(_ext.get("ip", "") or "")
EXT_GW_GATEWAY: str = str(_ext.get("gateway", "") or "")

# VM IDs
VMID_GW: int = int(_cfg.get("vmids", {}).get("gateway", 100))
VMID_FORCAD: int = int(_cfg.get("vmids", {}).get("forcad", 110))
VMID_TEAM_BASE: int = int(_cfg.get("vmids", {}).get("team_base", 720))

# Root passwords for participants (team VMs)
ALLOW_ROOT_SSH: bool = bool(_cfg.get("lab", {}).get("allow_root_ssh", True))

# Resources
_res = _cfg.get("resources", {})
TEAM_CORES: int = int(_res.get("team", {}).get("cores", 2))
TEAM_RAM_MB: int = int(_res.get("team", {}).get("ram_mb", 4096))
FORCAD_CORES: int = int(_res.get("forcad", {}).get("cores", 2))
FORCAD_RAM_MB: int = int(_res.get("forcad", {}).get("ram_mb", 4096))
GW_CORES: int = int(_res.get("gateway", {}).get("cores", 2))
GW_RAM_MB: int = int(_res.get("gateway", {}).get("ram_mb", 1024))

# IP plan — isolated /31 point-to-point links
_ip = _cfg.get("ip_plan", {})
FORCAD_IP: str = str(_ip.get("forcad_ip", "10.10.10.10/31"))
FORCAD_GW_SIDE: str = str(_ip.get("forcad_gw_side", "10.10.10.11/31"))
FORCAD_GW: str = FORCAD_GW_SIDE.split("/")[0]
WG_GW_IP: str = str(_ip.get("wg_gw_ip", "10.10.10.1"))

# WireGuard + FRP
WG_PORT: int = int(_cfg.get("wireguard", {}).get("port", 51820))
WG_ENDPOINT: str = str(_cfg.get("wireguard", {}).get("endpoint", "") or "")

# WireGuard config export (scp from gateway)
EXT_GW_HOST: str = EXT_GW_IP.split("/")[0] if EXT_GW_IP else ""
_scp = _cfg.get("wireguard", {}).get("scp", {})
WG_SCP_ENABLED: bool = bool(_scp.get("enabled", True))
WG_SCP_HOST: str = str(_scp.get("host", "") or "") or EXT_GW_HOST
WG_SCP_PORT: int = int(_scp.get("port", 22))
WG_SCP_USER: str = str(_scp.get("user", "root"))
WG_SCP_OUTPUT_DIR: str = str(_scp.get("output_dir", "wg-configs"))
WG_SCP_WAIT_TIMEOUT_SEC: int = int(_scp.get("wait_timeout_sec", 600))
WG_SCP_POLL_SEC: int = int(_scp.get("poll_interval_sec", 15))

_frp = _cfg.get("frp", {})
FRP_ENABLED: bool = bool(_frp.get("enabled", True))
FRP_SERVER: str = str(_frp.get("server", "") or "") if FRP_ENABLED else ""
FRP_PORT: int = int(_frp.get("port", 7000))
FRP_VER: str = str(_frp.get("ver", "0.52.3"))

# Resource pool
POOL_ID: str = str(_cfg.get("lab", {}).get("pool", "ctf"))

# MAC addresses
_mac = _cfg.get("mac", {})
MAC_GW_NET0: str = str(_mac.get("gw_net0", "02:00:00:02:BC:00"))
MAC_GW_NET1: str = str(_mac.get("gw_net1", "02:00:00:02:BC:01"))
MAC_FORCAD_NET0: str = str(_mac.get("forcad_net0", "02:00:00:02:C6:00"))
MAC_TEAM_BASE: str = str(_mac.get("team_base", "02:00:00:02:D0:00"))

for _name in ("MAC_GW_NET0", "MAC_GW_NET1", "MAC_FORCAD_NET0", "MAC_TEAM_BASE"):
    _val = globals()[_name]
    if len(_val.split(":")) != 6:
        raise SystemExit(f"Invalid {_name} in {_CONFIG_PATH}: {_val!r} (expected 6 octets)")
