"""Proxmox VE API helpers — REST + proxmoxer upload."""
from __future__ import annotations

import time
from urllib.parse import urljoin

import requests
import urllib3
from proxmoxer import ProxmoxAPI

from modules.config import (
    PVE_HOST, PVE_HOST_CLEAN, PVE_PORT, PVE_NODE,
    TOKEN_ID, TOKEN_SECRET, VERIFY_TLS,
    TEMPLATE_VMID, ISO_STORAGE, POOL_ID, CLONE_FULL,
    VMID_GW, VMID_FORCAD, VMID_TEAM_BASE,
    MAC_GW_NET0, MAC_GW_NET1, MAC_FORCAD_NET0, MAC_TEAM_BASE,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# --------------- low-level REST helpers ---------------

def _hdr() -> dict[str, str]:
    return {"Authorization": f"PVEAPIToken={TOKEN_ID}={TOKEN_SECRET}"}


def _api_url(path: str) -> str:
    return urljoin(PVE_HOST.rstrip("/") + "/", f"api2/json/{path.lstrip('/')}")


def api_get(path: str, params=None):
    r = requests.get(_api_url(path), headers=_hdr(), params=params,
                     verify=VERIFY_TLS, timeout=60)
    r.raise_for_status()
    return r.json()["data"]


def api_post(path: str, data=None, timeout: int = 600):
    r = requests.post(_api_url(path), headers=_hdr(), data=data,
                      verify=VERIFY_TLS, timeout=timeout)
    if not r.ok:
        print("\n--- Proxmox API error ---")
        print("URL:", r.url)
        print("STATUS:", r.status_code)
        print("SENT DATA:", data)
        print("RESPONSE TEXT:", r.text)
        print("------------------------\n")
    r.raise_for_status()
    return r.json()["data"]


def api_put(path: str, data=None, timeout: int = 600):
    r = requests.put(_api_url(path), headers=_hdr(), data=data,
                     verify=VERIFY_TLS, timeout=timeout)
    if not r.ok:
        print("\n--- Proxmox API error ---")
        print("URL:", r.url)
        print("STATUS:", r.status_code)
        print("SENT DATA:", data)
        print("RESPONSE TEXT:", r.text)
        print("------------------------\n")
    r.raise_for_status()
    return r.json().get("data")


def api_delete(path: str, params=None, timeout: int = 600):
    r = requests.delete(_api_url(path), headers=_hdr(), params=params,
                        verify=VERIFY_TLS, timeout=timeout)
    r.raise_for_status()
    return r.json()["data"]


# --------------- task helpers ---------------

def wait_task(upid: str, poll: int = 2) -> None:
    while True:
        st = api_get(f"nodes/{PVE_NODE}/tasks/{upid}/status")
        if st.get("status") == "stopped":
            if st.get("exitstatus") != "OK":
                log = api_get(f"nodes/{PVE_NODE}/tasks/{upid}/log")
                raise RuntimeError(
                    f"Task failed: {upid}\n"
                    f"Exit: {st.get('exitstatus')}\n"
                    f"Log tail: {log[-10:]}"
                )
            return
        time.sleep(poll)


# --------------- VM lifecycle ---------------

def vm_exists(vmid: int) -> bool:
    vms = api_get(f"nodes/{PVE_NODE}/qemu")
    return any(int(v.get("vmid")) == int(vmid) for v in vms)


def destroy_vm_if_exists(vmid: int) -> None:
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


def clone_vm(new_vmid: int, name: str) -> None:
    clone_type = "full" if CLONE_FULL else "link"
    print(f"[→] Cloning VM {new_vmid} ({name}) from template {TEMPLATE_VMID} ({clone_type})...")
    clone_data = {
        "newid": new_vmid,
        "name": name,
        "full": 1 if CLONE_FULL else 0,
        "pool": POOL_ID,
    }
    upid = api_post(
        f"nodes/{PVE_NODE}/qemu/{TEMPLATE_VMID}/clone",
        data=clone_data, timeout=1200,
    )
    wait_task(upid)
    print(f"[✓] VM {new_vmid} ({name}) cloned ({clone_type})")


def set_vm_config(vmid: int, **kwargs) -> None:
    print(f"[→] Configuring VM {vmid}...")
    upid = api_post(f"nodes/{PVE_NODE}/qemu/{vmid}/config", data=kwargs, timeout=600)
    wait_task(upid)
    print(f"[✓] VM {vmid} configured")


def start_vm(vmid: int) -> None:
    print(f"[→] Starting VM {vmid}...")
    upid = api_post(f"nodes/{PVE_NODE}/qemu/{vmid}/status/start", timeout=120)
    wait_task(upid)
    print(f"[✓] VM {vmid} started")


# --------------- pool ---------------

def ensure_pool(pool_id: str) -> None:
    try:
        api_get(f"pools/{pool_id}")
        return
    except Exception:
        pass
    try:
        api_post("pools", data={"poolid": pool_id})
        print(f"[✓] Created pool {pool_id}")
    except Exception:
        print(f"[!] Could not create pool {pool_id}; will try to add VMs anyway")


def add_vm_to_pool(vmid: int, pool_id: str) -> None:
    print(f"[→] Adding VM {vmid} to pool {pool_id}...")
    api_put(f"pools/{pool_id}", data={"vms": str(vmid)})
    print(f"[✓] VM {vmid} added to pool {pool_id}")


# --------------- MAC generation ---------------

def generate_mac_address(vmid: int, interface: int = 0) -> str:
    """Return a deterministic MAC address for *vmid* / *interface*."""
    if vmid == VMID_GW:
        return MAC_GW_NET0 if interface == 0 else MAC_GW_NET1
    if vmid == VMID_FORCAD:
        return MAC_FORCAD_NET0
    # Team VM
    team_num = vmid - VMID_TEAM_BASE
    base_parts = MAC_TEAM_BASE.split(":")
    last_byte = int(base_parts[-1], 16) + team_num
    mac_parts = base_parts[:-1] + [f"{last_byte:02x}"]
    return ":".join(mac_parts)


# --------------- proxmoxer upload ---------------

def _get_proxmox_connection() -> ProxmoxAPI:
    user, tokenid = TOKEN_ID.rsplit("!", 1)
    return ProxmoxAPI(
        PVE_HOST_CLEAN,
        user=user,
        token_name=tokenid,
        token_value=TOKEN_SECRET,
        verify_ssl=VERIFY_TLS,
        port=PVE_PORT,
        timeout=300,
    )


def upload_iso(file_path: str, storage: str | None = None, retries: int = 3) -> bool:
    """Upload an ISO file to Proxmox storage via proxmoxer."""
    import os
    if storage is None:
        storage = ISO_STORAGE
    filename = os.path.basename(file_path)

    for attempt in range(retries):
        try:
            if attempt > 0:
                print(f" (retry {attempt}/{retries - 1})...", end=" ", flush=True)
            proxmox = _get_proxmox_connection()
            with open(file_path, "rb") as f:
                proxmox.nodes(PVE_NODE).storage(storage).upload.post(
                    content="iso", filename=f,
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
