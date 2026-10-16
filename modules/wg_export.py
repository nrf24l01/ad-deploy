"""Download WireGuard client configs from the gateway VM via scp."""
from __future__ import annotations

import os
import shutil
import subprocess
import time

from modules.config import (
    WG_SCP_ENABLED, WG_SCP_HOST, WG_SCP_PORT, WG_SCP_USER,
    WG_SCP_OUTPUT_DIR, WG_SCP_WAIT_TIMEOUT_SEC, WG_SCP_POLL_SEC,
)


def _sshpass_available() -> bool:
    return shutil.which("sshpass") is not None


def _wait_for_gateway(host: str, port: int, user: str, password: str,
                      timeout_sec: int, poll_sec: int) -> bool:
    probe = [
        "sshpass", "-p", password,
        "ssh", "-p", str(port),
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=5",
        f"{user}@{host}",
        "test -f /root/admin.zip && echo ready",
    ]
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            r = subprocess.run(probe, capture_output=True, text=True, timeout=15)
            if r.returncode == 0 and "ready" in r.stdout:
                return True
        except subprocess.TimeoutExpired:
            pass
        time.sleep(poll_sec)
    return False


def _scp(host: str, port: int, user: str, password: str,
         remote_path: str, output_dir: str) -> subprocess.CompletedProcess:
    cmd = [
        "sshpass", "-p", password,
        "scp", "-P", str(port),
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        f"{user}@{host}:{remote_path}",
        output_dir,
    ]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120)


def download_wg_configs(gw_host: str, gw_password: str, n_teams: int) -> str:
    """Download admin.zip and teamN.zip from the gateway; return output dir."""
    if not _sshpass_available():
        raise RuntimeError(
            "sshpass is not installed. Install it: sudo apt-get install -y sshpass"
        )

    port = WG_SCP_PORT
    user = WG_SCP_USER
    output_dir = WG_SCP_OUTPUT_DIR

    print(f"[*] Waiting for gateway {user}@{gw_host}:{port} to generate "
          f"WireGuard configs (timeout {WG_SCP_WAIT_TIMEOUT_SEC}s)...")
    if not _wait_for_gateway(gw_host, port, user, gw_password,
                             WG_SCP_WAIT_TIMEOUT_SEC, WG_SCP_POLL_SEC):
        raise TimeoutError(
            f"Gateway did not become ready within {WG_SCP_WAIT_TIMEOUT_SEC}s. "
            "Check that the gateway is reachable and cloud-init finished."
        )

    os.makedirs(output_dir, exist_ok=True)
    remote_files = ["admin.zip"] + [f"team{t}.zip" for t in range(1, n_teams + 1)]
    downloaded = []
    for name in remote_files:
        print(f"[→] Downloading {name} ...", end=" ", flush=True)
        r = _scp(host=gw_host, port=port, user=user, password=gw_password,
                 remote_path=f"/root/{name}", output_dir=output_dir)
        if r.returncode != 0:
            print("✗")
            raise RuntimeError(f"scp failed for {name}: {r.stderr.strip()}")
        print("✓")
        downloaded.append(os.path.join(output_dir, name))

    print(f"[✓] Downloaded {len(downloaded)} WireGuard config archives to {output_dir}")
    return output_dir


def wg_export_available() -> bool:
    """Whether config export is enabled and a reachable host is configured."""
    return WG_SCP_ENABLED and bool(WG_SCP_HOST)
