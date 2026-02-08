#!/usr/bin/env python3
"""CTF Lab Setup — entry point.

Creates cloud-init ISOs, uploads them to Proxmox, clones template VMs,
configures networking and starts the lab.
"""
from __future__ import annotations

import json
import os
from datetime import datetime

from modules.config import (
    N_TEAMS, PVE_HOST, PVE_NODE,
    BR_CTF, EXT_BRIDGE, EXT_VLAN, EXT_GW_IP, EXT_GW_GATEWAY,
    ISO_STORAGE, POOL_ID,
    VMID_GW, VMID_FORCAD, VMID_TEAM_BASE,
    FORCAD_IP, FORCAD_GW, FORCAD_GW_SIDE, WG_GW_IP,
    ALLOW_ROOT_SSH,
    GW_CORES, GW_RAM_MB,
    FORCAD_CORES, FORCAD_RAM_MB,
    TEAM_CORES, TEAM_RAM_MB,
    WG_PORT, WG_ENDPOINT,
    FRP_ENABLED, FRP_SERVER, FRP_PORT, FRP_VER,
)
from modules.network import (
    team_vm_ip, team_gw_ip, team_vm_addr, team_gw_addr,
    random_password,
)
from modules.proxmox_api import (
    api_get,
    ensure_pool, destroy_vm_if_exists,
    clone_vm, set_vm_config, start_vm,
    generate_mac_address, upload_iso,
)
from modules.cloud_init_generator import (
    gw_network_config, gw_user_data,
    forcad_user_data, forcad_network_config,
    team_user_data, team_network_config,
    build_forcad_config,
    create_cloud_init_iso, zip_dir_to_file,
)


def main() -> None:
    print("=" * 60)
    print("CTF Lab Setup Script")
    print("=" * 60)
    print(f"\n[*] Configuration:")
    print(f"    Teams: {N_TEAMS}")
    print(f"    Proxmox: {PVE_HOST} (node: {PVE_NODE})")
    print(f"    CTF Bridge: {BR_CTF}")
    if EXT_BRIDGE and EXT_GW_IP:
        print(f"    External Bridge: {EXT_BRIDGE} (VLAN: {EXT_VLAN or 'none'}, IP: {EXT_GW_IP})")
    print(f"    VMIDs: GW={VMID_GW}, ForcAD={VMID_FORCAD}, Teams={VMID_TEAM_BASE}+")
    print(f"\n[*] Network topology (isolated /31 point-to-point):")
    print(f"    ForcAD:  {FORCAD_IP} <-> GW {FORCAD_GW_SIDE}")
    for t in range(1, N_TEAMS + 1):
        print(f"    Team {t}:  {team_vm_ip(t)} <-> GW {team_gw_ip(t)}")
    print(f"    WG:      Players 10.57.<team>.{{3..13}}/24, GW wg0 = {WG_GW_IP}")

    print("\n[*] Cloud-init will be created as ISO images")
    print(f"    - ISO storage: {ISO_STORAGE}")
    print(f"    - CTF bridge: {BR_CTF}")

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    creds_path = f"creds_{ts}.json"
    print(f"\n[*] Timestamp: {ts}")

    # Ensure pool exists
    ensure_pool(POOL_ID)

    # Create local temp directory for ISOs
    tmpdir = os.path.abspath(f"./cloud-init_{ts}")
    os.makedirs(tmpdir, exist_ok=True)
    print(f"[✓] Local cloud-init directory: {tmpdir}")

    # Prepare payloads
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

    # Generate passwords
    print(f"\n[*] Generating cloud-init configs for {N_TEAMS} teams...")
    gw_password = random_password(20)
    forcad_password = random_password(20)

    creds: dict = {
        "generated_at_utc": ts,
        "n_teams": N_TEAMS,
        "allow_root_ssh_password": ALLOW_ROOT_SSH,
        "gateway": {
            "vm_name": "ctf-gw",
            "vmid": VMID_GW,
            "forcad_link_ip": FORCAD_GW_SIDE,
            "team_link_ips": [team_gw_ip(t) for t in range(1, N_TEAMS + 1)],
            "wg_ip": WG_GW_IP,
            "ext_ip": EXT_GW_IP or "none",
            "root_password": gw_password,
        },
        "forcad": {
            "vm_name": "forcad",
            "vmid": VMID_FORCAD,
            "ip": FORCAD_IP,
            "gateway": FORCAD_GW,
            "root_password": forcad_password,
        },
        "teams": [],
    }

    # -- shared template variables for gateway --
    gw_extra = dict(
        ext_gw_ip=EXT_GW_IP,
        ext_gw_gateway=EXT_GW_GATEWAY,
        wg_gw_ip=WG_GW_IP,
        wg_port=WG_PORT,
        wg_endpoint=WG_ENDPOINT,
        frp_enabled=FRP_ENABLED,
        frp_server=FRP_SERVER,
        frp_port=FRP_PORT,
        frp_ver=FRP_VER,
    )

    # Create cloud-init ISOs
    print(f"\n[*] Creating cloud-init ISO images...")

    gw_iso = create_cloud_init_iso(
        gw_user_data(N_TEAMS, gw_password, **gw_extra),
        "ctf-gw",
        tmpdir,
        network_config=gw_network_config(
            N_TEAMS,
            forcad_gw_side=FORCAD_GW_SIDE,
            ext_gw_ip=EXT_GW_IP,
            ext_gw_gateway=EXT_GW_GATEWAY,
        ),
    )
    print(f"[✓] Created gateway ISO: {os.path.basename(gw_iso)}")

    fc_iso = create_cloud_init_iso(
        forcad_user_data(
            forcad_password,
            forcad_config,
            forcad_ip=FORCAD_IP,
            forcad_gw=FORCAD_GW,
        ),
        "forcad",
        tmpdir,
        extra_files=[(forcad_checkers_zip, "forcad-checkers.zip")],
        network_config=forcad_network_config(FORCAD_IP, FORCAD_GW),
    )
    print(f"[✓] Created ForcAD ISO: {os.path.basename(fc_iso)}")

    team_isos: dict[int, str] = {}
    for team in range(1, N_TEAMS + 1):
        pw = random_password(20)
        t_ip = team_vm_ip(team)
        t_gw = team_gw_addr(team)
        team_iso = create_cloud_init_iso(
            team_user_data(pw, ALLOW_ROOT_SSH, t_ip, t_gw),
            f"team-{team}",
            tmpdir,
            extra_files=[(services_zip, "services.zip")],
            network_config=team_network_config(t_ip, t_gw),
        )
        team_isos[team] = team_iso
        print(f"[✓] Created team {team} ISO: {os.path.basename(team_iso)} ({t_ip} -> gw {t_gw})")

        creds["teams"].append({
            "team": team,
            "vm_name": f"team-{team}",
            "vmid": VMID_TEAM_BASE + team,
            "ip": t_ip,
            "gateway": t_gw,
            "root_password": pw,
        })

    # Upload ISOs
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

    # Write credentials
    with open(creds_path, "w", encoding="utf-8") as f:
        json.dump(creds, f, ensure_ascii=False, indent=2)
    os.chmod(creds_path, 0o600)
    print(f"\n[✓] Snippet files ready in {tmpdir}")
    print(f"[✓] Credentials written to {creds_path}")

    # Destroy old VMs
    print(f"\n[*] Cleaning up existing VMs...")
    all_vmids = [VMID_GW, VMID_FORCAD] + [VMID_TEAM_BASE + i for i in range(1, N_TEAMS + 1)]
    for vmid in all_vmids:
        destroy_vm_if_exists(vmid)
    print(f"[✓] Cleanup complete")

    # -------- Create Gateway --------
    print(f"\n[*] Creating Gateway VM (VMID {VMID_GW})...")
    clone_vm(VMID_GW, "ctf-gw")

    net1_config = f"virtio,bridge={EXT_BRIDGE}"
    if EXT_VLAN:
        net1_config += f",tag={EXT_VLAN}"

    ipconfig1 = ""
    if EXT_GW_IP:
        ipconfig1 = f"ip={EXT_GW_IP}"
        if EXT_GW_GATEWAY:
            ipconfig1 += f",gw={EXT_GW_GATEWAY}"

    gw_cfg: dict = {
        "cores": GW_CORES,
        "memory": GW_RAM_MB,
        "net0": f"virtio,bridge={BR_CTF},macaddr={generate_mac_address(VMID_GW, 0)}",
        "net1": f"{net1_config},macaddr={generate_mac_address(VMID_GW, 1)}",
        "ipconfig0": f"ip={FORCAD_GW_SIDE}",
        "ide2": f"{ISO_STORAGE}:iso/{os.path.basename(gw_iso)},media=cdrom",
        "agent": "enabled=1",
        "serial0": "socket",
    }
    if ipconfig1:
        gw_cfg["ipconfig1"] = ipconfig1

    set_vm_config(VMID_GW, **gw_cfg)

    print(f"[*] Verifying gateway VM config...")
    vm_config = api_get(f"nodes/{PVE_NODE}/qemu/{VMID_GW}/config")
    print(f"    ide2 (cloud-init): {vm_config.get('ide2', 'NOT SET')}")

    # -------- Create ForcAD --------
    print(f"\n[*] Creating ForcAD VM (VMID {VMID_FORCAD})...")
    clone_vm(VMID_FORCAD, "forcad")
    set_vm_config(
        VMID_FORCAD,
        cores=FORCAD_CORES, memory=FORCAD_RAM_MB,
        net0=f"virtio,bridge={BR_CTF},macaddr={generate_mac_address(VMID_FORCAD, 0)}",
        ipconfig0=f"ip={FORCAD_IP},gw={FORCAD_GW}",
        ide2=f"{ISO_STORAGE}:iso/{os.path.basename(fc_iso)},media=cdrom",
        agent="enabled=1",
    )

    # -------- Create Teams --------
    print(f"\n[*] Creating {N_TEAMS} Team VMs...")
    for team in range(1, N_TEAMS + 1):
        vmid = VMID_TEAM_BASE + team
        t_ip = team_vm_ip(team)
        t_gw = team_gw_addr(team)
        print(f"\n[*] Creating Team {team} VM (VMID {vmid}, {t_ip} -> gw {t_gw})...")
        clone_vm(vmid, f"team-{team}")
        set_vm_config(
            vmid,
            cores=TEAM_CORES, memory=TEAM_RAM_MB,
            net0=f"virtio,bridge={BR_CTF},macaddr={generate_mac_address(vmid, 0)}",
            ipconfig0=f"ip={t_ip},gw={t_gw}",
            ide2=f"{ISO_STORAGE}:iso/{os.path.basename(team_isos[team])},media=cdrom",
            agent="enabled=1",
        )

    # -------- Start all --------
    print(f"\n[*] Starting all VMs...")
    start_vm(VMID_GW)
    start_vm(VMID_FORCAD)
    for team in range(1, N_TEAMS + 1):
        start_vm(VMID_TEAM_BASE + team)

    print("\n" + "=" * 60)
    print("[+] Setup Complete!")
    print("=" * 60)
    print(f"    Credentials: {creds_path}")
    print(f"    Network: isolated /31 point-to-point links")
    print(f"    ForcAD:  {FORCAD_IP} (gw {FORCAD_GW})")
    for t in range(1, N_TEAMS + 1):
        print(f"    Team {t}:  {team_vm_ip(t)} (gw {team_gw_addr(t)})")
    print(f"    WireGuard configs: NOT DOWNLOADED")
    print(f"      Check on gateway: /var/log/wg-config-gen.log")
    print(f"      Configs will be in: /srv/wg-configs/")
    print("    FRP client on GW forwards only UDP WireGuard port.")


if __name__ == "__main__":
    main()
