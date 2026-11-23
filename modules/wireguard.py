"""Generate WireGuard server and client configs on the deploy host.

The gateway VM no longer derives keys itself: every deploy builds the full
config set here, writes it to ``wg-configs/`` next to the deployer and packs a
bundle that the gateway cloud-init ISO carries.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import zipfile
from pathlib import Path

# Subnets a client may reach through the tunnel.
CLIENT_ALLOWED = "10.58.57.0/24, 10.10.10.0/24, 10.57.0.0/16"

ADMIN_LAST_OCTETS = range(2, 10)      # 10.10.10.2 .. 10.10.10.9
PLAYER_LAST_OCTETS = range(3, 14)     # 10.57.<team>.3 .. 10.57.<team>.13

BUNDLE_NAME = "wg-configs.zip"


def _wg_pubkey(private_key: str) -> str:
    try:
        result = subprocess.run(
            ["wg", "pubkey"],
            input=private_key,
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "wireguard-tools is required to generate WireGuard configs "
            "(install the 'wg' binary, e.g. apt-get install wireguard-tools)"
        ) from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"'wg pubkey' failed: {exc.stderr.strip()}") from exc
    return result.stdout.strip()


def _wg_genkey() -> str:
    try:
        result = subprocess.run(
            ["wg", "genkey"],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "wireguard-tools is required to generate WireGuard configs "
            "(install the 'wg' binary, e.g. apt-get install wireguard-tools)"
        ) from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"'wg genkey' failed: {exc.stderr.strip()}") from exc
    return result.stdout.strip()


def _keypair() -> tuple[str, str]:
    private = _wg_genkey()
    return private, _wg_pubkey(private)


def _client_conf(address: str, private_key: str,
                 server_pub: str, endpoint: str) -> str:
    return (
        "[Interface]\n"
        f"Address = {address}/32\n"
        f"PrivateKey = {private_key}\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {server_pub}\n"
        f"Endpoint = {endpoint}\n"
        f"AllowedIPs = {CLIENT_ALLOWED}\n"
        "PersistentKeepalive = 25\n"
    )


def _server_conf(wg_gw_ip: str, wg_port: int, server_priv: str,
                 peers: list[tuple[str, str]]) -> str:
    lines = [
        "[Interface]",
        f"Address = {wg_gw_ip}/32",
        f"ListenPort = {wg_port}",
        f"PrivateKey = {server_priv}",
        "PostUp   = ip route add 10.57.0.0/16 dev %i; ip route add 10.10.10.0/29 dev %i",
        "PostDown = ip route del 10.57.0.0/16 dev %i 2>/dev/null; "
        "ip route del 10.10.10.0/29 dev %i 2>/dev/null",
    ]
    for peer_pub, peer_ip in peers:
        lines += [
            "",
            "[Peer]",
            f"PublicKey = {peer_pub}",
            f"AllowedIPs = {peer_ip}/32",
        ]
    return "\n".join(lines) + "\n"


def _write_private(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    os.chmod(path, 0o600)


def _zip_files(zip_path: Path, files: list[Path]) -> None:
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            archive.write(path, arcname=path.name)


def _bundle(bundle_path: Path, root: Path) -> None:
    with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                archive.write(path, arcname=str(path.relative_to(root)))


def generate_wireguard_configs(
    *,
    n_teams: int,
    wg_gw_ip: str,
    wg_port: int,
    wg_endpoint: str,
    teams: list[dict],
    output_dir: str | Path,
    bundle_path: str | Path,
) -> dict:
    """Build server/client configs, archives and the gateway bundle.

    Returns a dict with the generated paths. ``teams`` entries need
    ``team``, ``ip``, ``user`` and ``password`` (used for ``info.txt``).
    """
    root = Path(output_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)

    # Keys are regenerated every deploy: drop configs from previous runs so a
    # stale client config can never be handed out.
    for stale in root.rglob("*.conf"):
        stale.unlink()
    for stale in root.glob("*.zip"):
        stale.unlink()
    for stale in root.glob("team*"):
        if stale.is_dir() and not any(
            stale.name == f"team{team}" for team in range(1, n_teams + 1)
        ):
            shutil.rmtree(stale, ignore_errors=True)

    server_priv, server_pub = _keypair()
    peers: list[tuple[str, str]] = []

    # --- admin clients: 10.10.10.2 .. 10.10.10.9 -----------------------
    admin_dir = root / "admin"
    admin_dir.mkdir(parents=True, exist_ok=True)
    admin_confs: list[Path] = []
    for last in ADMIN_LAST_OCTETS:
        address = f"10.10.10.{last}"
        priv, pub = _keypair()
        peers.append((pub, address))
        conf_path = admin_dir / f"admin-{last}.conf"
        _write_private(
            conf_path,
            _client_conf(address, priv, server_pub, wg_endpoint),
        )
        admin_confs.append(conf_path)

    # --- team clients: 10.57.<team>.3 .. 10.57.<team>.13 ---------------
    team_zips: list[Path] = []
    team_dirs: list[Path] = []
    for team in range(1, n_teams + 1):
        team_dir = root / f"team{team}"
        team_dir.mkdir(parents=True, exist_ok=True)
        team_dirs.append(team_dir)
        team_confs: list[Path] = []
        for last in PLAYER_LAST_OCTETS:
            address = f"10.57.{team}.{last}"
            priv, pub = _keypair()
            peers.append((pub, address))
            conf_path = team_dir / f"team{team}-player{last}.conf"
            _write_private(
                conf_path,
                _client_conf(address, priv, server_pub, wg_endpoint),
            )
            team_confs.append(conf_path)

        info = next((t for t in teams if int(t["team"]) == team), None)
        info_path = team_dir / "info.txt"
        if info is not None:
            info_path.write_text(
                f"Team {team}\n"
                f"IP: {info['ip']}\n"
                f"User: {info.get('user', 'root')}\n"
                f"Password: {info['password']}\n",
                encoding="utf-8",
            )
        _zip_files(root / f"team{team}.zip", team_confs + [info_path])
        team_zips.append(root / f"team{team}.zip")

    # --- server config --------------------------------------------------
    server_conf = root / "server" / "wg0.conf"
    _write_private(
        server_conf,
        _server_conf(wg_gw_ip, wg_port, server_priv, peers),
    )

    # --- archives the gateway serves to players -------------------------
    admin_zip = root / "admin.zip"
    _zip_files(admin_zip, admin_confs)

    bundle = Path(bundle_path).resolve()
    bundle.parent.mkdir(parents=True, exist_ok=True)
    _bundle(bundle, root)

    for directory in (root, admin_dir, root / "server", *team_dirs):
        os.chmod(directory, 0o700)
    for archive in (admin_zip, *team_zips, bundle):
        os.chmod(archive, 0o600)

    return {
        "root": root,
        "server_conf": server_conf,
        "admin_zip": admin_zip,
        "team_zips": team_zips,
        "bundle": bundle,
        "client_count": len(peers),
    }
