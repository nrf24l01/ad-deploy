"""Cloud-init ISO builder — renders Jinja2 templates and packs NoCloud ISOs."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from jinja2 import Environment, FileSystemLoader
import yaml

from modules.config import DNS_SERVERS
from modules.network import team_vm_addr

# Resolve template directories relative to this file
_BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = _BASE_DIR / "cloud_inits" / "vm"
CONFIGS_DIR = _BASE_DIR / "cloud_inits" / "configs"

_jinja_env: Environment | None = None


def _get_jinja_env() -> Environment:
    global _jinja_env
    if _jinja_env is None:
        _jinja_env = Environment(
            loader=FileSystemLoader([str(TEMPLATES_DIR), str(CONFIGS_DIR)]),
            keep_trailing_newline=True,
            lstrip_blocks=True,
            trim_blocks=True,
        )
    return _jinja_env


def render_template(template_name: str, **kwargs) -> str:
    """Render a Jinja2 template from cloud_inits/vm/ or cloud_inits/configs/."""
    env = _get_jinja_env()
    tpl = env.get_template(template_name)
    return tpl.render(**kwargs)


def read_config_file(name: str) -> str:
    """Read a static config file from cloud_inits/configs/."""
    return (CONFIGS_DIR / name).read_text(encoding="utf-8")


def render_config_file(name: str, **kwargs) -> str:
    """Render a config file from cloud_inits/configs/ as a Jinja2 template."""
    return render_template(name, **kwargs)


# --------------- cloud-init user-data renderers ---------------

def gw_network_config(n_teams: int, *, forcad_gw_side: str,
                      ext_gw_ip: str, ext_gw_gateway: str) -> str:
    return render_template(
        "gw_network.yaml.j2",
        n_teams=n_teams,
        forcad_gw_side=forcad_gw_side,
        ext_gw_ip=ext_gw_ip,
        ext_gw_gateway=ext_gw_gateway,
        dns_servers=DNS_SERVERS,
    )


def team_network_config(team_ip: str, gateway_ip: str) -> str:
    return render_template(
        "team_network.yaml.j2",
        team_ip=team_ip,
        gateway_ip=gateway_ip,
        dns_servers=DNS_SERVERS,
    )


def forcad_network_config(forcad_ip: str, forcad_gw: str) -> str:
    return render_template(
        "forcad_network.yaml.j2",
        forcad_ip=forcad_ip,
        forcad_gw=forcad_gw,
        dns_servers=DNS_SERVERS,
    )


def gw_user_data(n_teams: int, root_pw: str, **extra) -> str:
    # Static config files (no Jinja vars inside)
    nftables_conf = read_config_file("nftables.conf")
    sshd_config = read_config_file("sshd_config")

    # WireGuard configs are generated on the deploy host and shipped on the
    # cloud-init ISO, so the gateway only installs them.
    install_wg_sh = read_config_file("install-wg-configs.sh")

    # Config files that contain Jinja2 variables — render them first
    tpl_vars = dict(
        n_teams=n_teams,
        wg_gw_ip=extra.get("wg_gw_ip", "10.10.10.1"),
        wg_port=extra.get("wg_port", 51820),
        wg_endpoint=extra.get("wg_endpoint", ""),
        frp_server=extra.get("frp_server", ""),
        frp_port=extra.get("frp_port", 7000),
    )
    frpc_ini = render_config_file("frpc.ini", **tpl_vars) if extra.get("frp_enabled") else ""
    frpc_service = read_config_file("frpc.service") if extra.get("frp_enabled") else ""

    return render_template(
        "gateway.yaml.j2",
        n_teams=n_teams,
        root_pw=root_pw,
        dns_servers=DNS_SERVERS,
        nftables_conf=nftables_conf,
        sshd_config=sshd_config,
        install_wg_sh=install_wg_sh,
        frpc_ini=frpc_ini,
        frpc_service=frpc_service,
        **extra,
    )


def forcad_user_data(root_pw: str, config_yaml: str, **extra) -> str:
    return render_template(
        "forcad.yaml.j2",
        root_pw=root_pw,
        config_yaml=config_yaml,
        dns_servers=DNS_SERVERS,
        **extra,
    )


def team_user_data(root_pw: str, allow_root_ssh: bool,
                   team_ip: str, gateway_ip: str,
                   checker_secret: str = "") -> str:
    return render_template(
        "team.yaml.j2",
        root_pw=root_pw,
        allow_root_ssh=allow_root_ssh,
        team_ip=team_ip,
        gateway_ip=gateway_ip,
        checker_secret=checker_secret,
        dns_servers=DNS_SERVERS,
    )


# --------------- ForcAD config builder ---------------

def build_forcad_config(
    base_config: str,
    n_teams: int,
    start_time: str = "",
    services_dir: str | Path | None = None,
    task_ports: dict[str, int] | None = None,
) -> str:
    """Adapt an AD config to this lab's teams and deployment start time."""
    config = yaml.safe_load(base_config) or {}
    if not isinstance(config, dict):
        raise ValueError("ForcAD config must be a YAML mapping")

    game = config.setdefault("game", {})
    if not isinstance(game, dict):
        raise ValueError("ForcAD config 'game' section must be a mapping")

    timezone = ZoneInfo(str(game.get("timezone", "UTC")))
    if start_time:
        game_start = datetime.fromisoformat(start_time)
        if game_start.tzinfo is not None:
            game_start = game_start.astimezone(timezone).replace(tzinfo=None)
    else:
        game_start = (datetime.now(timezone) + timedelta(minutes=30)).replace(
            tzinfo=None
        )
    # PyYAML serializes datetime values as YAML timestamps; ForcAD validates
    # this field strictly and rejects a quoted YAML string.
    game["start_time"] = game_start

    task_ports = task_ports or {}
    tasks = config.get("tasks", [])
    if services_dir is not None:
        if not isinstance(tasks, list):
            raise ValueError("ForcAD config 'tasks' section must be a list")
        for task in tasks:
            if not isinstance(task, dict) or not isinstance(task.get("name"), str):
                raise ValueError("Each ForcAD task must have a name")
            service_name = task["name"]
            if service_name in task_ports:
                ports = {str(task_ports[service_name])}
            else:
                compose_path = Path(services_dir) / service_name / "docker-compose.yml"
                if not compose_path.is_file():
                    raise ValueError(
                        f"Missing Compose file for service {service_name!r}: {compose_path}"
                    )
                with compose_path.open(encoding="utf-8") as compose_file:
                    compose = yaml.safe_load(compose_file) or {}
                ports = set()
                for service in (compose.get("services") or {}).values():
                    for mapping in service.get("ports", []) or []:
                        if isinstance(mapping, str):
                            target = mapping.rsplit(":", 1)[-1].split("/", 1)[0]
                        elif isinstance(mapping, dict):
                            target = mapping.get("target")
                        else:
                            continue
                        if target is not None:
                            ports.add(str(target))
            if len(ports) != 1:
                raise ValueError(
                    f"Expected exactly one service port for {service_name!r}, found {sorted(ports)}"
                )
            task["name"] = f"{service_name}({next(iter(ports))})"

    config["teams"] = [
        {"ip": team_vm_addr(team), "name": f"Team {team}"}
        for team in range(1, n_teams + 1)
    ]
    return yaml.safe_dump(config, sort_keys=False, allow_unicode=True)


# --------------- ISO creation ---------------

def create_cloud_init_iso(
    user_data: str,
    vm_name: str,
    output_dir: str,
    extra_files: list[tuple[str, str]] | None = None,
    network_config: str | None = None,
    iso_filename: str | None = None,
) -> str:
    """Create a NoCloud cloud-init ISO image and return its path."""
    iso_name = iso_filename or f"{vm_name}-cloud-init.iso"
    iso_path = os.path.join(output_dir, iso_name)

    with tempfile.TemporaryDirectory() as tmpdir:
        user_data_path = os.path.join(tmpdir, "user-data")
        with open(user_data_path, "w", encoding="utf-8") as f:
            f.write(user_data)

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

        cmd = None
        for tool in ("genisoimage", "mkisofs"):
            if shutil.which(tool):
                cmd = [
                    tool,
                    "-output", iso_path,
                    "-volid", "cidata",
                    "-joliet", "-rock",
                    user_data_path, meta_data_path,
                ]
                if network_config_path:
                    cmd.append(network_config_path)
                if extra_files:
                    for _, dest_name in extra_files:
                        cmd.append(os.path.join(tmpdir, dest_name))
                break

        if not cmd:
            raise RuntimeError(
                "Neither genisoimage nor mkisofs found.  "
                "Install: apt-get install genisoimage"
            )

        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    return iso_path


# --------------- helpers ---------------

def zip_dir_to_file(dir_path: str, out_path: str) -> None:
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(dir_path):
            for name in files:
                full = os.path.join(root, name)
                zf.write(full, os.path.relpath(full, dir_path))
