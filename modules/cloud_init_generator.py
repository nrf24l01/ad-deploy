"""Cloud-init ISO builder — renders Jinja2 templates and packs NoCloud ISOs."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

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

    # Config files that contain Jinja2 variables — render them first
    tpl_vars = dict(
        n_teams=n_teams,
        wg_gw_ip=extra.get("wg_gw_ip", "10.10.10.1"),
        wg_port=extra.get("wg_port", 51820),
        wg_endpoint=extra.get("wg_endpoint", ""),
        frp_server=extra.get("frp_server", ""),
        frp_port=extra.get("frp_port", 7000),
    )
    generate_wg_sh = render_config_file("generate-wg-configs.sh", **tpl_vars)
    zip_wg_sh = render_config_file("zip-wg-configs.sh", **tpl_vars)
    frpc_ini = render_config_file("frpc.ini", **tpl_vars) if extra.get("frp_enabled") else ""
    frpc_service = read_config_file("frpc.service") if extra.get("frp_enabled") else ""

    return render_template(
        "gateway.yaml.j2",
        n_teams=n_teams,
        root_pw=root_pw,
        dns_servers=DNS_SERVERS,
        nftables_conf=nftables_conf,
        sshd_config=sshd_config,
        generate_wg_sh=generate_wg_sh,
        zip_wg_sh=zip_wg_sh,
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
                   team_ip: str, gateway_ip: str) -> str:
    return render_template(
        "team.yaml.j2",
        root_pw=root_pw,
        allow_root_ssh=allow_root_ssh,
        team_ip=team_ip,
        gateway_ip=gateway_ip,
        dns_servers=DNS_SERVERS,
    )


# --------------- ForcAD config builder ---------------

def build_forcad_config(base_config: str, n_teams: int) -> str:
    if "\nteams:" in base_config or base_config.strip().startswith("teams:"):
        base_config = base_config.split("\nteams:", 1)[0].rstrip() + "\n"

    lines = [base_config.rstrip(), "", "teams:"]
    for team in range(1, n_teams + 1):
        lines.append(f"  - ip: {team_vm_addr(team)}")
        lines.append(f'    name: "Team {team}"')
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# --------------- ISO creation ---------------

def create_cloud_init_iso(
    user_data: str,
    vm_name: str,
    output_dir: str,
    extra_files: list[tuple[str, str]] | None = None,
    network_config: str | None = None,
) -> str:
    """Create a NoCloud cloud-init ISO image and return its path."""
    iso_name = f"{vm_name}-cloud-init.iso"
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
