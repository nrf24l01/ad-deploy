# ad-deploy

Deploys a CTF lab on Proxmox by:

- generating cloud-init ISO images for a gateway VM, a ForcAD VM, and one VM per team
- uploading those ISOs to Proxmox storage
- cloning all VMs from a prepared Proxmox template
- applying VM networking and hardware configuration
- starting the full lab

The script reads its configuration from `deploy.yaml` and fetches the AD services, checkers, and ForcAD configuration from the configured Git repository.

## What It Creates

The project creates these machines:

- `ctf-gw`: gateway VM for the lab
- `forcad`: ForcAD VM
- `team-1` through `team-N`: one VM per team

Network layout is based on isolated `/31` point-to-point links:

- ForcAD: `10.10.10.10/31` <-> gateway `10.10.10.11/31`
- Teams: `10.58.57.x/31` links generated per team
- WireGuard gateway IP defaults to `10.10.10.1`

## Prerequisites

You need:

- `uv`
- `git`
- `genisoimage` or `mkisofs`
- `wireguard-tools` (the `wg` binary, used to generate the WireGuard keys)
- access to a Proxmox VE host
- a prepared Proxmox VM template with cloud-init support
- a Proxmox API token with permission to clone VMs, configure them, and upload ISOs

System packages example on Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y git genisoimage wireguard-tools
```

Install `uv` if it is not already present:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## Install

This project is a standard `uv` project: dependencies are declared in `pyproject.toml`, so `uv` handles the environment automatically.

Run in place (recommended while developing):

```bash
uv sync            # create .venv and install dependencies from pyproject.toml
uv run main.py
```

Or install it as a tool for a globally available `ad-deploy` command:

```bash
uv tool install .
ad-deploy
```

Either way, `uv` resolves the same dependencies (`requests`, `urllib3`, `proxmoxer`, `pyyaml`, `jinja2`).

## Configuration

Start from the example file:

```bash
cp deploy.example.yaml deploy.yaml
```

Then edit `deploy.yaml` with your real Proxmox and network values.

### AD source

- `ad.repository`: Git URL containing the AD source (defaults to `https://github.com/C4T-BuT-S4D/ctfcup-2024-ad.git`)
- `ad.ref`: branch or tag to fetch (defaults to `master`)
- `ad.start_time`: optional ForcAD start time in the timezone set by the AD config; when blank, the deployer schedules it 30 minutes after deployment starts
- `ad.overlay`: optional local directory copied over the clone, for repos that are not deployment-ready (supply `forcad_config.yml`, generated files, per-service `pre-start.sh` hooks). Keep overlays outside this repository — they are deployment data, like `deploy.yaml`, and are gitignored under `ad-overlays/`.
- `ad.task_ports`: optional `service: port` map, for services whose Compose file publishes several ports or one that cannot be inferred

The repository (after the overlay is applied) must contain `services/`, `checkers/`, and `forcad_config.yml` at its root. The deployer packages the service and checker directories, replaces the ForcAD team list with `lab.n_teams` and the configured team IP plan, and sets a usable game start time. Git must be installed on the machine running the deployment.

A service directory may contain an executable `pre-start.sh`; it runs before `docker compose up` on every team VM with `TEAM_IP` and `CHECKER_SECRET` in its environment, which covers per-team secrets and TLS material.

### Proxmox

- `proxmox.host`: full Proxmox URL, for example `https://pve.example.org:8006`
- `proxmox.port`: Proxmox API port, usually `8006`
- `proxmox.node`: target Proxmox node name
- `proxmox.token_id`: token id in the form `user@realm!tokenname`
- `proxmox.token_secret`: token secret
- `proxmox.verify_tls`: `true` to verify TLS, `false` to skip

### Template and Storage

- `template.vmid`: VMID of the prepared source template
- `template.clone_full`: `true` for full clone, `false` for linked clone
- `storage.iso`: Proxmox storage name where ISOs are uploaded

The storage must allow `ISO image` content.

### Lab Size and VM IDs

- `lab.n_teams`: number of team VMs to create
- `vmids.gateway`: gateway VMID
- `vmids.forcad`: ForcAD VMID
- `vmids.team_base`: base VMID for team VMs

Team VMIDs are generated as `team_base + team_number`.

### Networking

- `network.ctf_bridge`: internal bridge for the isolated lab network
- `network.external.bridge`: external bridge for gateway `net1`
- `network.external.vlan`: optional VLAN tag for `net1` (blank for none)
- `network.external.ip`: optional external IP for the gateway
- `network.external.gateway`: optional external gateway
- `network.dns_servers`: list of DNS servers
- `ip_plan.forcad_ip`: ForcAD address with CIDR
- `ip_plan.forcad_gw_side`: gateway-side address with CIDR on the ForcAD link
- `ip_plan.wg_gw_ip`: WireGuard gateway IP

### Resources

- `resources.team.cores` / `resources.team.ram_mb`
- `resources.forcad.cores` / `resources.forcad.ram_mb`
- `resources.gateway.cores` / `resources.gateway.ram_mb`

### Optional Features

- `lab.allow_root_ssh`: `true` to allow root password SSH on team VMs
- `lab.pool`: Proxmox pool to use or create
- `wireguard.port`, `wireguard.endpoint`: WireGuard settings
- `wireguard.output_dir`: local directory where the generated client configs are written (default `wg-configs/`)
- `frp.enabled`, `frp.server`, `frp.port`, `frp.ver`: FRP settings for the gateway

## How To Use

### 1. Prepare the environment

```bash
uv sync
cp deploy.example.yaml deploy.yaml
```

Then edit `deploy.yaml` with your real Proxmox and network values.

### 2. Run the deployment

Run the script with `uv`:

```bash
uv run main.py
```

## What Happens During a Run

When you run `uv run main.py`, the script will:

1. load configuration from `deploy.yaml`
2. create a Proxmox pool if needed
3. build temporary cloud-init ISO files in a timestamped local directory
4. clone the configured AD repository ref and validate its expected layout
5. zip and include the repository's `checkers/` and `services/` folders, and adapt `forcad_config.yml` to the configured teams
6. generate the WireGuard server config, client configs and archives on this machine
7. build the cloud-init ISOs, packing the WireGuard bundle into the gateway ISO
8. upload all generated ISOs to Proxmox storage
9. write a credentials file like `creds_YYYYMMDD_HHMMSS.json`
10. destroy any existing VMs using the configured VMIDs
11. clone new VMs from the template
12. configure CPU, memory, NICs, IP config, and attached cloud-init ISOs
13. start all VMs

The WireGuard configs are generated on this machine before any VM is created:
the server `wg0.conf`, the admin and player client configs, and the
`admin.zip` / `teamN.zip` archives. They are written to `wireguard.output_dir`
and packed into the gateway's cloud-init ISO, so the gateway only installs them
and never generates keys itself. Keys are regenerated on every deploy.

## Output Files

Each run generates:

- a temporary local directory like `cloud-init_YYYYMMDD_HHMMSS/`
- a credentials file like `creds_YYYYMMDD_HHMMSS.json`
- a `wg-configs/` directory with `server/wg0.conf`, `admin/`, `teamN/`, plus the `admin.zip` and `teamN.zip` archives

The credentials JSON contains generated passwords and addressing information for the deployed lab.

## Notes and Caveats

- The script destroys existing VMs that use the configured VMIDs before recreating them.
- If ISO uploads fail, the script stops before VM recreation completes.
- The Proxmox storage configured by `storage.iso` must support ISO uploads.
- If neither `genisoimage` nor `mkisofs` is installed, ISO creation fails.
- `deploy.yaml` is gitignored; commit `deploy.example.yaml` instead. Keep the Proxmox token secret out of version control.

## Troubleshooting

### Missing Python modules

Run `uv sync` to install all dependencies from `pyproject.toml` into the project environment.

### ISO upload errors

Check:

- `storage.iso` points to the correct Proxmox storage
- the storage has `ISO image` content enabled
- the API token has permission to allocate space on that storage

### Cloud-init ISO creation fails

Install `genisoimage`:

```bash
sudo apt-get install -y genisoimage
```

### TLS issues

If your Proxmox instance uses a self-signed certificate, set:

```yaml
proxmox:
  verify_tls: false
```

Use that only when appropriate for your environment.
