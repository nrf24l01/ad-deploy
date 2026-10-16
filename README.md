# ad-deploy

Deploys a CTF lab on Proxmox by:

- generating cloud-init ISO images for a gateway VM, a ForcAD VM, and one VM per team
- uploading those ISOs to Proxmox storage
- cloning all VMs from a prepared Proxmox template
- applying VM networking and hardware configuration
- starting the full lab

The script reads its configuration from a `deploy.yaml` file and expects supporting payload files under `data/`.

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
- `genisoimage` or `mkisofs`
- `sshpass` (only needed to automatically download the WireGuard configs from the gateway)
- access to a Proxmox VE host
- a prepared Proxmox VM template with cloud-init support
- a Proxmox API token with permission to clone VMs, configure them, and upload ISOs

System packages example on Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y genisoimage sshpass
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

## Required Project Files

Before running the deploy script, make sure these paths exist:

- `deploy.yaml`
- `data/config.yaml`
- `data/checkers/`
- `data/services/`

The script zips `data/checkers/` and `data/services/` and injects them into the generated cloud-init payloads.

## Configuration

Start from the example file:

```bash
cp deploy.example.yaml deploy.yaml
```

Then edit `deploy.yaml` with your real Proxmox and network values.

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
- `wireguard.scp`: export the generated WireGuard configs to this machine after the lab starts
  - `enabled`: `true` to download them automatically
  - `host`: gateway SSH address (defaults to `network.external.ip`)
  - `port` / `user`: SSH target (default `22` / `root`)
  - `output_dir`: local directory for the downloaded archives (default `wg-configs/`)
  - `wait_timeout_sec`, `poll_interval_sec`: how long to wait for the gateway to finish
  - requires `sshpass` on this machine; downloads `admin.zip` and `teamN.zip` from the gateway
- `frp.enabled`, `frp.server`, `frp.port`, `frp.ver`: FRP settings for the gateway

## How To Use

### 1. Prepare the environment

```bash
uv sync
cp deploy.example.yaml deploy.yaml
```

Then edit `deploy.yaml` with your real Proxmox and network values.

### 2. Add input data

Create the required data structure:

```text
data/
├── config.yaml
├── checkers/
└── services/
```

### 3. Run the deployment

Run the script with `uv`:

```bash
uv run main.py
```

## What Happens During a Run

When you run `uv run main.py`, the script will:

1. load configuration from `deploy.yaml`
2. create a Proxmox pool if needed
3. build temporary cloud-init ISO files in a timestamped local directory
4. zip and include `data/checkers/` and `data/services/`
5. upload all generated ISOs to Proxmox storage
6. write a credentials file like `creds_YYYYMMDD_HHMMSS.json`
7. destroy any existing VMs using the configured VMIDs
8. clone new VMs from the template
9. configure CPU, memory, NICs, IP config, and attached cloud-init ISOs
10. start all VMs
11. download the WireGuard config archives (`admin.zip`, `teamN.zip`) from the gateway via scp (if enabled)

## Output Files

Each run generates:

- a temporary local directory like `cloud-init_YYYYMMDD_HHMMSS/`
- a credentials file like `creds_YYYYMMDD_HHMMSS.json`
- a `wg-configs/` directory with the WireGuard client archives (if export is enabled)

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
