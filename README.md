# ad-deploy

Deploys a CTF lab on Proxmox by:

- generating cloud-init ISO images for a gateway VM, a ForcAD VM, and one VM per team
- uploading those ISOs to Proxmox storage
- cloning all VMs from a prepared Proxmox template
- applying VM networking and hardware configuration
- starting the full lab

The script reads its configuration from environment variables in a `.env` file and expects supporting payload files under `data/`.

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
- access to a Proxmox VE host
- a prepared Proxmox VM template with cloud-init support
- a Proxmox API token with permission to clone VMs, configure them, and upload ISOs

System package example on Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y genisoimage
```

Install `uv` if it is not already present:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## Python Dependencies

This repository currently does not include a `pyproject.toml`, so use `uv` with a virtual environment and `uv pip`.

Create the environment:

```bash
uv venv
```

Install runtime dependencies into that environment:

```bash
uv pip install requests urllib3 proxmoxer python-dotenv jinja2
```

## Required Project Files

Before running the deploy script, make sure these paths exist:

- `.env`
- `data/config.yaml`
- `data/checkers/`
- `data/services/`

The script zips `data/checkers/` and `data/services/` and injects them into the generated cloud-init payloads.

## Configuration

Start from the example file:

```bash
cp .env.example .env
```

Important variables in `.env`:

### Proxmox

- `PVE_HOST`: full Proxmox URL, for example `https://pve.example.org:8006`
- `PVE_PORT`: Proxmox API port, usually `8006`
- `PVE_NODE`: target Proxmox node name
- `PVE_TOKEN_ID`: token id in the form `user@realm!tokenname`
- `PVE_TOKEN_SECRET`: token secret
- `VERIFY_TLS`: `1` to verify TLS, `0` to skip verification

### Template and Storage

- `TEMPLATE_VMID`: VMID of the prepared source template
- `ISO_STORAGE`: Proxmox storage name where ISOs are uploaded

The storage must allow `ISO image` content.

### Lab Size and VM IDs

- `N_TEAMS`: number of team VMs to create
- `VMID_GW`: gateway VMID
- `VMID_FORCAD`: ForcAD VMID
- `VMID_TEAM_BASE`: base VMID for team VMs

Team VMIDs are generated as `VMID_TEAM_BASE + team_number`.

### Networking

- `BR_CTF`: internal bridge for the isolated lab network
- `EXT_BRIDGE`: external bridge for gateway `net1`
- `EXT_VLAN`: optional VLAN tag for `net1`
- `EXT_GW_IP`: optional external IP for the gateway
- `EXT_GW_GATEWAY`: optional external gateway
- `DNS_SERVERS`: comma-separated DNS servers
- `FORCAD_IP`: ForcAD address with CIDR
- `FORCAD_GW_SIDE`: gateway-side address with CIDR on the ForcAD link
- `WG_GW_IP`: WireGuard gateway IP

### Resources

- `TEAM_CORES`, `TEAM_RAM_MB`
- `FORCAD_CORES`, `FORCAD_RAM_MB`
- `GW_CORES`, `GW_RAM_MB`

### Optional Features

- `ALLOW_ROOT_SSH`: `1` to allow root password SSH on team VMs
- `POOL_ID`: Proxmox pool to use or create
- `CLONE_FULL`: `1` for full clone, `0` for linked clone
- `WG_PORT`, `WG_ENDPOINT`: WireGuard settings
- `FRP_ENABLED`, `FRP_SERVER`, `FRP_PORT`, `FRP_VER`: FRP settings for the gateway

## How To Use

### 1. Prepare the environment

```bash
uv venv
uv pip install requests urllib3 proxmoxer python-dotenv jinja2
cp .env.example .env
```

Then edit `.env` with your real Proxmox and network values.

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

1. load configuration from `.env`
2. create a Proxmox pool if needed
3. build temporary cloud-init ISO files in a timestamped local directory
4. zip and include `data/checkers/` and `data/services/`
5. upload all generated ISOs to Proxmox storage
6. write a credentials file like `creds_YYYYMMDD_HHMMSS.json`
7. destroy any existing VMs using the configured VMIDs
8. clone new VMs from the template
9. configure CPU, memory, NICs, IP config, and attached cloud-init ISOs
10. start all VMs

## Output Files

Each run generates:

- a temporary local directory like `cloud-init_YYYYMMDD_HHMMSS/`
- a credentials file like `creds_YYYYMMDD_HHMMSS.json`

The credentials JSON contains generated passwords and addressing information for the deployed lab.

## Notes and Caveats

- The script destroys existing VMs that use the configured VMIDs before recreating them.
- If ISO uploads fail, the script stops before VM recreation completes.
- The Proxmox storage configured by `ISO_STORAGE` must support ISO uploads.
- If neither `genisoimage` nor `mkisofs` is installed, ISO creation fails.
- `uv run main.py` relies on the dependencies being installed into the current `uv` environment because this repo does not yet define them in a `pyproject.toml`.

## Troubleshooting

### Missing Python modules

Install dependencies with:

```bash
uv pip install requests urllib3 proxmoxer python-dotenv jinja2
```

### ISO upload errors

Check:

- `ISO_STORAGE` points to the correct Proxmox storage
- the storage has `ISO image` content enabled
- the API token has permission to allocate space on that storage

### Cloud-init ISO creation fails

Install `genisoimage`:

```bash
sudo apt-get install -y genisoimage
```

### TLS issues

If your Proxmox instance uses a self-signed certificate, set:

```dotenv
VERIFY_TLS=0
```

Use that only when appropriate for your environment.
