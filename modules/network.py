"""/31 point-to-point addressing helpers + misc network utilities."""
from __future__ import annotations

import secrets
import string


# ---------- /31 point-to-point helpers ----------

def team_vm_ip(team: int) -> str:
    """Team N VM address: 10.58.57.(2N-1)/31"""
    return f"10.58.57.{2 * team - 1}/31"


def team_gw_ip(team: int) -> str:
    """GW-side address for team N link: 10.58.57.(2N-2)/31"""
    return f"10.58.57.{2 * team - 2}/31"


def team_vm_addr(team: int) -> str:
    """Plain IP without mask for team VM."""
    return f"10.58.57.{2 * team - 1}"


def team_gw_addr(team: int) -> str:
    """Plain IP without mask for GW side of team link."""
    return f"10.58.57.{2 * team - 2}"


# ---------- password generation ----------

def random_password(length: int = 24) -> str:
    """Alphanumeric-only password (safe for serial console paste)."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))
