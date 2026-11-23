"""Fetch and validate the AD source used to build deployment payloads."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def _apply_overlay(source: Path, overlay: str | Path) -> None:
    """Copy a local overlay tree over the cloned AD source."""
    overlay_path = Path(overlay).resolve()
    if not overlay_path.is_dir():
        raise RuntimeError(f"AD overlay directory does not exist: {overlay_path}")
    shutil.copytree(overlay_path, source, dirs_exist_ok=True)


def fetch_ad_source(
    repository: str,
    ref: str,
    destination: str | Path,
    overlay: str | Path | None = None,
) -> Path:
    """Clone an AD repository ref and return its root directory.

    The repository (after the optional overlay is applied) must have
    ``services/``, ``checkers/``, and ``forcad_config.yml`` at its root.
    """
    if not repository.strip():
        raise ValueError("AD repository URL must not be empty")
    if not ref.strip():
        raise ValueError("AD repository ref must not be empty")

    root = Path(destination).resolve()
    if root.exists():
        raise FileExistsError(f"AD source destination already exists: {root}")

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", ref, "--", repository, str(root)],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("git is required to fetch the AD repository") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or str(exc)).strip()
        raise RuntimeError(f"Unable to clone AD repository ref {ref!r}: {detail}") from exc

    if overlay:
        _apply_overlay(root, overlay)

    required = (root / "services", root / "checkers", root / "forcad_config.yml")
    missing = [str(path.relative_to(root)) for path in required if not path.exists()]
    if missing:
        raise RuntimeError(
            "AD repository is missing required paths: " + ", ".join(missing)
        )
    if not any(path.is_file() for path in (root / "services").rglob("*")):
        raise RuntimeError("AD repository services/ directory contains no files")
    if not any(path.is_file() for path in (root / "checkers").rglob("*")):
        raise RuntimeError("AD repository checkers/ directory contains no files")

    return root
