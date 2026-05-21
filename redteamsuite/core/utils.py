from __future__ import annotations

import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional


def safe_path_component(text: str) -> str:
    text = str(text or "").strip()
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", text)
    text = text.strip("._-")
    return text or "run"


def make_timestamped_output_dir(base: Path, profile: str, target: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = safe_path_component(target)
    out = base / f"{safe_path_component(profile)}_{safe_target}_{stamp}"
    out.mkdir(parents=True, exist_ok=True)
    return out


def resolve_output_dir(
    base: Path,
    *,
    profile: str,
    target: Optional[str] = None,
    run_id: Optional[str] = None,
    new_run: bool = False,
    force_overwrite: bool = False,
) -> Path:
    """Resolve the concrete run directory.

    Default behavior is append-safe: the same profile/target/run-id resolves to the same
    directory and existing JSON evidence is preserved by EvidenceStore.

    - --run-id NAME writes to <base>/<NAME>.
    - no --run-id writes to <base>/<profile>_<target> for target commands.
    - no --target writes to <base>/<profile>_network for network mapping.
    - --new-run appends a timestamp suffix.
    - --force-overwrite deletes the selected run directory before writing.
    """
    base = Path(base)
    if base.name.endswith(".json"):
        raise ValueError("--out must be a directory, not a JSON file")

    if run_id:
        name = safe_path_component(run_id)
    elif target:
        name = f"{safe_path_component(profile)}_{safe_path_component(target)}"
    else:
        name = f"{safe_path_component(profile)}_network"

    if new_run:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = f"{name}_{stamp}"

    out = base / name

    if force_overwrite and out.exists():
        shutil.rmtree(out)

    out.mkdir(parents=True, exist_ok=True)
    return out


def normalize_url(base: str, path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    if not path.startswith("/"):
        path = "/" + path
    return base.rstrip("/") + path


def extract_between(text: str, start: str, end: str) -> Optional[str]:
    i = text.find(start)
    if i < 0:
        return None
    i += len(start)
    j = text.find(end, i)
    if j < 0:
        return None
    return text[i:j]
