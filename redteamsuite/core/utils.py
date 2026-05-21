from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional


def make_timestamped_output_dir(base: Path, profile: str, target: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(":", "_").replace("/", "_")
    out = base / f"{profile}_{safe_target}_{stamp}"
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
