from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class RuntimeConfig:
    target: Optional[str] = None
    profile: str = "default"
    output_dir: Optional[Path] = None
    run_id: Optional[str] = None
    http_port: int = 80
    nextjs_port: int = 3000
    timeout: float = 10.0
    allow_code_exec_validation: bool = False
    allow_upload_marker: bool = False
    allow_php_exec_marker: bool = False
    user_agent: str = "RedTeamSuite/0.5 evidence-first lab client"

    @property
    def base_http_url(self) -> str:
        if not self.target:
            raise ValueError("No target is configured for this run.")
        if self.http_port == 80:
            return f"http://{self.target}"
        return f"http://{self.target}:{self.http_port}"

    @property
    def base_nextjs_url(self) -> str:
        if not self.target:
            raise ValueError("No target is configured for this run.")
        return f"http://{self.target}:{self.nextjs_port}"
