from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class RuntimeConfig:
    target: str
    profile: str = "generic"
    output_dir: Optional[Path] = None
    http_port: int = 80
    nextjs_port: int = 3000
    timeout: float = 10.0
    allow_code_exec_validation: bool = False
    allow_upload_marker: bool = False
    user_agent: str = "RedTeamSuite/0.1 evidence-first lab client"

    @property
    def base_http_url(self) -> str:
        if self.http_port == 80:
            return f"http://{self.target}"
        return f"http://{self.target}:{self.http_port}"

    @property
    def base_nextjs_url(self) -> str:
        return f"http://{self.target}:{self.nextjs_port}"
