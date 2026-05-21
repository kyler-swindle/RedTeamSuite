from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class DefaultProfile:
    """Profile-agnostic defaults for evidence-driven workflows.

    v0.5 intentionally keeps this profile small. Generic web content discovery
    should come from methodology/tooling such as gobuster, links, directory
    listings, robots/sitemaps discovered during probing, and prior JSON evidence
    rather than a project-specific embedded path checklist.
    """

    name: str = "default"
    seed_paths: List[str] = field(default_factory=lambda: ["/"])
    credential_keywords: List[str] = field(default_factory=lambda: [
        "password", "passwd", "pwd", "username", "user", "credential", "secret", "token", "api_key", "apikey"
    ])
    framework_header_keys: List[str] = field(default_factory=lambda: [
        "server", "x-powered-by", "x-generator", "x-runtime", "x-aspnet-version"
    ])

    @property
    def common_paths(self) -> List[str]:
        # Backward-compatible alias for older modules; deliberately tiny.
        return list(self.seed_paths)


def get_profile(name: str = "default") -> DefaultProfile:
    return DefaultProfile(name=name or "default")
