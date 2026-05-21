from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class DefaultProfile:
    """Profile-agnostic defaults used by the evidence-driven recon workflow.

    These are not project-specific assumptions. They are small, generic discovery
    seeds used only to bootstrap HTTP enumeration after network evidence has
    identified services on a manually selected target.
    """

    name: str = "default"
    common_paths: List[str] = field(default_factory=lambda: [
        "/",
        "/robots.txt",
        "/sitemap.xml",
        "/login",
        "/login.php",
        "/admin",
        "/dashboard",
        "/upload",
        "/uploads/",
        "/api/",
        "/data/",
        "/backup/",
        "/config/",
        "/.env",
    ])
    credential_keywords: List[str] = field(default_factory=lambda: [
        "password", "passwd", "pwd", "username", "user", "credential", "secret", "token", "api_key", "apikey"
    ])
    framework_header_keys: List[str] = field(default_factory=lambda: [
        "server", "x-powered-by", "x-generator", "x-runtime", "x-aspnet-version"
    ])


def get_profile(name: str = "default") -> DefaultProfile:
    return DefaultProfile(name=name or "default")
