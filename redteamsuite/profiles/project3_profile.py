from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class Project3Profile:
    name: str = "project3"
    default_http_port: int = 80
    default_nextjs_port: int = 3000
    common_paths: List[str] = field(default_factory=lambda: [
        "/",
        "/index.php",
        "/robots.txt",
        "/login.php",
        "/data/",
        "/data/users.txt",
        "/data/uploads.txt",
        "/uploads/",
        "/admin/",
        "/dashboard.php",
        "/upload.php",
    ])
    login_path: str = "/login.php"
    dashboard_path: str = "/dashboard.php"
    admin_path: str = "/admin/index.php"
    upload_path: str = "/upload.php"
    data_users_path: str = "/data/users.txt"
    data_uploads_path: str = "/data/uploads.txt"
    uploads_path: str = "/uploads/"
    login_username_field: str = "username"
    login_password_field: str = "password"
    nextjs_dashboard_path: str = "/dashboard"


PROFILES: Dict[str, Project3Profile] = {
    "project3": Project3Profile(),
}


def get_profile(name: str) -> Project3Profile:
    try:
        return PROFILES[name]
    except KeyError as exc:
        raise ValueError(f"Unknown profile: {name}. Available: {', '.join(PROFILES)}") from exc
