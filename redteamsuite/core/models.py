from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class HostProfile:
    target: str
    profile: str = "generic"
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now_iso)


@dataclass
class ServiceRecord:
    port: int
    protocol: str = "tcp"
    service: str = "unknown"
    banner: Optional[str] = None
    notes: List[str] = field(default_factory=list)


@dataclass
class CredentialRecord:
    username: str
    password: str
    role: Optional[str] = None
    source: Optional[str] = None
    valid_portal_login: Optional[bool] = None
    notes: List[str] = field(default_factory=list)


@dataclass
class SessionRecord:
    username: str
    role: Optional[str]
    cookie_file: str
    login_url: str
    valid: bool
    evidence_id: Optional[str] = None


@dataclass
class WebPathRecord:
    url: str
    status_code: int
    method: str = "GET"
    content_type: Optional[str] = None
    length: Optional[int] = None
    title: Optional[str] = None
    evidence_id: Optional[str] = None
    notes: List[str] = field(default_factory=list)


@dataclass
class UploadRecord:
    local_path: str
    upload_url: str
    stored_name: Optional[str] = None
    public_url: Optional[str] = None
    upload_status_code: Optional[int] = None
    accessible_status_code: Optional[int] = None
    executed_marker: Optional[bool] = None
    evidence_ids: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    target: str
    description: str
    impact: str
    remediation: str
    evidence_ids: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now_iso)
    metadata: Dict[str, Any] = field(default_factory=dict)


def to_jsonable(obj: Any) -> Any:
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    if isinstance(obj, list):
        return [to_jsonable(v) for v in obj]
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    return obj
