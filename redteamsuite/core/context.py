from __future__ import annotations

from dataclasses import dataclass

from redteamsuite.core.config import RuntimeConfig
from redteamsuite.core.evidence_store import EvidenceStore
from redteamsuite.core.http_client import HttpClient
from redteamsuite.core.run_logger import RunLogger


@dataclass
class TargetContext:
    config: RuntimeConfig
    evidence: EvidenceStore
    logger: RunLogger
    http: HttpClient
