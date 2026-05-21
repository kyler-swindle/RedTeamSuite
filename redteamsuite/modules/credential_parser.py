from __future__ import annotations

from typing import List

from redteamsuite.core.models import CredentialRecord


class CredentialParser:
    @staticmethod
    def parse_colon_credentials(text: str, *, source: str) -> List[CredentialRecord]:
        records: List[CredentialRecord] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 2:
                continue
            username = parts[0].strip()
            password = parts[1].strip()
            role = parts[2].strip() if len(parts) >= 3 and parts[2].strip() else None
            records.append(CredentialRecord(username=username, password=password, role=role, source=source))
        return records
