from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import requests
from bs4 import BeautifulSoup

from redteamsuite.core.evidence_store import EvidenceStore


@dataclass
class HttpResult:
    method: str
    url: str
    status_code: int
    headers: Dict[str, str]
    text: str
    evidence_id: str
    final_url: str

    @property
    def content_type(self) -> Optional[str]:
        return self.headers.get("Content-Type")

    @property
    def title(self) -> Optional[str]:
        soup = BeautifulSoup(self.text, "html.parser")
        if soup.title and soup.title.string:
            return soup.title.string.strip()
        return None


class HttpClient:
    def __init__(self, evidence: EvidenceStore, timeout: float = 10.0, user_agent: str = "RedTeamSuite/0.1"):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        self.evidence = evidence
        self.timeout = timeout

    def get(self, url: str, *, allow_redirects: bool = True, cookies: Optional[Dict[str, str]] = None) -> HttpResult:
        resp = self.session.get(url, timeout=self.timeout, allow_redirects=allow_redirects, cookies=cookies)
        return self._record("GET", url, resp)

    def post(self, url: str, *, data: Optional[Dict[str, str]] = None, files=None, allow_redirects: bool = False) -> HttpResult:
        resp = self.session.post(url, data=data, files=files, timeout=self.timeout, allow_redirects=allow_redirects)
        return self._record("POST", url, resp)

    def _record(self, method: str, url: str, resp: requests.Response) -> HttpResult:
        text = resp.text
        evidence_id = self.evidence.save_http_response(method, url, resp.status_code, dict(resp.headers), text)
        return HttpResult(method, url, resp.status_code, dict(resp.headers), text, evidence_id, resp.url)

    def cookie_dict(self) -> Dict[str, str]:
        return self.session.cookies.get_dict()
