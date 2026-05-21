from __future__ import annotations

import json
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from redteamsuite.core.context import TargetContext
from redteamsuite.core.models import Finding, to_jsonable, utc_now_iso
from redteamsuite.profiles.default_profile import get_profile as get_default_profile

WEB_PORTS = {80, 443, 3000, 5000, 8000, 8080, 8443}
DIRECTORY_LISTING_MARKERS = (
    "Index of /",
    "<title>Index of",
    "Parent Directory",
    "Directory listing for",
)
CREDENTIAL_REGEXES = [
    re.compile(r"(?i)\b(?:user(?:name)?|login)\b\s*[:=]\s*[^\s<>'\"]+"),
    re.compile(r"(?i)\b(?:pass(?:word)?|passwd|pwd)\b\s*[:=]\s*[^\s<>'\"]+"),
    re.compile(r"(?i)\b(?:api[_-]?key|token|secret)\b\s*[:=]\s*[^\s<>'\"]+"),
    re.compile(r"^[A-Za-z0-9_.-]{2,}\s*[:|,]\s*[^\s:|,]{3,}", re.MULTILINE),
]


@dataclass
class HttpService:
    host: str
    port: int
    scheme: str
    base_url: str
    source: str
    evidence_id: Optional[str] = None
    status_code: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    x_powered_by: Optional[str] = None


class _LinkAndFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: List[str] = []
        self.forms: List[Dict[str, Any]] = []
        self._current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        tag_l = tag.lower()
        if tag_l in {"a", "link", "script"}:
            href = attr.get("href") or attr.get("src")
            if href:
                self.links.append(href)
        elif tag_l == "form":
            self._current_form = {
                "method": (attr.get("method") or "GET").upper(),
                "action": attr.get("action") or "",
                "fields": [],
                "has_password": False,
                "has_file": False,
            }
            self.forms.append(self._current_form)
        elif tag_l in {"input", "textarea", "select", "button"} and self._current_form is not None:
            field = {
                "tag": tag_l,
                "name": attr.get("name") or attr.get("id") or "",
                "type": (attr.get("type") or "text").lower(),
            }
            self._current_form["fields"].append(field)
            if field["type"] == "password":
                self._current_form["has_password"] = True
            if field["type"] == "file":
                self._current_form["has_file"] = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._current_form = None


class ReconWorkflow:
    """Default evidence-driven recon workflow.

    It consumes earlier JSON evidence where possible, probes discovered HTTP
    services for a manually selected target, derives surfaces/artifacts, and
    writes recommended next commands. It does not auto-run risky validation.
    """

    def __init__(self, ctx: TargetContext):
        self.ctx = ctx
        self.profile = get_default_profile(ctx.config.profile or "default")

    def run(self) -> Dict[str, Any]:
        target = self.ctx.config.target
        if not target:
            raise ValueError("Recon requires a manually selected target.")

        services = self._resolve_http_services(target)
        discovered_paths: List[Dict[str, Any]] = self._load_list("discovered_paths.json")
        content_artifacts: List[Dict[str, Any]] = self._load_list("content_artifacts.json")
        auth_surfaces: List[Dict[str, Any]] = self._load_list("auth_surfaces.json")
        upload_surfaces: List[Dict[str, Any]] = self._load_list("upload_surfaces.json")
        framework_fingerprints: List[Dict[str, Any]] = self._load_list("framework_fingerprints.json")

        seen_urls = {str(row.get("url")) for row in discovered_paths if isinstance(row, dict)}
        queued_paths = self._initial_paths()

        for service in services:
            base = service.base_url
            for path in queued_paths:
                url = urljoin(base.rstrip("/") + "/", path.lstrip("/")) if path != "/" else base.rstrip("/") + "/"
                if url in seen_urls:
                    continue
                row = self._probe_url(url, service)
                if row is None:
                    continue
                discovered_paths.append(row)
                seen_urls.add(url)

                # Add a small number of same-host links from successfully fetched HTML.
                for extra in self._extract_candidate_links(row, base):
                    if extra not in queued_paths and len(queued_paths) < 64:
                        queued_paths.append(extra)

        for row in discovered_paths:
            if not isinstance(row, dict):
                continue
            self._derive_from_path(row, content_artifacts, auth_surfaces, upload_surfaces, framework_fingerprints)

        discovered_paths = self._dedupe_records(discovered_paths, key_fields=("url",))
        content_artifacts = self._dedupe_records(content_artifacts, key_fields=("url", "artifact_type"))
        auth_surfaces = self._dedupe_records(auth_surfaces, key_fields=("url", "method"))
        upload_surfaces = self._dedupe_records(upload_surfaces, key_fields=("url", "method"))
        framework_fingerprints = self._dedupe_records(framework_fingerprints, key_fields=("service_url", "framework", "source"))

        self._emit_generic_findings(content_artifacts, auth_surfaces, upload_surfaces, framework_fingerprints)
        recommendations = self._build_recommendations(target, auth_surfaces, upload_surfaces, content_artifacts, framework_fingerprints)

        self.ctx.evidence.save_json("http_services.json", [s.__dict__ for s in services])
        self.ctx.evidence.save_json("discovered_paths.json", discovered_paths)
        self.ctx.evidence.save_json("content_artifacts.json", content_artifacts)
        self.ctx.evidence.save_json("auth_surfaces.json", auth_surfaces)
        self.ctx.evidence.save_json("upload_surfaces.json", upload_surfaces)
        self.ctx.evidence.save_json("framework_fingerprints.json", framework_fingerprints)
        self.ctx.evidence.save_json("recommended_next_steps.json", recommendations)
        self.ctx.evidence.flush()

        summary = {
            "schema": "redteamsuite.recon_summary.v1",
            "created_at": utc_now_iso(),
            "target": target,
            "http_services": len(services),
            "discovered_paths": len(discovered_paths),
            "content_artifacts": len(content_artifacts),
            "auth_surfaces": len(auth_surfaces),
            "upload_surfaces": len(upload_surfaces),
            "framework_fingerprints": len(framework_fingerprints),
            "recommended_next_steps": len(recommendations),
        }
        self.ctx.evidence.save_json("recon_summary.json", summary)
        self.ctx.logger.event("recon.end", "Default recon workflow complete", summary)
        return summary

    def _resolve_http_services(self, target: str) -> List[HttpService]:
        services_json = self.ctx.evidence.load_json("network_services.json", [])
        services: List[HttpService] = []
        if isinstance(services_json, list):
            for row in services_json:
                if not isinstance(row, dict) or str(row.get("host")) != str(target):
                    continue
                port = int(row.get("port") or 0)
                http = row.get("http") if isinstance(row.get("http"), dict) else {}
                hint = str(row.get("service_hint") or "").lower()
                if port in WEB_PORTS or http or "http" in hint or "next" in hint:
                    scheme = "https" if port in (443, 8443) else "http"
                    base_url = str(http.get("url") or (f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"))
                    services.append(HttpService(
                        host=target,
                        port=port,
                        scheme=scheme,
                        base_url=base_url.rstrip("/"),
                        source="network_services.json",
                        evidence_id=http.get("evidence_id"),
                        status_code=http.get("status_code"),
                        title=http.get("title"),
                        server=http.get("server"),
                        x_powered_by=http.get("x_powered_by"),
                    ))
        if not services:
            port = int(self.ctx.config.http_port or 80)
            scheme = "https" if port == 443 else "http"
            services.append(HttpService(
                host=target,
                port=port,
                scheme=scheme,
                base_url=self.ctx.config.base_http_url.rstrip("/"),
                source="fallback_http_port",
            ))
        return self._dedupe_services(services)

    def _initial_paths(self) -> List[str]:
        paths = list(self.profile.common_paths)
        # Use prior robots/sitemap/path discoveries if they exist.
        for row in self._load_list("discovered_paths.json"):
            if isinstance(row, dict) and row.get("path"):
                paths.append(str(row["path"]))
        return self._unique_paths(paths)

    def _probe_url(self, url: str, service: HttpService) -> Optional[Dict[str, Any]]:
        try:
            result = self.ctx.http.get(url, allow_redirects=False)
        except Exception as exc:
            self.ctx.logger.event("recon.http_error", f"GET failed: {url}", {"error": str(exc)})
            return None

        headers = dict(getattr(result, "headers", {}) or {})
        text = getattr(result, "text", "") or ""
        parsed = urlparse(url)
        title = self._extract_title(text)
        parser = _LinkAndFormParser()
        try:
            parser.feed(text[:250000])
        except Exception:
            pass
        row = {
            "schema": "redteamsuite.discovered_path.v1",
            "created_at": utc_now_iso(),
            "target": self.ctx.config.target,
            "service_url": service.base_url,
            "url": url,
            "path": parsed.path or "/",
            "status_code": getattr(result, "status_code", None),
            "content_type": headers.get("Content-Type") or headers.get("content-type"),
            "server": headers.get("Server") or headers.get("server"),
            "x_powered_by": headers.get("X-Powered-By") or headers.get("x-powered-by"),
            "location": headers.get("Location") or headers.get("location"),
            "title": title,
            "body_length": len(text),
            "body_sample": text[:500],
            "links": self._same_host_paths(parser.links, service.base_url),
            "forms": self._normalize_forms(parser.forms, url),
            "evidence_id": getattr(result, "evidence_id", None),
            "source": "recon_http_probe",
        }
        return row

    def _derive_from_path(
        self,
        row: Dict[str, Any],
        artifacts: List[Dict[str, Any]],
        auth_surfaces: List[Dict[str, Any]],
        upload_surfaces: List[Dict[str, Any]],
        fingerprints: List[Dict[str, Any]],
    ) -> None:
        url = str(row.get("url") or "")
        body = str(row.get("body_sample") or "")
        title = str(row.get("title") or "")
        status = int(row.get("status_code") or 0)
        headers = {
            "server": row.get("server"),
            "x_powered_by": row.get("x_powered_by"),
            "content_type": row.get("content_type"),
        }
        evidence_ids = [row.get("evidence_id")] if row.get("evidence_id") else []

        if status in {200, 301, 302, 401, 403}:
            lower_path = str(row.get("path") or "").lower()
            if self._looks_directory_listing(title, body):
                artifacts.append(self._artifact(row, "directory_listing", "high", ["Directory listing markers observed"]))
            if self._looks_credential_like(url, body):
                artifacts.append(self._artifact(row, "credential_like", "medium", ["Credential-like keywords or delimiter patterns observed"]))
            if any(piece in lower_path for piece in ("backup", ".bak", ".old", "dump", "archive")):
                artifacts.append(self._artifact(row, "backup_like", "medium", ["Backup/archive-like path name observed"]))
            if any(piece in lower_path for piece in ("config", ".env", "settings")):
                artifacts.append(self._artifact(row, "config_like", "medium", ["Config-like path name observed"]))
            if any(piece in lower_path for piece in ("log", "logs")):
                artifacts.append(self._artifact(row, "log_like", "low", ["Log-like path name observed"]))

        for form in row.get("forms") or []:
            if not isinstance(form, dict):
                continue
            fields = form.get("fields") or []
            names = " ".join(str(f.get("name") or "") + " " + str(f.get("type") or "") for f in fields if isinstance(f, dict)).lower()
            action_url = str(form.get("action_url") or url)
            method = str(form.get("method") or "GET").upper()
            if form.get("has_password") or ("password" in names and any(k in names for k in ("user", "login", "email"))):
                auth_surfaces.append({
                    "schema": "redteamsuite.auth_surface.v1",
                    "created_at": utc_now_iso(),
                    "target": self.ctx.config.target,
                    "url": action_url,
                    "source_page": url,
                    "method": method,
                    "fields": fields,
                    "confidence": "high" if form.get("has_password") else "medium",
                    "reasons": ["HTML form contains password field" if form.get("has_password") else "HTML form resembles login/auth surface"],
                    "source_evidence_ids": evidence_ids,
                })
            if form.get("has_file") or "file" in names or "upload" in action_url.lower():
                upload_surfaces.append({
                    "schema": "redteamsuite.upload_surface.v1",
                    "created_at": utc_now_iso(),
                    "target": self.ctx.config.target,
                    "url": action_url,
                    "source_page": url,
                    "method": method,
                    "fields": fields,
                    "file_fields": [f for f in fields if isinstance(f, dict) and f.get("type") == "file"],
                    "confidence": "high" if form.get("has_file") else "medium",
                    "reasons": ["HTML form contains file input" if form.get("has_file") else "Upload-like form/action observed"],
                    "source_evidence_ids": evidence_ids,
                })

        for source, value in headers.items():
            val = str(value or "")
            if not val:
                continue
            framework = self._classify_framework(val)
            if framework:
                fingerprints.append({
                    "schema": "redteamsuite.framework_fingerprint.v1",
                    "created_at": utc_now_iso(),
                    "target": self.ctx.config.target,
                    "service_url": row.get("service_url"),
                    "url": url,
                    "framework": framework,
                    "source": source,
                    "value": val,
                    "confidence": "medium",
                    "source_evidence_ids": evidence_ids,
                })

    def _artifact(self, row: Dict[str, Any], artifact_type: str, confidence: str, reasons: List[str]) -> Dict[str, Any]:
        return {
            "schema": "redteamsuite.content_artifact.v1",
            "created_at": utc_now_iso(),
            "target": self.ctx.config.target,
            "url": row.get("url"),
            "path": row.get("path"),
            "artifact_type": artifact_type,
            "status_code": row.get("status_code"),
            "content_type": row.get("content_type"),
            "confidence": confidence,
            "reasons": reasons,
            "source_evidence_ids": [row.get("evidence_id")] if row.get("evidence_id") else [],
        }

    def _emit_generic_findings(
        self,
        artifacts: List[Dict[str, Any]],
        auth_surfaces: List[Dict[str, Any]],
        upload_surfaces: List[Dict[str, Any]],
        fingerprints: List[Dict[str, Any]],
    ) -> None:
        for artifact in artifacts:
            typ = artifact.get("artifact_type")
            if typ == "directory_listing":
                self._append_finding(
                    finding_type="WEB_DIRECTORY_LISTING",
                    title="Directory listing exposed",
                    severity="Medium",
                    target=str(artifact.get("url")),
                    description="An HTTP path appears to expose a directory listing.",
                    impact="Directory listings can reveal sensitive files, backups, logs, and application structure.",
                    remediation="Disable directory indexing and restrict access to sensitive paths.",
                    evidence_ids=artifact.get("source_evidence_ids") or [],
                )
            elif typ == "credential_like":
                self._append_finding(
                    finding_type="WEB_CREDENTIAL_LIKE_CONTENT",
                    title="Credential-like content exposed over HTTP",
                    severity="High",
                    target=str(artifact.get("url")),
                    description="A fetched HTTP resource contains keywords or delimiter patterns that resemble credentials or secrets.",
                    impact="Exposed credentials may enable authenticated access or further compromise.",
                    remediation="Remove secrets from web-accessible locations and rotate any exposed credentials.",
                    evidence_ids=artifact.get("source_evidence_ids") or [],
                )
            elif typ in {"backup_like", "config_like"}:
                self._append_finding(
                    finding_type=f"WEB_{str(typ).upper()}_RESOURCE",
                    title=f"{typ.replace('_', ' ').title()} HTTP resource discovered",
                    severity="Medium",
                    target=str(artifact.get("url")),
                    description="A web-accessible path resembles a backup, config, or deployment artifact.",
                    impact="Such artifacts may expose source code, credentials, or operational details.",
                    remediation="Keep backup/config files outside the web root and restrict access.",
                    evidence_ids=artifact.get("source_evidence_ids") or [],
                )

        for surface in auth_surfaces:
            self._append_finding(
                finding_type="WEB_AUTH_SURFACE_DISCOVERED",
                title="Authentication surface discovered",
                severity="Info",
                target=str(surface.get("url")),
                description="A login/authentication-like HTML form was discovered.",
                impact="This is a recon finding that can guide authorized authentication testing.",
                remediation="Ensure authentication surfaces enforce strong credential policy, rate limiting, and secure session handling.",
                evidence_ids=surface.get("source_evidence_ids") or [],
            )

        for surface in upload_surfaces:
            self._append_finding(
                finding_type="WEB_UPLOAD_SURFACE_DISCOVERED",
                title="Upload surface discovered",
                severity="Info",
                target=str(surface.get("url")),
                description="A file-upload-like HTML form was discovered.",
                impact="This is a recon finding that can guide authorized upload validation.",
                remediation="Validate file type/content, store uploads safely, and prevent uploaded code execution.",
                evidence_ids=surface.get("source_evidence_ids") or [],
            )

        for fp in fingerprints:
            if str(fp.get("framework") or "").lower() in {"next.js", "node.js", "php", "apache", "nginx"}:
                self._append_finding(
                    finding_type="WEB_FRAMEWORK_FINGERPRINT",
                    title="Web framework/server fingerprint observed",
                    severity="Info",
                    target=str(fp.get("service_url") or fp.get("url")),
                    description=f"Observed framework/server indicator: {fp.get('framework')} via {fp.get('source')}.",
                    impact="Framework fingerprints help select relevant follow-up modules and manual review paths.",
                    remediation="Avoid exposing unnecessary version details and keep frameworks patched.",
                    evidence_ids=fp.get("source_evidence_ids") or [],
                )

    def _append_finding(self, *, finding_type: str, title: str, severity: str, target: str, description: str, impact: str, remediation: str, evidence_ids: List[Any]) -> None:
        finding = Finding(
            id=finding_type,
            title=title,
            severity=severity,
            target=target,
            description=description,
            impact=impact,
            remediation=remediation,
            evidence_ids=[str(e) for e in evidence_ids if e],
        )
        data = to_jsonable(finding)
        if not isinstance(data, dict):
            data = {"id": finding_type, "target": target, "title": title, "severity": severity}
        data["finding_type"] = finding_type
        data["metadata"] = {
            "schema": "redteamsuite.finding.v2",
            "legacy_id": None,
            "affected_resource": target,
            "first_seen": data.get("created_at") or utc_now_iso(),
            "last_seen": data.get("created_at") or utc_now_iso(),
            "occurrence_count": 1,
        }
        self.ctx.evidence.findings.append(data)

    def _build_recommendations(
        self,
        target: str,
        auth_surfaces: List[Dict[str, Any]],
        upload_surfaces: List[Dict[str, Any]],
        artifacts: List[Dict[str, Any]],
        fingerprints: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        base = f"python -m redteamsuite.cli.rts"
        profile = self.ctx.config.profile or "default"
        common = f"--target {target} --profile {profile} --out {self._shell_quote(str(self.ctx.evidence.output_dir.parent))}"
        if self.ctx.config.run_id:
            common += f" --run-id {self._shell_quote(self.ctx.config.run_id)}"
        is_project_profile = profile.lower() in {"project3", "p3"}

        credential_like = [a for a in artifacts if a.get("artifact_type") == "credential_like"]
        if auth_surfaces and credential_like:
            out.append({
                "priority": "high",
                "category": "auth_testing",
                "reason": "Authentication surface and credential-like content were both discovered. Review the artifact before attempting login validation.",
                "evidence_inputs": {
                    "auth_surfaces": [s.get("url") for s in auth_surfaces[:5]],
                    "credential_like_artifacts": [a.get("url") for a in credential_like[:5]],
                },
                "suggested_command": (
                    f"{base} portal-test {common}" if is_project_profile
                    else f"cat {self._shell_quote(str(self.ctx.evidence.output_dir / 'auth_surfaces.json'))} && cat {self._shell_quote(str(self.ctx.evidence.output_dir / 'content_artifacts.json'))}"
                ),
                "requires_manual_review": True,
            })
        elif auth_surfaces:
            out.append({
                "priority": "medium",
                "category": "auth_review",
                "reason": "Authentication-like surfaces were discovered.",
                "evidence_inputs": {"auth_surfaces": [s.get("url") for s in auth_surfaces[:5]]},
                "suggested_command": f"cat {self._shell_quote(str(self.ctx.evidence.output_dir / 'auth_surfaces.json'))}",
                "requires_manual_review": True,
            })

        if upload_surfaces:
            out.append({
                "priority": "medium",
                "category": "upload_validation",
                "reason": "Upload-like surfaces were discovered. Run only benign upload marker validation unless explicitly authorized for stronger checks.",
                "evidence_inputs": {"upload_surfaces": [s.get("url") for s in upload_surfaces[:5]]},
                "suggested_command": (
                    f"{base} upload-test {common} --allow-upload-marker" if is_project_profile
                    else f"cat {self._shell_quote(str(self.ctx.evidence.output_dir / 'upload_surfaces.json'))}"
                ),
                "requires_manual_review": True,
            })

        nextjs = [f for f in fingerprints if str(f.get("framework") or "").lower() == "next.js"]
        if nextjs:
            port = self._port_from_url(str(nextjs[0].get("service_url") or "")) or 3000
            out.append({
                "priority": "medium",
                "category": "framework_specific_review",
                "reason": "Next.js fingerprint observed. Consider framework-specific checks only after confirming the app exposes a relevant diagnostic/eval surface.",
                "evidence_inputs": {"framework_fingerprints": [f.get("service_url") for f in nextjs[:5]]},
                "suggested_command": (
                    f"{base} nextjs-test {common} --port {port}  # add --allow-code-exec-validation only when explicitly authorized" if is_project_profile
                    else f"cat {self._shell_quote(str(self.ctx.evidence.output_dir / 'framework_fingerprints.json'))}"
                ),
                "requires_manual_review": True,
            })

        if not out:
            out.append({
                "priority": "low",
                "category": "manual_review",
                "reason": "No high-confidence auth/upload/framework next step was derived. Review discovered paths and content artifacts.",
                "suggested_command": f"cat {self._shell_quote(str(self.ctx.evidence.output_dir / 'discovered_paths.json'))}",
                "requires_manual_review": True,
            })
        return out

    def _load_list(self, filename: str) -> List[Any]:
        data = self.ctx.evidence.load_json(filename, [])
        return data if isinstance(data, list) else []

    def _extract_candidate_links(self, row: Dict[str, Any], base_url: str) -> List[str]:
        out: List[str] = []
        for path in row.get("links") or []:
            if isinstance(path, str) and path.startswith("/") and len(path) <= 120:
                out.append(path)
        if str(row.get("path") or "").endswith("robots.txt"):
            sample = str(row.get("body_sample") or "")
            for match in re.finditer(r"(?im)^\s*(?:allow|disallow|sitemap)\s*:\s*(\S+)", sample):
                val = match.group(1).strip()
                if val.startswith("http"):
                    parsed = urlparse(val)
                    out.append(parsed.path or "/")
                elif val.startswith("/"):
                    out.append(val)
        return self._unique_paths(out)

    @staticmethod
    def _same_host_paths(links: Iterable[str], base_url: str) -> List[str]:
        base_host = urlparse(base_url).netloc
        out: List[str] = []
        for link in links:
            if not link or link.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            abs_url = urljoin(base_url.rstrip("/") + "/", link)
            parsed = urlparse(abs_url)
            if parsed.netloc == base_host:
                out.append(parsed.path or "/")
        return ReconWorkflow._unique_paths(out)

    @staticmethod
    def _normalize_forms(forms: List[Dict[str, Any]], page_url: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for form in forms:
            action = str(form.get("action") or "")
            normalized = dict(form)
            normalized["action_url"] = urljoin(page_url, action) if action else page_url
            out.append(normalized)
        return out

    @staticmethod
    def _extract_title(text: str) -> Optional[str]:
        match = re.search(r"(?is)<title[^>]*>(.*?)</title>", text or "")
        if not match:
            return None
        return re.sub(r"\s+", " ", match.group(1)).strip()[:200]

    @staticmethod
    def _looks_directory_listing(title: str, body: str) -> bool:
        haystack = f"{title}\n{body}"
        return any(marker.lower() in haystack.lower() for marker in DIRECTORY_LISTING_MARKERS)

    @staticmethod
    def _looks_credential_like(url: str, body: str) -> bool:
        lower_url = url.lower()
        if any(piece in lower_url for piece in ("users", "creds", "credentials", "password", "passwd", "secret", "token")):
            if any(rx.search(body or "") for rx in CREDENTIAL_REGEXES):
                return True
        return any(rx.search(body or "") for rx in CREDENTIAL_REGEXES[:3])

    @staticmethod
    def _classify_framework(value: str) -> Optional[str]:
        lower = value.lower()
        if "next" in lower:
            return "Next.js"
        if "express" in lower or "node" in lower:
            return "Node.js"
        if "php" in lower:
            return "PHP"
        if "apache" in lower:
            return "Apache"
        if "nginx" in lower:
            return "nginx"
        if "django" in lower:
            return "Django"
        if "flask" in lower or "werkzeug" in lower:
            return "Flask/Werkzeug"
        return None

    @staticmethod
    def _dedupe_services(services: List[HttpService]) -> List[HttpService]:
        seen: Set[Tuple[str, int, str]] = set()
        out: List[HttpService] = []
        for service in services:
            key = (service.host, service.port, service.base_url)
            if key in seen:
                continue
            seen.add(key)
            out.append(service)
        return out

    @staticmethod
    def _dedupe_records(records: List[Dict[str, Any]], *, key_fields: Tuple[str, ...]) -> List[Dict[str, Any]]:
        seen: Dict[Tuple[str, ...], Dict[str, Any]] = {}
        order: List[Tuple[str, ...]] = []
        for record in records:
            if not isinstance(record, dict):
                continue
            key = tuple(str(record.get(field) or "") for field in key_fields)
            if key not in seen:
                seen[key] = record
                order.append(key)
            else:
                existing = seen[key]
                for list_key in ("source_evidence_ids", "reasons"):
                    if list_key in record or list_key in existing:
                        existing[list_key] = ReconWorkflow._unique_values(list(existing.get(list_key) or []) + list(record.get(list_key) or []))
                existing["last_seen"] = utc_now_iso()
        return [seen[key] for key in order]

    @staticmethod
    def _unique_values(values: List[Any]) -> List[Any]:
        out: List[Any] = []
        seen: Set[str] = set()
        for value in values:
            marker = json.dumps(value, sort_keys=True, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)
            if marker in seen:
                continue
            seen.add(marker)
            out.append(value)
        return out

    @staticmethod
    def _unique_paths(paths: Iterable[str]) -> List[str]:
        out: List[str] = []
        seen: Set[str] = set()
        for path in paths:
            if not path:
                continue
            path = str(path).strip()
            if not path:
                continue
            if path.startswith("http"):
                path = urlparse(path).path or "/"
            if not path.startswith("/"):
                path = "/" + path
            if path in seen:
                continue
            seen.add(path)
            out.append(path)
        return out

    @staticmethod
    def _port_from_url(url: str) -> Optional[int]:
        try:
            parsed = urlparse(url)
            if parsed.port:
                return parsed.port
            if parsed.scheme == "https":
                return 443
            if parsed.scheme == "http":
                return 80
        except Exception:
            return None
        return None

    @staticmethod
    def _shell_quote(value: str) -> str:
        if re.fullmatch(r"[A-Za-z0-9_./:-]+", value):
            return value
        return "'" + value.replace("'", "'\\''") + "'"
