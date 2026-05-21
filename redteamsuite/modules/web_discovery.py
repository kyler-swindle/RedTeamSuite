from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from redteamsuite.core.context import TargetContext
from redteamsuite.core.models import utc_now_iso
from redteamsuite.modules.recon import ReconWorkflow, _LinkAndFormParser

WEB_PORTS = {80, 443, 3000, 5000, 8000, 8080, 8443}
USEFUL_STATUSES = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403}
DEFAULT_WORDLIST_CANDIDATES = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
]
DIRECTORY_LISTING_MARKERS = (
    "Index of /",
    "<title>Index of",
    "Parent Directory",
    "Directory listing for",
)


@dataclass(frozen=True)
class WebServiceTarget:
    base_url: str
    host: str
    port: int
    source: str


class WebDiscoverer:
    """Tool-backed web content discovery.

    v0.5 intentionally delegates directory/content brute discovery to gobuster
    when available instead of baking large path lists into RedTeamSuite. The
    suite stores raw output, normalizes discoveries to JSON, fetches/classifies
    discovered URLs, expands directory listings, and then lets ReconWorkflow
    derive surfaces/recommendations from the accumulated evidence.
    """

    def __init__(self, ctx: TargetContext):
        self.ctx = ctx

    def run(
        self,
        *,
        target: str,
        engine: str = "auto",
        wordlist: Optional[str] = None,
        extensions: str = "php,txt,html,js,bak,old",
        status_codes: str = "200,204,301,302,307,308,401,403",
        threads: int = 50,
        gobuster_timeout: str = "10s",
        ports: Optional[List[int]] = None,
        service_urls: Optional[List[str]] = None,
        crawl_depth: int = 1,
        use_discovered_services: bool = True,
    ) -> Dict[str, Any]:
        services = self._resolve_services(target, ports=ports, service_urls=service_urls, use_discovered_services=use_discovered_services)
        if not services:
            raise ValueError("No HTTP service URLs available. Run net-map first or pass --service-url.")

        selected_engine = self._select_engine(engine)
        resolved_wordlist = self._resolve_wordlist(wordlist) if selected_engine == "gobuster" else wordlist
        if selected_engine == "gobuster" and not resolved_wordlist:
            raise SystemExit(
                "No gobuster wordlist found. Pass --wordlist, e.g. "
                "/usr/share/wordlists/dirb/common.txt. RedTeamSuite does not bundle large wordlists."
            )

        print(f"web-discover: scanning {len(services)} HTTP service(s) with engine={selected_engine}.")
        if selected_engine == "gobuster":
            print("Runtime warning: gobuster runtime depends on wordlist size, extensions, and service response speed.")
            print("Press Ctrl+C to stop; raw/partial output is preserved when possible.")

        discovery_runs: List[Dict[str, Any]] = []
        discovered_paths = self._load_list("discovered_paths.json")
        seen_urls = {str(row.get("url")) for row in discovered_paths if isinstance(row, dict) and row.get("url")}

        for service in services:
            if selected_engine == "gobuster":
                run = self._run_gobuster(
                    service,
                    wordlist=str(resolved_wordlist),
                    extensions=extensions,
                    status_codes=status_codes,
                    threads=threads,
                    gobuster_timeout=gobuster_timeout,
                )
            else:
                run = self._run_native(service, wordlist=wordlist, extensions=extensions, status_codes=status_codes)
            discovery_runs.append(run)

            for item in run.get("results", []):
                url = str(item.get("url") or "")
                if not url or url in seen_urls:
                    continue
                row = self._fetch_url(url, service, source=f"web_discover_{selected_engine}", source_metadata=item)
                if row:
                    discovered_paths.append(row)
                    seen_urls.add(url)

                    # Bounded, evidence-driven expansion from links and directory listings.
                    for child_url in self._child_urls_from_row(row, depth_remaining=crawl_depth):
                        if child_url in seen_urls:
                            continue
                        child_row = self._fetch_url(child_url, service, source="web_discover_child_expansion", source_metadata={"parent_url": url})
                        if child_row:
                            discovered_paths.append(child_row)
                            seen_urls.add(child_url)

        gobuster_result_count = sum(len(run.get("results", []) or []) for run in discovery_runs)
        failed_runs = [run for run in discovery_runs if run.get("success") is False]
        failed_run_count = len(failed_runs)
        if discovery_runs and failed_run_count == len(discovery_runs):
            discovery_status = "failed"
        elif failed_run_count:
            discovery_status = "partial"
        else:
            discovery_status = "ok"

        discovered_paths = ReconWorkflow._dedupe_records(discovered_paths, key_fields=("url",))
        self.ctx.evidence.save_json("discovered_paths.json", discovered_paths)
        self.ctx.evidence.save_json("web_discovery.json", {
            "schema": "redteamsuite.web_discovery.v1",
            "created_at": utc_now_iso(),
            "target": target,
            "engine": selected_engine,
            "wordlist": str(resolved_wordlist) if resolved_wordlist else wordlist,
            "extensions": extensions,
            "status_codes": status_codes,
            "services": [s.__dict__ for s in services],
            "runs": discovery_runs,
            "status": discovery_status,
            "failed_runs": failed_run_count,
            "gobuster_result_count": gobuster_result_count,
            "discovered_path_count": len(discovered_paths),
        })

        # Re-run bounded recon derivation over accumulated discovered_paths so
        # content_artifacts/auth_surfaces/upload_surfaces/recommendations snowball.
        summary = ReconWorkflow(self.ctx).run()
        return {
            "schema": "redteamsuite.web_discovery_summary.v1",
            "created_at": utc_now_iso(),
            "target": target,
            "engine": selected_engine,
            "status": discovery_status,
            "services_scanned": len(services),
            "discovery_runs": len(discovery_runs),
            "failed_runs": failed_run_count,
            "gobuster_result_count": gobuster_result_count,
            "discovered_paths": len(discovered_paths),
            "error_summaries": [run.get("error_summary") for run in failed_runs if run.get("error_summary")],
            "recon_summary": summary,
        }

    def _select_engine(self, engine: str) -> str:
        engine = (engine or "auto").lower().strip()
        if engine not in {"auto", "gobuster", "native"}:
            raise ValueError("engine must be auto, gobuster, or native")
        if engine == "native":
            return "native"
        if shutil.which("gobuster"):
            return "gobuster"
        if engine == "gobuster":
            raise SystemExit("gobuster was requested but is not installed or not in PATH.")
        raise SystemExit("gobuster is not installed/in PATH. Install gobuster or rerun with --engine native --wordlist <file>.")

    def _resolve_wordlist(self, wordlist: Optional[str]) -> Optional[Path]:
        candidates = [wordlist] if wordlist else DEFAULT_WORDLIST_CANDIDATES
        for candidate in candidates:
            if not candidate:
                continue
            path = Path(candidate).expanduser()
            if path.exists() and path.is_file():
                return path
        return None

    def _gobuster_json_supported(self) -> bool:
        try:
            proc = subprocess.run(["gobuster", "dir", "--help"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        except Exception:
            return False
        text = proc.stdout or ""
        # Support varies across gobuster releases. Only try JSON when help makes
        # a JSON/format flag obvious so we do not waste a full scan attempt.
        return ("--format" in text or "-f," in text) and "json" in text.lower()

    def _run_gobuster(self, service: WebServiceTarget, *, wordlist: str, extensions: str, status_codes: str, threads: int, gobuster_timeout: str) -> Dict[str, Any]:
        json_supported = self._gobuster_json_supported()
        cmd = [
            "gobuster", "dir",
            "-u", service.base_url.rstrip("/") + "/",
            "-w", wordlist,
            "-t", str(threads),
            "--timeout", str(gobuster_timeout),
        ]
        if status_codes:
            # Gobuster 3.x sets status-codes-blacklist=404 by default.
            # It refuses to run if an allowlist (-s) and blacklist are both set,
            # so clear the default blacklist explicitly.
            cmd += ["-s", status_codes, "-b", ""]
        if extensions:
            cmd += ["-x", extensions]
        if json_supported:
            cmd += ["--format", "json"]

        print("web-discover: running:", " ".join(self._quote_piece(c) for c in cmd))
        stdout, stderr, returncode, interrupted = self._run_streaming(cmd, stream_to_console=not json_supported)
        raw = stdout + (("\nSTDERR:\n" + stderr) if stderr else "")
        evidence_id = self.ctx.evidence.save_text_evidence(
            "gobuster",
            f"gobuster_{service.host}_{service.port}_{'json' if json_supported else 'text'}.txt",
            raw,
        )

        error_summary = self._summarize_gobuster_error(stderr, returncode, interrupted)

        mode = "json" if json_supported else "text"
        results = self._parse_gobuster_json(stdout, service) if json_supported else []
        if json_supported and not results and returncode != 0:
            # If a version advertised JSON oddly but rejected the flag, do one
            # real text-mode run rather than silently losing discovery.
            fallback_cmd = [c for c in cmd if c not in {"--format", "json"}]
            print("web-discover: JSON output was not usable; falling back to standard gobuster text output.")
            stdout2, stderr2, returncode2, interrupted2 = self._run_streaming(fallback_cmd, stream_to_console=True)
            raw2 = stdout2 + (("\nSTDERR:\n" + stderr2) if stderr2 else "")
            evidence_id2 = self.ctx.evidence.save_text_evidence("gobuster", f"gobuster_{service.host}_{service.port}_text_fallback.txt", raw2)
            fallback_results = self._parse_gobuster_text(stdout2 + "\n" + stderr2, service)
            fallback_error = self._summarize_gobuster_error(stderr2, returncode2, interrupted2)
            return {
                "schema": "redteamsuite.gobuster_run.v1",
                "created_at": utc_now_iso(),
                "service_url": service.base_url,
                "engine": "gobuster",
                "mode": "text_fallback",
                "command": fallback_cmd,
                "returncode": returncode2,
                "interrupted": interrupted2,
                "success": bool(returncode2 == 0 or fallback_results),
                "error_summary": fallback_error,
                "stderr_sample": (stderr2 or "")[:2000],
                "raw_evidence_id": evidence_id2,
                "results": fallback_results,
            }

        if not results:
            results = self._parse_gobuster_text(stdout + "\n" + stderr, service)
            mode = "text_parse_fallback" if json_supported else mode

        return {
            "schema": "redteamsuite.gobuster_run.v1",
            "created_at": utc_now_iso(),
            "service_url": service.base_url,
            "engine": "gobuster",
            "mode": mode,
            "command": cmd,
            "returncode": returncode,
            "interrupted": interrupted,
            "success": bool(returncode == 0 or results),
            "error_summary": error_summary,
            "stderr_sample": (stderr or "")[:2000],
            "raw_evidence_id": evidence_id,
            "results": results,
        }

    @staticmethod
    def _summarize_gobuster_error(stderr: str, returncode: int, interrupted: bool) -> Optional[str]:
        if interrupted:
            return "Gobuster was interrupted; partial output may have been preserved."
        if returncode == 0:
            return None
        text = (stderr or "").strip()
        if not text:
            return f"Gobuster exited with return code {returncode}."
        one_line = " ".join(text.split())
        if "status-codes" in one_line and "status-codes-blacklist" in one_line:
            return "Gobuster status-code allowlist conflicted with the default blacklist. v0.5.1 clears the blacklist with -b ''."
        return one_line[:500]

    def _run_streaming(self, cmd: List[str], *, stream_to_console: bool) -> Tuple[str, str, int, bool]:
        out_parts: List[str] = []
        err_parts: List[str] = []
        interrupted = False
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                out_parts.append(line)
                if stream_to_console:
                    print(line, end="")
            stderr = proc.stderr.read() if proc.stderr is not None else ""
            if stderr:
                err_parts.append(stderr)
            code = proc.wait()
        except KeyboardInterrupt:
            interrupted = True
            proc.terminate()
            try:
                code = proc.wait(timeout=5)
            except Exception:
                proc.kill()
                code = proc.wait()
            print("\nweb-discover: interrupted; preserving partial gobuster output.")
        return "".join(out_parts), "".join(err_parts), code, interrupted

    def _parse_gobuster_json(self, text: str, service: WebServiceTarget) -> List[Dict[str, Any]]:
        if not text.strip():
            return []
        values: List[Any] = []
        try:
            values = [json.loads(text)]
        except Exception:
            for line in text.splitlines():
                line = line.strip()
                if not line or not line.startswith(("{", "[")):
                    continue
                try:
                    values.append(json.loads(line))
                except Exception:
                    continue
        out: List[Dict[str, Any]] = []
        def walk(obj: Any) -> None:
            if isinstance(obj, list):
                for x in obj:
                    walk(x)
            elif isinstance(obj, dict):
                path = obj.get("path") or obj.get("url") or obj.get("result")
                status = obj.get("status") or obj.get("status_code")
                if path:
                    out.append(self._normalize_result(str(path), service, status=status, raw=obj))
                for key in ("results", "found", "items"):
                    if key in obj:
                        walk(obj[key])
        for value in values:
            walk(value)
        return self._dedupe_results(out)

    def _parse_gobuster_text(self, text: str, service: WebServiceTarget) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        # Typical: /login.php (Status: 200) [Size: 1234] [--> /login.php]
        rx = re.compile(r"(?m)^\s*(/\S*)\s+\(Status:\s*(\d{3})\)(.*)$")
        for match in rx.finditer(text or ""):
            path = match.group(1).strip()
            status = int(match.group(2))
            rest = match.group(3) or ""
            size_m = re.search(r"\[Size:\s*(\d+)\]", rest)
            redirect_m = re.search(r"\[-->\s*([^\]]+)\]", rest)
            out.append(self._normalize_result(path, service, status=status, raw={
                "line": match.group(0),
                "size": int(size_m.group(1)) if size_m else None,
                "redirect": redirect_m.group(1).strip() if redirect_m else None,
            }))
        return self._dedupe_results(out)

    def _normalize_result(self, path_or_url: str, service: WebServiceTarget, *, status: Any = None, raw: Any = None) -> Dict[str, Any]:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            url = path_or_url
        else:
            url = urljoin(service.base_url.rstrip("/") + "/", path_or_url.lstrip("/"))
        parsed = urlparse(url)
        return {
            "schema": "redteamsuite.web_discovery_result.v1",
            "created_at": utc_now_iso(),
            "target": self.ctx.config.target,
            "service_url": service.base_url,
            "url": url,
            "path": parsed.path or "/",
            "status_code": int(status) if str(status or "").isdigit() else None,
            "source": "gobuster",
            "raw": raw,
        }

    def _fetch_url(self, url: str, service: WebServiceTarget, *, source: str, source_metadata: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            result = self.ctx.http.get(url, allow_redirects=False)
        except Exception as exc:
            self.ctx.logger.event("web_discover.fetch_error", f"GET failed: {url}", {"error": str(exc)})
            return None
        headers = dict(getattr(result, "headers", {}) or {})
        text = getattr(result, "text", "") or ""
        parser = _LinkAndFormParser()
        try:
            parser.feed(text[:250000])
        except Exception:
            pass
        parsed = urlparse(url)
        return {
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
            "title": ReconWorkflow._extract_title(text),
            "body_length": len(text),
            "body_sample": text[:1000],
            "links": ReconWorkflow._same_host_paths(parser.links, url),
            "forms": ReconWorkflow._normalize_forms(parser.forms, url),
            "evidence_id": getattr(result, "evidence_id", None),
            "source": source,
            "source_metadata": source_metadata,
        }

    def _child_urls_from_row(self, row: Dict[str, Any], *, depth_remaining: int) -> List[str]:
        if depth_remaining <= 0:
            return []
        title = str(row.get("title") or "")
        body = str(row.get("body_sample") or "")
        links = [str(x) for x in row.get("links") or [] if isinstance(x, str)]
        if not links:
            return []
        is_listing = any(marker.lower() in f"{title}\n{body}".lower() for marker in DIRECTORY_LISTING_MARKERS)
        out: List[str] = []
        base_url = str(row.get("url") or "")
        base_parsed = urlparse(base_url)
        for path in links:
            url = urljoin(base_url, path)
            parsed = urlparse(url)
            if parsed.netloc != base_parsed.netloc:
                continue
            # For normal pages, fetch linked HTML-ish pages. For directory
            # listings, fetch direct children too, including txt/log/config files.
            if is_listing or self._looks_fetchable_link(parsed.path):
                out.append(url)
        return self._unique(out)

    @staticmethod
    def _looks_fetchable_link(path: str) -> bool:
        lower = path.lower()
        if lower.endswith((".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2")):
            return False
        return True

    def _run_native(self, service: WebServiceTarget, *, wordlist: Optional[str], extensions: str, status_codes: str) -> Dict[str, Any]:
        if not wordlist or not Path(wordlist).expanduser().exists():
            raise SystemExit("Native discovery requires --wordlist. Gobuster is preferred for normal Kali usage.")
        statuses = {int(x) for x in status_codes.split(",") if x.strip().isdigit()}
        words = [line.strip() for line in Path(wordlist).expanduser().read_text(errors="ignore").splitlines() if line.strip() and not line.startswith("#")]
        exts = [x.strip().lstrip(".") for x in extensions.split(",") if x.strip()]
        results: List[Dict[str, Any]] = []
        for word in words:
            candidates = [word]
            candidates += [f"{word}.{ext}" for ext in exts if "." not in word.rsplit("/", 1)[-1]]
            for candidate in candidates:
                url = urljoin(service.base_url.rstrip("/") + "/", candidate.lstrip("/"))
                try:
                    result = self.ctx.http.get(url, allow_redirects=False)
                except Exception:
                    continue
                status = int(getattr(result, "status_code", 0) or 0)
                if status in statuses:
                    results.append(self._normalize_result(url, service, status=status, raw={"engine": "native"}))
        return {
            "schema": "redteamsuite.native_web_discovery_run.v1",
            "created_at": utc_now_iso(),
            "service_url": service.base_url,
            "engine": "native",
            "wordlist": wordlist,
            "results": self._dedupe_results(results),
        }

    def _resolve_services(self, target: str, *, ports: Optional[List[int]], service_urls: Optional[List[str]], use_discovered_services: bool) -> List[WebServiceTarget]:
        services: List[WebServiceTarget] = []
        for url in service_urls or []:
            parsed = urlparse(url if "://" in url else "http://" + url)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            services.append(WebServiceTarget(base_url=f"{parsed.scheme}://{parsed.netloc}".rstrip("/"), host=parsed.hostname or target, port=port, source="cli_service_url"))

        wanted_ports = set(ports or [])
        if use_discovered_services:
            services_json = self.ctx.evidence.load_json("network_services.json", [])
            if isinstance(services_json, list):
                for row in services_json:
                    if not isinstance(row, dict) or str(row.get("host")) != str(target):
                        continue
                    port = int(row.get("port") or 0)
                    if wanted_ports and port not in wanted_ports:
                        continue
                    http = row.get("http") if isinstance(row.get("http"), dict) else {}
                    hint = str(row.get("service_hint") or "").lower()
                    if port in WEB_PORTS or http or "http" in hint or "next" in hint:
                        scheme = "https" if port in (443, 8443) else "http"
                        base = str(http.get("url") or (f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"))
                        services.append(WebServiceTarget(base_url=base.rstrip("/"), host=target, port=port, source="network_services.json"))
        if wanted_ports and not any(s.source == "network_services.json" for s in services):
            for port in wanted_ports:
                scheme = "https" if port in (443, 8443) else "http"
                base = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"
                services.append(WebServiceTarget(base_url=base, host=target, port=port, source="cli_ports"))
        if not services:
            port = int(self.ctx.config.http_port or 80)
            scheme = "https" if port == 443 else "http"
            base = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"
            services.append(WebServiceTarget(base_url=base, host=target, port=port, source="fallback_http_port"))
        return self._dedupe_services(services)

    def _load_list(self, filename: str) -> List[Any]:
        data = self.ctx.evidence.load_json(filename, [])
        return data if isinstance(data, list) else []

    @staticmethod
    def _dedupe_services(services: List[WebServiceTarget]) -> List[WebServiceTarget]:
        seen: Set[str] = set()
        out: List[WebServiceTarget] = []
        for service in services:
            if service.base_url in seen:
                continue
            seen.add(service.base_url)
            out.append(service)
        return out

    @staticmethod
    def _dedupe_results(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: Set[str] = set()
        out: List[Dict[str, Any]] = []
        for row in results:
            url = str(row.get("url") or "")
            if not url or url in seen:
                continue
            seen.add(url)
            out.append(row)
        return out

    @staticmethod
    def _unique(values: Iterable[str]) -> List[str]:
        seen: Set[str] = set()
        out: List[str] = []
        for value in values:
            if value in seen:
                continue
            seen.add(value)
            out.append(value)
        return out

    @staticmethod
    def _quote_piece(value: str) -> str:
        if re.fullmatch(r"[A-Za-z0-9_./:=,-]+", value):
            return value
        return "'" + value.replace("'", "'\\''") + "'"
