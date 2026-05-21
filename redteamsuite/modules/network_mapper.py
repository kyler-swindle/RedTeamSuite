from __future__ import annotations

import ipaddress
import platform
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

import requests
from bs4 import BeautifulSoup

from redteamsuite.core.context import TargetContext
from redteamsuite.core.models import utc_now_iso


DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 5000, 5432, 8000, 8080, 8443, 3000]
WEB_PORTS = {80, 443, 3000, 5000, 8000, 8080, 8443}


@dataclass
class PortProbe:
    port: int
    protocol: str = "tcp"
    state: str = "closed"
    service_hint: str = "unknown"
    banner: Optional[str] = None
    http: Optional[Dict[str, object]] = None


@dataclass
class HostProbe:
    ip: str
    alive: bool = False
    hostname: Optional[str] = None
    discovery_method: str = "unknown"
    latency_ms: Optional[float] = None
    open_ports: List[PortProbe] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


class NetworkMapper:
    def __init__(self, ctx: TargetContext):
        self.ctx = ctx

    def map_network(
        self,
        cidr: str,
        *,
        ports: Optional[Iterable[int]] = None,
        max_hosts: int = 512,
        ping_timeout_s: float = 1.0,
        connect_timeout_s: float = 0.75,
        workers: int = 64,
        use_nmap: bool = False,
    ) -> Dict[str, object]:
        network = ipaddress.ip_network(cidr, strict=False)
        hosts = list(network.hosts())
        if len(hosts) > max_hosts:
            raise ValueError(f"Refusing to scan {len(hosts)} hosts. Increase --max-hosts if this CIDR is authorized.")

        port_list = list(ports or DEFAULT_PORTS)
        self.ctx.logger.event("netmap.start", f"Mapping network {network}", {"ports": port_list})

        interface_snapshot = self._collect_interface_snapshot()
        alive_hosts = self._discover_hosts([str(h) for h in hosts], ping_timeout_s=ping_timeout_s, workers=workers)
        self.ctx.evidence.save_json("network_interfaces.json", interface_snapshot)
        self.ctx.evidence.save_json("network_hosts.json", [h.__dict__ for h in alive_hosts])

        for host in alive_hosts:
            host.open_ports = self._scan_ports(host.ip, port_list, timeout_s=connect_timeout_s, workers=min(workers, len(port_list) or 1))
            for probe in host.open_ports:
                if probe.port in WEB_PORTS:
                    probe.http = self._probe_http(host.ip, probe.port)

        candidates = self._score_candidates(alive_hosts)
        result = {
            "schema": "redteamsuite.network_map.v1",
            "created_at": utc_now_iso(),
            "cidr": str(network),
            "ports_scanned": port_list,
            "host_count": len(hosts),
            "alive_count": len(alive_hosts),
            "hosts": [self._host_to_dict(h) for h in alive_hosts],
            "target_candidates": candidates,
            "nmap": None,
        }

        if use_nmap:
            result["nmap"] = self._run_nmap(str(network), port_list)

        self.ctx.evidence.save_json("network_ports.json", self._flatten_ports(alive_hosts))
        self.ctx.evidence.save_json("network_services.json", self._flatten_services(alive_hosts))
        self.ctx.evidence.save_json("target_candidates.json", candidates)
        self.ctx.evidence.save_json("network_map.json", result)
        self.ctx.logger.event("netmap.end", "Network mapping complete", {"alive": len(alive_hosts), "candidates": len(candidates)})
        return result

    def _collect_interface_snapshot(self) -> Dict[str, object]:
        commands = {
            "hostname": ["hostname"],
            "ip_addr": ["ip", "addr"],
            "ip_route": ["ip", "route"],
            "arp": ["ip", "neigh"],
        }
        snapshot: Dict[str, object] = {"platform": platform.platform(), "commands": {}}
        for name, cmd in commands.items():
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                snapshot["commands"][name] = {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
                self.ctx.evidence.save_text_evidence("network", f"{name}.txt", proc.stdout + ("\nSTDERR:\n" + proc.stderr if proc.stderr else ""))
            except Exception as exc:
                snapshot["commands"][name] = {"error": str(exc)}
        return snapshot

    def _discover_hosts(self, hosts: List[str], *, ping_timeout_s: float, workers: int) -> List[HostProbe]:
        results: List[HostProbe] = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self._ping_host, host, ping_timeout_s): host for host in hosts}
            for future in as_completed(futures):
                probe = future.result()
                if probe.alive:
                    results.append(probe)
        return sorted(results, key=lambda h: tuple(int(p) for p in h.ip.split(".")))

    def _ping_host(self, host: str, timeout_s: float) -> HostProbe:
        start = time.perf_counter()
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_s))), host]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 1.0)
            alive = proc.returncode == 0
            latency = round((time.perf_counter() - start) * 1000.0, 3) if alive else None
            hostname = self._reverse_dns(host) if alive else None
            return HostProbe(ip=host, alive=alive, hostname=hostname, discovery_method="icmp_ping", latency_ms=latency)
        except Exception as exc:
            return HostProbe(ip=host, alive=False, discovery_method="icmp_ping", notes=[str(exc)])

    def _reverse_dns(self, host: str) -> Optional[str]:
        try:
            return socket.gethostbyaddr(host)[0]
        except Exception:
            return None

    def _scan_ports(self, host: str, ports: List[int], *, timeout_s: float, workers: int) -> List[PortProbe]:
        probes: List[PortProbe] = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self._connect_port, host, port, timeout_s): port for port in ports}
            for future in as_completed(futures):
                probe = future.result()
                if probe.state == "open":
                    probes.append(probe)
        return sorted(probes, key=lambda p: p.port)

    def _connect_port(self, host: str, port: int, timeout_s: float) -> PortProbe:
        try:
            with socket.create_connection((host, port), timeout=timeout_s) as sock:
                sock.settimeout(timeout_s)
                banner = None
                try:
                    sock.sendall(b"\r\n")
                    banner = sock.recv(120).decode("utf-8", errors="replace").strip() or None
                except Exception:
                    pass
                return PortProbe(port=port, state="open", service_hint=self._service_hint(port), banner=banner)
        except Exception:
            return PortProbe(port=port, state="closed", service_hint=self._service_hint(port))

    def _probe_http(self, host: str, port: int) -> Dict[str, object]:
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
        try:
            resp = requests.get(url, timeout=2.0, allow_redirects=False, headers={"User-Agent": self.ctx.config.user_agent})
            evidence_id = self.ctx.evidence.save_http_response("GET", url, resp.status_code, dict(resp.headers), resp.text)
            soup = BeautifulSoup(resp.text, "html.parser")
            title = soup.title.string.strip() if soup.title and soup.title.string else None
            return {
                "url": url,
                "status_code": resp.status_code,
                "server": resp.headers.get("Server"),
                "x_powered_by": resp.headers.get("X-Powered-By"),
                "content_type": resp.headers.get("Content-Type"),
                "title": title,
                "evidence_id": evidence_id,
            }
        except Exception as exc:
            return {"url": url, "error": str(exc)}

    def _score_candidates(self, hosts: List[HostProbe]) -> List[Dict[str, object]]:
        candidates: List[Dict[str, object]] = []
        for host in hosts:
            score = 0
            reasons: List[str] = []
            if host.alive:
                score += 10
                reasons.append("Host responded to discovery probe")

            for probe in host.open_ports:
                if probe.port in WEB_PORTS:
                    score += 20
                    reasons.append(f"TCP/{probe.port} open with web-service likelihood")
                elif probe.port in (22, 445, 3306, 5432):
                    score += 8
                    reasons.append(f"TCP/{probe.port} open ({probe.service_hint})")
                else:
                    score += 4
                    reasons.append(f"TCP/{probe.port} open")

                http = probe.http or {}
                title = http.get("title")
                server = http.get("server")
                powered = http.get("x_powered_by")
                if title:
                    score += 8
                    reasons.append(f"HTTP title on {probe.port}: {title}")
                if server:
                    score += 4
                    reasons.append(f"Server header on {probe.port}: {server}")
                if powered:
                    score += 6
                    reasons.append(f"X-Powered-By on {probe.port}: {powered}")
                if powered and "next" in str(powered).lower():
                    score += 12
                    reasons.append(f"Next.js indicator on TCP/{probe.port}")

            if score <= 10:
                continue
            confidence = "high" if score >= 55 else "medium" if score >= 30 else "low"
            candidates.append({
                "host": host.ip,
                "score": score,
                "confidence": confidence,
                "open_ports": [p.port for p in host.open_ports],
                "reasons": reasons,
                "recommended_next_step": f"export TARGET={host.ip}",
            })
        return sorted(candidates, key=lambda c: int(c["score"]), reverse=True)

    def _run_nmap(self, cidr: str, ports: List[int]) -> Dict[str, object]:
        port_arg = ",".join(str(p) for p in ports)
        cmd = ["nmap", "-sV", "-oX", "-", "-p", port_arg, cidr]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            evidence_id = self.ctx.evidence.save_text_evidence("network", "nmap.xml", proc.stdout + ("\nSTDERR:\n" + proc.stderr if proc.stderr else ""))
            return {"command": cmd, "returncode": proc.returncode, "evidence_id": evidence_id}
        except FileNotFoundError:
            return {"command": cmd, "error": "nmap not found"}
        except Exception as exc:
            return {"command": cmd, "error": str(exc)}

    @staticmethod
    def _service_hint(port: int) -> str:
        return {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
            110: "pop3", 139: "netbios", 143: "imap", 443: "https", 445: "smb",
            3306: "mysql", 5000: "http-alt", 5432: "postgres", 8000: "http-alt",
            8080: "http-alt", 8443: "https-alt", 3000: "node/nextjs-dev",
        }.get(port, "unknown")

    @staticmethod
    def _host_to_dict(host: HostProbe) -> Dict[str, object]:
        return {
            "ip": host.ip,
            "alive": host.alive,
            "hostname": host.hostname,
            "discovery_method": host.discovery_method,
            "latency_ms": host.latency_ms,
            "open_ports": [p.__dict__ for p in host.open_ports],
            "notes": host.notes,
        }

    @staticmethod
    def _flatten_ports(hosts: List[HostProbe]) -> List[Dict[str, object]]:
        rows: List[Dict[str, object]] = []
        for host in hosts:
            for probe in host.open_ports:
                rows.append({"host": host.ip, "port": probe.port, "protocol": probe.protocol, "state": probe.state})
        return rows

    @staticmethod
    def _flatten_services(hosts: List[HostProbe]) -> List[Dict[str, object]]:
        rows: List[Dict[str, object]] = []
        for host in hosts:
            for probe in host.open_ports:
                rows.append({
                    "host": host.ip,
                    "port": probe.port,
                    "service_hint": probe.service_hint,
                    "banner": probe.banner,
                    "http": probe.http,
                })
        return rows
