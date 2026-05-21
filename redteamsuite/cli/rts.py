from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Optional

from redteamsuite.core.config import RuntimeConfig
from redteamsuite.core.context import TargetContext
from redteamsuite.core.evidence_store import EvidenceStore
from redteamsuite.core.http_client import HttpClient
from redteamsuite.core.models import HostProfile, utc_now_iso
from redteamsuite.core.run_logger import RunLogger
from redteamsuite.core.utils import resolve_output_dir
from redteamsuite.modules.auth_tester import AuthTester
from redteamsuite.modules.network_mapper import DEFAULT_PORTS, NetworkMapper
from redteamsuite.modules.nextjs_eval_tester import NextJsEvalTester
from redteamsuite.modules.recon import ReconWorkflow
from redteamsuite.modules.staff_portal import StaffPortalModule
from redteamsuite.modules.upload_tester import UploadTester
from redteamsuite.modules.web_enum import WebEnumerator
from redteamsuite.profiles.default_profile import get_profile as get_default_profile
from redteamsuite.profiles.project3_profile import get_profile as get_project3_profile
from redteamsuite.workflows.run_all import run_profile

DEFAULT_PROFILE = "default"
PROJECT_PROFILE_NAMES = {"project3", "p3"}


def _parse_ports(value: str) -> list[int]:
    if value == "default":
        return list(DEFAULT_PORTS)
    ports: list[int] = []
    for piece in value.split(","):
        piece = piece.strip()
        if not piece:
            continue
        if "-" in piece:
            start_s, end_s = piece.split("-", 1)
            ports.extend(range(int(start_s), int(end_s) + 1))
        else:
            ports.append(int(piece))
    return sorted(set(p for p in ports if 1 <= p <= 65535))


def _profile_name(args: argparse.Namespace) -> str:
    return str(getattr(args, "profile", None) or DEFAULT_PROFILE).strip() or DEFAULT_PROFILE


def _load_path_profile(name: str) -> Any:
    if name.lower() in PROJECT_PROFILE_NAMES:
        return get_project3_profile("project3")
    return get_default_profile(name)


def _require_project_profile(name: str, command_name: str) -> None:
    if name.lower() not in PROJECT_PROFILE_NAMES:
        raise SystemExit(
            f"{command_name} is still profile-specific and currently requires --profile project3. "
            "For unknown targets, run `recon` first and inspect recommended_next_steps.json."
        )


def build_context(args: argparse.Namespace, *, require_target: bool = True) -> TargetContext:
    target = getattr(args, "target", None)
    if require_target and not target:
        raise SystemExit("This command requires --target. Run net-map first, inspect target_candidates.json, then export/select a target manually.")

    profile = _profile_name(args)
    output_base = Path(getattr(args, "out", None) or "output")
    output_dir = resolve_output_dir(
        output_base,
        profile=profile,
        target=target,
        run_id=getattr(args, "run_id", None),
        new_run=getattr(args, "new_run", False),
        force_overwrite=getattr(args, "force_overwrite", False),
    )

    config = RuntimeConfig(
        target=target,
        profile=profile,
        output_dir=output_dir,
        run_id=getattr(args, "run_id", None),
        http_port=getattr(args, "http_port", 80),
        nextjs_port=getattr(args, "port", getattr(args, "nextjs_port", 3000)),
        allow_code_exec_validation=getattr(args, "allow_code_exec_validation", False),
        allow_upload_marker=getattr(args, "allow_upload_marker", False),
        allow_php_exec_marker=getattr(args, "allow_php_exec_marker", False),
    )
    evidence = EvidenceStore(output_dir)
    logger = RunLogger(output_dir)
    http = HttpClient(evidence, timeout=config.timeout, user_agent=config.user_agent)
    ctx = TargetContext(config=config, evidence=evidence, logger=logger, http=http)
    write_run_metadata(ctx, args=args)
    return ctx


def write_run_metadata(ctx: TargetContext, *, args: argparse.Namespace) -> None:
    command = getattr(args, "command", None)
    row = {
        "timestamp": utc_now_iso(),
        "command": command,
        "target": ctx.config.target,
        "profile": ctx.config.profile,
        "run_id": ctx.config.run_id,
        "output_dir": str(ctx.evidence.output_dir),
        "http_port": ctx.config.http_port,
        "nextjs_port": ctx.config.nextjs_port,
        "allow_code_exec_validation": ctx.config.allow_code_exec_validation,
        "allow_upload_marker": ctx.config.allow_upload_marker,
        "allow_php_exec_marker": ctx.config.allow_php_exec_marker,
        "argv_options": _safe_args_dict(args),
    }
    ctx.evidence.upsert_run_metadata({
        "profile": ctx.config.profile,
        "run_id": ctx.config.run_id,
        "output_dir": str(ctx.evidence.output_dir),
        "last_command": command,
        "last_target": ctx.config.target,
        "http_port": ctx.config.http_port,
        "nextjs_port": ctx.config.nextjs_port,
    })
    ctx.evidence.append_jsonl("command_history.jsonl", row)
    if ctx.config.target:
        ctx.evidence.save_json("host_profile.json", HostProfile(target=ctx.config.target, profile=ctx.config.profile))


def _safe_args_dict(args: argparse.Namespace) -> dict[str, object]:
    data = vars(args).copy()
    data.pop("func", None)
    if data.get("password"):
        data["password"] = "<redacted>"
    return data


def cmd_init(args: argparse.Namespace) -> None:
    ctx = build_context(args, require_target=bool(args.target))
    ctx.logger.event("init", "Initialized RedTeamSuite output directory")
    ctx.evidence.flush()
    print(f"Initialized output directory: {ctx.evidence.output_dir}")


def cmd_net_map(args: argparse.Namespace) -> None:
    ctx = build_context(args, require_target=False)
    ports = _parse_ports(args.ports)
    result = NetworkMapper(ctx).map_network(
        args.cidr,
        ports=ports,
        max_hosts=args.max_hosts,
        ping_timeout_s=args.ping_timeout,
        connect_timeout_s=args.connect_timeout,
        workers=args.workers,
        use_nmap=args.use_nmap,
        include_self=args.include_self,
        include_infrastructure=args.include_infrastructure,
    )
    candidates = result.get("target_candidates", [])
    scanner_self = result.get("scanner_self", [])
    infrastructure_hosts = result.get("infrastructure_hosts", [])

    print(f"Network map complete. Output: {ctx.evidence.output_dir}")
    print(f"Alive hosts: {result.get('alive_count', 0)}")

    if scanner_self:
        print("\nScanner/self hosts excluded from candidates by default:")
        for host in scanner_self:
            ports_s = ",".join(str(p) for p in host.get("open_ports", [])) or "none"
            print(f"  - {host.get('host')} ports={ports_s}")
            for reason in host.get("reasons", [])[:3]:
                print(f"    - {reason}")

    if infrastructure_hosts:
        print("\nInfrastructure-like hosts excluded from candidates by default:")
        for host in infrastructure_hosts:
            ports_s = ",".join(str(p) for p in host.get("open_ports", [])) or "none"
            print(f"  - {host.get('host')} ports={ports_s}")
            for reason in host.get("reasons", [])[:3]:
                print(f"    - {reason}")

    if not candidates:
        print("\nNo target candidates scored above the threshold.")
        print("Use --include-self or --include-infrastructure only for debugging candidate scoring.")
        return

    print("\nTarget candidates; select manually before deeper testing:")
    for idx, cand in enumerate(candidates, start=1):
        ports_s = ",".join(str(p) for p in cand.get("open_ports", [])) or "none"
        print(f"  {idx}. {cand['host']}  score={cand['score']}  confidence={cand['confidence']}  classification={cand.get('classification')}  ports={ports_s}")
        for reason in cand.get("reasons", [])[:5]:
            print(f"     - {reason}")
    print("\nExample next step:")
    print(f"  export TARGET={candidates[0]['host']}  # only if this is the correct authorized target")
    print("  python -m redteamsuite.cli.rts recon --target $TARGET --out <same_out> --run-id <same_run_id>")


def cmd_recon(args: argparse.Namespace) -> None:
    ctx = build_context(args)
    summary = ReconWorkflow(ctx).run()
    print(f"Default recon complete. Output: {ctx.evidence.output_dir}")
    print(
        "Summary: "
        f"services={summary['http_services']} paths={summary['discovered_paths']} "
        f"artifacts={summary['content_artifacts']} auth_surfaces={summary['auth_surfaces']} "
        f"upload_surfaces={summary['upload_surfaces']} fingerprints={summary['framework_fingerprints']}"
    )
    _print_recommendations(ctx)


def cmd_suggest(args: argparse.Namespace) -> None:
    ctx = build_context(args, require_target=bool(args.target))
    _print_recommendations(ctx)


def _print_recommendations(ctx: TargetContext) -> None:
    recs = ctx.evidence.load_json("recommended_next_steps.json", [])
    if not isinstance(recs, list) or not recs:
        print("No recommended_next_steps.json entries found yet. Run recon first.")
        return
    print("\nRecommended next steps:")
    for idx, rec in enumerate(recs, start=1):
        print(f"  {idx}. [{rec.get('priority', 'unknown')}] {rec.get('category', 'next_step')}")
        print(f"     Reason: {rec.get('reason')}")
        cmd = rec.get("suggested_command")
        if cmd:
            print(f"     Command: {cmd}")


def cmd_web_enum(args: argparse.Namespace) -> None:
    ctx = build_context(args)
    profile = _load_path_profile(ctx.config.profile)
    paths = getattr(profile, "common_paths", [])
    records = WebEnumerator(ctx).check_paths(ctx.config.base_http_url, paths)
    print(f"Checked {len(records)} web paths. Output: {ctx.evidence.output_dir}")


def cmd_portal_test(args: argparse.Namespace) -> None:
    ctx = build_context(args)
    _require_project_profile(ctx.config.profile, "portal-test")
    profile = get_project3_profile("project3")
    portal = StaffPortalModule(ctx)
    creds = portal.fetch_and_parse_users(ctx.config.base_http_url, profile.data_users_path)
    portal.fetch_upload_log(ctx.config.base_http_url, profile.data_uploads_path)
    print(f"Parsed {len(creds)} credentials. Output: {ctx.evidence.output_dir}")


def cmd_upload_test(args: argparse.Namespace) -> None:
    ctx = build_context(args)
    _require_project_profile(ctx.config.profile, "upload-test")
    profile = get_project3_profile("project3")
    cred = None
    if args.username and args.password:
        from redteamsuite.core.models import CredentialRecord
        cred = CredentialRecord(username=args.username, password=args.password, role=args.role)
    else:
        creds = StaffPortalModule(ctx).fetch_and_parse_users(ctx.config.base_http_url, profile.data_users_path)
        cred = next((c for c in creds if (c.role or "").lower() == "admin"), creds[0] if creds else None)
    if cred is None:
        raise SystemExit("No credentials available for upload test.")
    session = AuthTester(ctx).login_form(
        ctx.config.base_http_url,
        profile.login_path,
        profile.login_username_field,
        profile.login_password_field,
        cred,
    )
    if not session.valid:
        raise SystemExit(f"Login failed for {cred.username}; not attempting upload.")
    upload = UploadTester(ctx)
    upload.safe_text_upload_test(ctx.config.base_http_url, profile.upload_path, profile.uploads_path)
    upload.php_double_extension_marker_test(ctx.config.base_http_url, profile.upload_path, profile.uploads_path)
    print(f"Upload checks complete. Output: {ctx.evidence.output_dir}")


def cmd_nextjs_test(args: argparse.Namespace) -> None:
    ctx = build_context(args)
    _require_project_profile(ctx.config.profile, "nextjs-test")
    profile = get_project3_profile("project3")
    tester = NextJsEvalTester(ctx)
    tester.safe_eval_checks(ctx.config.base_nextjs_url, profile.nextjs_dashboard_path)
    tester.command_execution_check(ctx.config.base_nextjs_url, profile.nextjs_dashboard_path)
    print(f"Next.js checks complete. Output: {ctx.evidence.output_dir}")


def cmd_run_profile(args: argparse.Namespace) -> None:
    ctx = build_context(args)
    if ctx.config.profile.lower() == DEFAULT_PROFILE:
        summary = ReconWorkflow(ctx).run()
        print(f"Default profile workflow complete. Output: {ctx.evidence.output_dir}")
        print(json.dumps(summary, indent=2))
        _print_recommendations(ctx)
        return
    _require_project_profile(ctx.config.profile, "run-profile")
    run_profile(ctx, "project3")
    print(f"Profile workflow complete. Output: {ctx.evidence.output_dir}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rts", description="RedTeamSuite evidence-first lab helper")
    parser.add_argument("--version", action="version", version="RedTeamSuite 0.4")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_output_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--profile", default=DEFAULT_PROFILE, help="Profile name, default: default")
        p.add_argument("--out", default="output", help="Base output directory")
        p.add_argument("--run-id", help="Stable run directory name under --out. Existing data is appended by default.")
        p.add_argument("--new-run", action="store_true", help="Create a fresh timestamp-suffixed run directory.")
        p.add_argument("--force-overwrite", action="store_true", help="Delete the selected run directory before writing. Use carefully.")

    def add_target_common(p: argparse.ArgumentParser) -> None:
        add_output_args(p)
        p.add_argument("--target", required=True, help="Target IP or hostname. Use net-map first if unknown.")
        p.add_argument("--http-port", type=int, default=80, help="HTTP port, default: 80")

    p_init = sub.add_parser("init", help="Initialize a run output directory")
    add_output_args(p_init)
    p_init.add_argument("--target", help="Optional target IP or hostname")
    p_init.add_argument("--http-port", type=int, default=80, help="HTTP port, default: 80")
    p_init.set_defaults(func=cmd_init)

    p_net = sub.add_parser("net-map", help="Map an authorized CIDR and rank probable targets")
    add_output_args(p_net)
    p_net.add_argument("--cidr", required=True, help="Authorized CIDR to map, e.g. 192.168.56.0/24")
    p_net.add_argument("--ports", default="default", help="default, comma list, or ranges; e.g. 22,80,443,3000 or 1-1024")
    p_net.add_argument("--max-hosts", type=int, default=512, help="Safety cap for hosts in CIDR")
    p_net.add_argument("--ping-timeout", type=float, default=1.0, help="ICMP ping timeout seconds")
    p_net.add_argument("--connect-timeout", type=float, default=0.75, help="TCP connect timeout seconds")
    p_net.add_argument("--workers", type=int, default=64, help="Concurrent worker count")
    p_net.add_argument("--use-nmap", action="store_true", help="Also run nmap -sV if nmap is installed")
    p_net.add_argument("--include-self", action="store_true", help="Include scanner-local IPs in target_candidates for debugging only")
    p_net.add_argument("--include-infrastructure", action="store_true", help="Include likely gateway/host/infrastructure hosts in target_candidates for debugging only")
    p_net.set_defaults(func=cmd_net_map)

    p_recon = sub.add_parser("recon", help="Run default evidence-driven HTTP/service recon against a manually selected target")
    add_target_common(p_recon)
    p_recon.set_defaults(func=cmd_recon)

    p_suggest = sub.add_parser("suggest", help="Print recommended_next_steps.json for a run")
    add_output_args(p_suggest)
    p_suggest.add_argument("--target", help="Optional target, only used to resolve output dir when no --run-id is provided")
    p_suggest.add_argument("--http-port", type=int, default=80, help="HTTP port, default: 80")
    p_suggest.set_defaults(func=cmd_suggest)

    p_web = sub.add_parser("web-enum", help="Fetch profile-defined web paths and record evidence")
    add_target_common(p_web)
    p_web.set_defaults(func=cmd_web_enum)

    p_portal = sub.add_parser("portal-test", help="Fetch and parse profile-specific portal data artifacts")
    add_target_common(p_portal)
    p_portal.set_defaults(func=cmd_portal_test)

    p_upload = sub.add_parser("upload-test", help="Validate profile-specific authenticated upload behavior")
    add_target_common(p_upload)
    p_upload.add_argument("--username")
    p_upload.add_argument("--password")
    p_upload.add_argument("--role", default="admin")
    p_upload.add_argument("--allow-upload-marker", action="store_true", help="Allow benign text marker upload/access validation")
    p_upload.add_argument("--allow-php-exec-marker", action="store_true", help="Allow double-extension PHP execution marker validation")
    p_upload.set_defaults(func=cmd_upload_test)

    p_next = sub.add_parser("nextjs-test", help="Validate profile-specific Next.js diagnostic eval behavior")
    add_target_common(p_next)
    p_next.add_argument("--port", type=int, default=3000, help="Next.js port, default: 3000")
    p_next.add_argument("--allow-code-exec-validation", action="store_true", help="Allow harmless child_process id validation")
    p_next.set_defaults(func=cmd_nextjs_test)

    p_run = sub.add_parser("run-profile", help="Run selected profile workflow against a manually selected target")
    add_target_common(p_run)
    p_run.add_argument("--nextjs-port", type=int, default=3000, help="Next.js port, default: 3000")
    p_run.add_argument("--allow-code-exec-validation", action="store_true", help="Allow harmless child_process id validation")
    p_run.add_argument("--allow-upload-marker", action="store_true", help="Allow benign text marker upload/access validation")
    p_run.add_argument("--allow-php-exec-marker", action="store_true", help="Allow double-extension PHP execution marker validation")
    p_run.set_defaults(func=cmd_run_profile)

    return parser


def main(argv: Optional[list[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
