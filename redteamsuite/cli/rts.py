from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional

from redteamsuite.core.config import RuntimeConfig
from redteamsuite.core.context import TargetContext
from redteamsuite.core.evidence_store import EvidenceStore
from redteamsuite.core.http_client import HttpClient
from redteamsuite.core.models import HostProfile
from redteamsuite.core.run_logger import RunLogger
from redteamsuite.core.utils import make_timestamped_output_dir
from redteamsuite.modules.auth_tester import AuthTester
from redteamsuite.modules.nextjs_eval_tester import NextJsEvalTester
from redteamsuite.modules.staff_portal import StaffPortalModule
from redteamsuite.modules.upload_tester import UploadTester
from redteamsuite.modules.web_enum import WebEnumerator
from redteamsuite.profiles.project3_profile import get_profile
from redteamsuite.workflows.run_all import run_profile


def build_context(args: argparse.Namespace) -> TargetContext:
    output_base = Path(getattr(args, "out", None) or "output")
    if output_base.name.endswith(".json"):
        raise ValueError("--out must be a directory, not a JSON file")
    if not output_base.exists() or not any(output_base.iterdir() if output_base.exists() else []):
        output_dir = make_timestamped_output_dir(output_base, args.profile, args.target)
    else:
        output_dir = make_timestamped_output_dir(output_base, args.profile, args.target)

    config = RuntimeConfig(
        target=args.target,
        profile=args.profile,
        output_dir=output_dir,
        http_port=getattr(args, "http_port", 80),
        nextjs_port=getattr(args, "port", getattr(args, "nextjs_port", 3000)),
        allow_code_exec_validation=getattr(args, "allow_code_exec_validation", False),
        allow_upload_marker=getattr(args, "allow_upload_marker", False),
    )
    evidence = EvidenceStore(output_dir)
    logger = RunLogger(output_dir)
    http = HttpClient(evidence, timeout=config.timeout, user_agent=config.user_agent)
    ctx = TargetContext(config=config, evidence=evidence, logger=logger, http=http)
    write_run_metadata(ctx)
    return ctx


def write_run_metadata(ctx: TargetContext) -> None:
    ctx.evidence.save_json("run_metadata.json", {
        "target": ctx.config.target,
        "profile": ctx.config.profile,
        "http_port": ctx.config.http_port,
        "nextjs_port": ctx.config.nextjs_port,
        "allow_code_exec_validation": ctx.config.allow_code_exec_validation,
        "allow_upload_marker": ctx.config.allow_upload_marker,
    })
    ctx.evidence.save_json("host_profile.json", HostProfile(target=ctx.config.target, profile=ctx.config.profile))


def cmd_init(args: argparse.Namespace) -> None:
    ctx = build_context(args)
    ctx.logger.event("init", "Initialized RedTeamSuite output directory")
    ctx.evidence.flush()
    print(f"Initialized output directory: {ctx.evidence.output_dir}")


def cmd_web_enum(args: argparse.Namespace) -> None:
    ctx = build_context(args)
    profile = get_profile(args.profile)
    records = WebEnumerator(ctx).check_paths(ctx.config.base_http_url, profile.common_paths)
    print(f"Checked {len(records)} web paths. Output: {ctx.evidence.output_dir}")


def cmd_portal_test(args: argparse.Namespace) -> None:
    ctx = build_context(args)
    profile = get_profile(args.profile)
    portal = StaffPortalModule(ctx)
    creds = portal.fetch_and_parse_users(ctx.config.base_http_url, profile.data_users_path)
    portal.fetch_upload_log(ctx.config.base_http_url, profile.data_uploads_path)
    print(f"Parsed {len(creds)} credentials. Output: {ctx.evidence.output_dir}")


def cmd_upload_test(args: argparse.Namespace) -> None:
    ctx = build_context(args)
    profile = get_profile(args.profile)
    cred = None
    if args.username and args.password:
        from redteamsuite.core.models import CredentialRecord
        cred = CredentialRecord(username=args.username, password=args.password, role=args.role)
    else:
        creds = StaffPortalModule(ctx).fetch_and_parse_users(ctx.config.base_http_url, profile.data_users_path)
        cred = next((c for c in creds if (c.role or "").lower() == "admin"), creds[0] if creds else None)
    if cred is None:
        raise SystemExit("No credentials available for upload test.")
    session = AuthTester(ctx).login_form(ctx.config.base_http_url, profile.login_path, profile.login_username_field, profile.login_password_field, cred)
    if not session.valid:
        raise SystemExit(f"Login failed for {cred.username}; not attempting upload.")
    upload = UploadTester(ctx)
    upload.safe_text_upload_test(ctx.config.base_http_url, profile.upload_path, profile.uploads_path)
    upload.php_double_extension_marker_test(ctx.config.base_http_url, profile.upload_path, profile.uploads_path)
    print(f"Upload checks complete. Output: {ctx.evidence.output_dir}")


def cmd_nextjs_test(args: argparse.Namespace) -> None:
    ctx = build_context(args)
    profile = get_profile(args.profile)
    tester = NextJsEvalTester(ctx)
    tester.safe_eval_checks(ctx.config.base_nextjs_url, profile.nextjs_dashboard_path)
    tester.command_execution_check(ctx.config.base_nextjs_url, profile.nextjs_dashboard_path)
    print(f"Next.js checks complete. Output: {ctx.evidence.output_dir}")


def cmd_run_profile(args: argparse.Namespace) -> None:
    ctx = build_context(args)
    run_profile(ctx, args.profile)
    print(f"Profile workflow complete. Output: {ctx.evidence.output_dir}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rts", description="RedTeamSuite evidence-first lab helper")
    parser.add_argument("--version", action="version", version="RedTeamSuite 0.1")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--target", required=True, help="Target IP or hostname")
        p.add_argument("--profile", default="project3", help="Profile name, default: project3")
        p.add_argument("--out", default="output", help="Base output directory")
        p.add_argument("--http-port", type=int, default=80, help="HTTP port, default: 80")

    p_init = sub.add_parser("init", help="Initialize a run output directory")
    add_common(p_init)
    p_init.set_defaults(func=cmd_init)

    p_web = sub.add_parser("web-enum", help="Fetch profile-defined web paths and record evidence")
    add_common(p_web)
    p_web.set_defaults(func=cmd_web_enum)

    p_portal = sub.add_parser("portal-test", help="Fetch and parse portal data artifacts")
    add_common(p_portal)
    p_portal.set_defaults(func=cmd_portal_test)

    p_upload = sub.add_parser("upload-test", help="Validate authenticated upload behavior")
    add_common(p_upload)
    p_upload.add_argument("--username")
    p_upload.add_argument("--password")
    p_upload.add_argument("--role", default="admin")
    p_upload.add_argument("--allow-upload-marker", action="store_true", help="Allow harmless PHP marker upload validation")
    p_upload.set_defaults(func=cmd_upload_test)

    p_next = sub.add_parser("nextjs-test", help="Validate Next.js diagnostic eval behavior")
    add_common(p_next)
    p_next.add_argument("--port", type=int, default=3000, help="Next.js port, default: 3000")
    p_next.add_argument("--allow-code-exec-validation", action="store_true", help="Allow harmless child_process id validation")
    p_next.set_defaults(func=cmd_nextjs_test)

    p_run = sub.add_parser("run-profile", help="Run profile workflow")
    add_common(p_run)
    p_run.add_argument("--nextjs-port", type=int, default=3000, help="Next.js port, default: 3000")
    p_run.add_argument("--allow-code-exec-validation", action="store_true", help="Allow harmless child_process id validation")
    p_run.add_argument("--allow-upload-marker", action="store_true", help="Allow harmless PHP marker upload validation")
    p_run.set_defaults(func=cmd_run_profile)

    return parser


def main(argv: Optional[list[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
