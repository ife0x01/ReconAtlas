"""
Stage 3: Live host probing.

Takes the subdomain list from stage 2 and checks which ones actually
resolve and respond over HTTP(S), using httpx (projectdiscovery's tool,
not the Python requests-adjacent library of the same name).

This matters because stage 2 often produces hundreds of candidate
subdomains, many dead or parked. Everything downstream (ports, dir
brute-forcing, fingerprinting) should only run against hosts that are
actually alive, or you waste a lot of time scanning nothing.
"""

import json
from typing import Dict, List

from core.config import tool_path
from core.module_base import ModuleResult, ReconModule
from core.runner import run_command


class LiveHostProbeModule(ReconModule):
    stage = 3
    name = "live_hosts"
    requires = ["subdomain_enum"]

    def run(self, target: str, workspace, prior_results: Dict) -> ModuleResult:
        subdomains: List[str] = prior_results["subdomain_enum"].data.get("subdomains", [])

        if not subdomains:
            return ModuleResult(
                module_name=self.name,
                success=False,
                errors=["No subdomains from stage 2 to probe."],
            )

        # httpx reads targets from stdin, one per line
        input_path = workspace.raw_path(self.name, "input_hosts.txt")
        input_path.write_text("\n".join(subdomains))

        httpx_bin = tool_path(self.config, "httpx")
        result = run_command(
            [
                httpx_bin,
                "-l", str(input_path),
                "-silent",
                "-json",
                "-status-code",
                "-title",
                "-tech-detect",
                "-follow-redirects",
            ],
            timeout=self.config.get("timeouts", {}).get("default_seconds", 180),
            logger=workspace.logger,
        )

        if not result.success:
            return ModuleResult(
                module_name=self.name,
                success=False,
                errors=[result.error or "httpx failed to run"],
            )

        raw_path = workspace.raw_path(self.name, "httpx_output.jsonl")
        raw_path.write_text(result.stdout)

        live_hosts = self._parse_httpx_jsonl(result.stdout, workspace)

        data = {
            "live_hosts": live_hosts,
            "count": len(live_hosts),
            "probed": len(subdomains),
            "raw_file": str(raw_path),
        }

        success = len(live_hosts) > 0
        errors = [] if success else ["httpx ran but found no live hosts among the probed subdomains."]

        return ModuleResult(module_name=self.name, success=success, data=data, errors=errors)

    @staticmethod
    def _parse_httpx_jsonl(raw_output: str, workspace) -> List[dict]:
        """
        httpx -json emits one JSON object per line. We keep only the
        fields later stages actually need, so results.json doesn't
        balloon with raw tool metadata.
        """
        live_hosts = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                workspace.logger.warning(f"Skipping unparseable httpx line: {line[:100]}")
                continue

            live_hosts.append({
                "url": entry.get("url"),
                "host": entry.get("host") or entry.get("input"),
                "status_code": entry.get("status_code"),
                "title": entry.get("title"),
                "tech": entry.get("tech", []),
                "webserver": entry.get("webserver"),
            })
        return live_hosts
