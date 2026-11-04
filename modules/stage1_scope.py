"""
Stage 1: Scope discovery (passive).

Finds related infrastructure without touching the target directly:
  - WHOIS registrant info
  - crt.sh certificate transparency logs (often reveals subdomains
    before you even start brute-forcing)

This runs first because it's zero-noise (no requests hit the target's
own servers) and can seed hostnames for stage 2.
"""

import json
from typing import Dict
from urllib.request import urlopen, Request
from urllib.error import URLError

from core.module_base import ModuleResult, ReconModule
from core.runner import run_command


class ScopeDiscoveryModule(ReconModule):
    stage = 1
    name = "scope_discovery"
    requires = []

    def run(self, target: str, workspace, prior_results: Dict) -> ModuleResult:
        data = {"whois": None, "crtsh_hostnames": []}
        errors = []

        # WHOIS
        whois_result = run_command(["whois", target], timeout=30, logger=workspace.logger)
        if whois_result.success:
            raw_path = workspace.raw_path(self.name, "whois.txt")
            raw_path.write_text(whois_result.stdout)
            data["whois"] = {"raw_file": str(raw_path)}
        else:
            msg = whois_result.error or "whois command failed"
            errors.append(msg)
            workspace.logger.warning(f"WHOIS lookup failed: {msg}")

        # crt.sh certificate transparency
        try:
            hostnames = self._query_crtsh(target, workspace)
            data["crtsh_hostnames"] = sorted(hostnames)
            raw_path = workspace.raw_path(self.name, "crtsh_hostnames.txt")
            raw_path.write_text("\n".join(sorted(hostnames)))
        except URLError as exc:
            msg = f"crt.sh query failed: {exc}"
            errors.append(msg)
            workspace.logger.warning(msg)

        # success if we got at least one source to work with
        success = data["whois"] is not None or bool(data["crtsh_hostnames"])
        return ModuleResult(module_name=self.name, success=success, data=data, errors=errors)

    @staticmethod
    def _query_crtsh(target: str, workspace) -> set:
        """
        Queries crt.sh's JSON endpoint for certs issued to *.target,
        and extracts unique hostnames from the matches. No API key needed.
        """
        url = f"https://crt.sh/?q=%25.{target}&output=json"
        req = Request(url, headers={"User-Agent": "ReconAtlas/0.1"})
        with urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")

        hostnames = set()
        try:
            entries = json.loads(raw)
        except json.JSONDecodeError:
            workspace.logger.warning("crt.sh returned non-JSON response; skipping")
            return hostnames

        for entry in entries:
            name_value = entry.get("name_value", "")
            for line in name_value.split("\n"):
                line = line.strip().lstrip("*.")
                if line and target in line:
                    hostnames.add(line)
        return hostnames
