"""
Stage 2: Active subdomain enumeration.

Runs amass and subfinder (if installed), merges their output with the
crt.sh hostnames stage 1 already found, dedupes, and writes a single
clean subdomain list for later stages to consume.

Neither tool being installed isn't fatal -- we fall back to whatever
stage 1 already found via crt.sh, so the pipeline can still proceed.
"""

from typing import Dict, Set

from core.config import tool_path
from core.module_base import ModuleResult, ReconModule
from core.runner import run_command


class SubdomainEnumModule(ReconModule):
    stage = 2
    name = "subdomain_enum"
    requires = []  # soft dependency on scope_discovery; we merge its output if present, but don't require it

    def run(self, target: str, workspace, prior_results: Dict) -> ModuleResult:
        all_subdomains: Set[str] = set()
        errors = []
        sources_used = []

        # seed from stage 1's crt.sh results if available
        scope_result = prior_results.get("scope_discovery")
        if scope_result and scope_result.success:
            crtsh_hosts = scope_result.data.get("crtsh_hostnames", [])
            all_subdomains.update(crtsh_hosts)
            if crtsh_hosts:
                sources_used.append("crt.sh (from stage 1)")

        # amass
        amass_bin = tool_path(self.config, "amass")
        amass_result = run_command(
            [amass_bin, "enum", "-passive", "-d", target],
            timeout=180,
            logger=workspace.logger,
        )
        if amass_result.success:
            found = self._parse_lines(amass_result.stdout, target)
            all_subdomains.update(found)
            sources_used.append("amass")
            workspace.raw_path(self.name, "amass.txt").write_text(amass_result.stdout)
        else:
            errors.append(amass_result.error or "amass failed")

        # subfinder
        subfinder_bin = tool_path(self.config, "subfinder")
        subfinder_result = run_command(
            [subfinder_bin, "-d", target, "-silent"],
            timeout=180,
            logger=workspace.logger,
        )
        if subfinder_result.success:
            found = self._parse_lines(subfinder_result.stdout, target)
            all_subdomains.update(found)
            sources_used.append("subfinder")
            workspace.raw_path(self.name, "subfinder.txt").write_text(subfinder_result.stdout)
        else:
            errors.append(subfinder_result.error or "subfinder failed")

        merged = sorted(all_subdomains)
        merged_path = workspace.raw_path(self.name, "merged_subdomains.txt")
        merged_path.write_text("\n".join(merged))

        data = {
            "subdomains": merged,
            "count": len(merged),
            "sources_used": sources_used,
            "merged_file": str(merged_path),
        }

        # success as long as we ended up with *some* subdomains, from any source
        success = len(merged) > 0
        if not success:
            errors.append("No subdomains found from any source (amass/subfinder/crt.sh).")

        return ModuleResult(module_name=self.name, success=success, data=data, errors=errors)

    @staticmethod
    def _parse_lines(raw_output: str, target: str) -> Set[str]:
        lines = set()
        for line in raw_output.splitlines():
            line = line.strip().lower()
            if line and target in line:
                lines.add(line)
        return lines
