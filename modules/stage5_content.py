"""
Stage 5: Content discovery.

For each live host from stage 3:
  - directory/file brute force (gobuster), using the wordlist from config
  - historical URLs via waybackurls (archive.org), which often surfaces
    paths/params no longer linked anywhere live

JS file URLs are separated out into their own list here, as plain
output only -- no parsing, no secret-hunting. That analysis belongs in
a downstream tool (BACHunter) that consumes this list as input.
"""

import re
from typing import Dict, List
from urllib.parse import urlparse

from core.config import tool_path
from core.module_base import ModuleResult, ReconModule
from core.runner import run_command, binary_available


class ContentDiscoveryModule(ReconModule):
    stage = 5
    name = "content_discovery"
    requires = ["live_hosts"]

    def run(self, target: str, workspace, prior_results: Dict) -> ModuleResult:
        live_hosts = prior_results["live_hosts"].data.get("live_hosts", [])
        urls = [h["url"] for h in live_hosts if h.get("url")]

        if not urls:
            return ModuleResult(
                module_name=self.name,
                success=False,
                errors=["No live host URLs from stage 3 to probe."],
            )

        errors = []
        results_by_host = {}

        gobuster_bin = tool_path(self.config, "gobuster")
        wordlist = self.config.get("wordlists", {}).get("directories")
        gobuster_available = binary_available(gobuster_bin)
        if gobuster_available and not wordlist:
            errors.append("gobuster is installed but no wordlists.directories set in config.yaml; skipping dir brute force.")
            gobuster_available = False
        elif not gobuster_available:
            errors.append(f"'{gobuster_bin}' not found on PATH; skipping directory brute force.")

        for url in urls:
            paths = self._gobuster_scan(url, gobuster_bin, wordlist, workspace) if gobuster_available else []
            results_by_host[url] = {"discovered_paths": paths}

        # waybackurls is org/domain-wide, not per-host
        all_js_files: List[str] = []
        all_wayback_urls: List[str] = []
        waybackurls_bin = tool_path(self.config, "waybackurls")
        if binary_available(waybackurls_bin):
            wb_result = run_command(
                [waybackurls_bin, target],
                timeout=self.config.get("timeouts", {}).get("default_seconds", 180),
                logger=workspace.logger,
            )
            if wb_result.success:
                workspace.raw_path(self.name, "waybackurls.txt").write_text(wb_result.stdout)
                all_wayback_urls = sorted({line.strip() for line in wb_result.stdout.splitlines() if line.strip()})
            else:
                errors.append(wb_result.error or "waybackurls failed")
        else:
            errors.append(f"'{waybackurls_bin}' not found on PATH; skipping historical URL discovery.")

        # merge JS file URLs from both gobuster-discovered paths and wayback history
        for host_url, host_data in results_by_host.items():
            all_js_files.extend(self._filter_js(host_data["discovered_paths"]))
        all_js_files.extend(self._filter_js(all_wayback_urls))
        unique_js_files = sorted(set(all_js_files))

        js_path = workspace.raw_path(self.name, "js_files.txt")
        js_path.write_text("\n".join(unique_js_files))

        data = {
            "results_by_host": results_by_host,
            "wayback_urls": all_wayback_urls,
            "wayback_url_count": len(all_wayback_urls),
            "js_files": unique_js_files,
            "js_file_count": len(unique_js_files),
            "js_files_output": str(js_path),
        }

        total_discovered = sum(len(v["discovered_paths"]) for v in results_by_host.values()) + len(all_wayback_urls)
        success = total_discovered > 0
        if not success:
            errors.append("No content discovered via gobuster or waybackurls.")

        return ModuleResult(module_name=self.name, success=success, data=data, errors=errors)

    def _gobuster_scan(self, url: str, gobuster_bin: str, wordlist: str, workspace) -> List[str]:
        result = run_command(
            [gobuster_bin, "dir", "-u", url, "-w", wordlist, "-q", "--no-error"],
            timeout=self.config.get("timeouts", {}).get("default_seconds", 180),
            logger=workspace.logger,
        )
        if not result.success:
            workspace.logger.warning(f"gobuster failed for {url}: {result.error}")
            return []

        safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", urlparse(url).netloc)
        workspace.raw_path(self.name, f"gobuster_{safe_name}.txt").write_text(result.stdout)

        paths = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # gobuster -q output is typically "/path (Status: 200) [Size: 1234]"
            path = line.split()[0] if line.split() else line
            full_url = url.rstrip("/") + path if path.startswith("/") else path
            paths.append(full_url)
        return paths

    @staticmethod
    def _filter_js(urls: List[str]) -> List[str]:
        return [u for u in urls if urlparse(u).path.endswith(".js")]
