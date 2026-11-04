"""
Stage 7: Tech stack fingerprinting.

httpx (stage 3) already does light tech-detect as a side effect, but
this stage goes deeper:
  - wappalyzer-cli against each live host, for a fuller fingerprint
    (CMS, frameworks, analytics, server software) than httpx's built-in
    detection
  - retire.js against JS files discovered in stage 5, specifically to
    flag outdated/vulnerable JS library versions

retire.js needs local files, not just URLs, so JS files are downloaded
into raw/ first.
"""

import json
import re
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError

from core.config import tool_path
from core.module_base import ModuleResult, ReconModule
from core.runner import run_command, binary_available


class FingerprintModule(ReconModule):
    stage = 7
    name = "fingerprint"
    requires = ["live_hosts"]  # retire.js findings (from content_discovery) are optional, checked at runtime

    def run(self, target: str, workspace, prior_results: Dict) -> ModuleResult:
        live_hosts = prior_results["live_hosts"].data.get("live_hosts", [])
        urls = [h["url"] for h in live_hosts if h.get("url")]
        errors = []

        wappalyzer_results = {}
        wappalyzer_bin = tool_path(self.config, "wappalyzer")
        if binary_available(wappalyzer_bin):
            for url in urls:
                tech = self._run_wappalyzer(url, wappalyzer_bin, workspace)
                if tech is not None:
                    wappalyzer_results[url] = tech
        else:
            errors.append(f"'{wappalyzer_bin}' not found on PATH; skipping wappalyzer scan "
                           f"(httpx tech-detect from stage 3 still available).")

        retire_findings = []
        content_result = prior_results.get("content_discovery")
        js_files = content_result.data.get("js_files", []) if content_result and content_result.success else []

        if js_files:
            retire_findings, retire_errors = self._run_retirejs(js_files, workspace)
            errors.extend(retire_errors)
        else:
            workspace.logger.info("No JS files from stage 5; skipping retire.js scan.")

        data = {
            "wappalyzer_by_host": wappalyzer_results,
            "retire_findings": retire_findings,
            "js_files_scanned": len(js_files),
        }

        success = bool(wappalyzer_results) or bool(retire_findings)
        if not success:
            errors.append("No fingerprinting results from wappalyzer or retire.js "
                           "(httpx's lighter tech-detect from stage 3 may still have data).")

        return ModuleResult(module_name=self.name, success=success, data=data, errors=errors)

    def _run_wappalyzer(self, url: str, wappalyzer_bin: str, workspace) -> List[str]:
        result = run_command(
            [wappalyzer_bin, url],
            timeout=self.config.get("timeouts", {}).get("default_seconds", 180),
            logger=workspace.logger,
        )
        if not result.success:
            workspace.logger.warning(f"wappalyzer failed for {url}: {result.error}")
            return None

        safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", urlparse(url).netloc)
        workspace.raw_path(self.name, f"wappalyzer_{safe_name}.json").write_text(result.stdout)

        try:
            parsed = json.loads(result.stdout)
            # wappalyzer-cli's exact schema varies by version; grab tech names defensively
            techs = parsed.get("technologies", []) if isinstance(parsed, dict) else parsed
            return [t.get("name") for t in techs if isinstance(t, dict) and t.get("name")]
        except (json.JSONDecodeError, AttributeError):
            workspace.logger.warning(f"Could not parse wappalyzer output for {url}")
            return []

    def _run_retirejs(self, js_files: List[str], workspace) -> (List[dict], List[str]):
        errors = []
        retire_bin = tool_path(self.config, "retire")
        if not binary_available(retire_bin):
            errors.append(f"'{retire_bin}' not found on PATH; skipping retire.js scan.")
            return [], errors

        # download JS files locally -- retire.js scans a directory, not remote URLs
        js_dir = Path(workspace.raw_path(self.name, "js").parent) / "js"
        js_dir.mkdir(parents=True, exist_ok=True)
        downloaded = 0

        for url in js_files:
            local_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", url)[-150:]
            local_path = js_dir / local_name
            try:
                req = Request(url, headers={"User-Agent": "ReconAtlas/0.1"})
                with urlopen(req, timeout=15) as resp:
                    local_path.write_bytes(resp.read())
                downloaded += 1
            except (URLError, ValueError) as exc:
                workspace.logger.warning(f"Could not download {url}: {exc}")

        if downloaded == 0:
            errors.append("Could not download any JS files for retire.js to scan.")
            return [], errors

        result = run_command(
            [retire_bin, "--path", str(js_dir), "--outputformat", "json"],
            timeout=self.config.get("timeouts", {}).get("default_seconds", 180),
            logger=workspace.logger,
        )
        # retire.js exits non-zero when it finds vulnerabilities -- that's a "success"
        # for our purposes, not a tool failure, so don't gate on result.success alone
        if result.returncode is None and not result.stdout:
            errors.append(result.error or "retire.js failed to run")
            return [], errors

        workspace.raw_path(self.name, "retire_output.json").write_text(result.stdout)

        try:
            parsed = json.loads(result.stdout)
            findings = parsed.get("data", parsed) if isinstance(parsed, dict) else parsed
            return findings if isinstance(findings, list) else [], errors
        except json.JSONDecodeError:
            errors.append("Could not parse retire.js JSON output.")
            return [], errors
