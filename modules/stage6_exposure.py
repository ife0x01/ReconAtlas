"""
Stage 6: Third-party exposure.

Org-wide, not tied to any single host:
  - Cloud storage bucket hunting across AWS S3, Azure Blob, and GCS,
    using permutations of the org name (not per-subdomain -- bucket
    names rarely match subdomains exactly)
  - GitHub secret scanning via trufflehog, if a github org/repo is
    configured

Bucket existence is checked with plain HTTP HEAD requests against each
provider's public URL scheme -- no AWS/Azure/GCP credentials needed to
*detect* a bucket, only to list/read its contents, which this stage
does not attempt (see README for why: that's an active, consent-sensitive
step left to the operator, not automated here).
"""

import re
from typing import Dict, List
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from core.config import tool_path
from core.module_base import ModuleResult, ReconModule
from core.runner import run_command, binary_available


# common suffixes/prefixes orgs tack onto bucket names
BUCKET_PERMUTATIONS = [
    "", "-backup", "-backups", "-assets", "-static", "-media",
    "-dev", "-development", "-staging", "-stage", "-prod", "-production",
    "-data", "-files", "-uploads", "-public", "-private", "-internal",
    "-test", "-logs", "-cdn", "-www",
]

BUCKET_URL_TEMPLATES = {
    "aws_s3": "https://{bucket}.s3.amazonaws.com/",
    "azure_blob": "https://{bucket}.blob.core.windows.net/?comp=list",
    "gcs": "https://storage.googleapis.com/{bucket}/",
}


class ThirdPartyExposureModule(ReconModule):
    stage = 6
    name = "third_party_exposure"
    requires = []  # org-wide; doesn't depend on live host discovery

    def run(self, target: str, workspace, prior_results: Dict) -> ModuleResult:
        errors = []
        org_name = self._org_name_from_target(target)
        candidate_names = sorted({org_name + suffix for suffix in BUCKET_PERMUTATIONS})

        found_buckets = self._check_buckets(candidate_names, workspace)

        github_findings = []
        github_org = self.config.get("github", {}).get("org")
        if github_org:
            github_findings, gh_errors = self._run_trufflehog(github_org, workspace)
            errors.extend(gh_errors)
        else:
            workspace.logger.info("No github.org configured; skipping GitHub secret scan.")

        data = {
            "org_name_used": org_name,
            "candidates_checked": len(candidate_names),
            "found_buckets": found_buckets,
            "github_org_scanned": github_org,
            "github_findings": github_findings,
        }

        success = bool(found_buckets) or bool(github_findings)
        if not success:
            errors.append("No exposed buckets or GitHub secrets found (or scans were skipped -- see errors).")

        return ModuleResult(module_name=self.name, success=success, data=data, errors=errors)

    @staticmethod
    def _org_name_from_target(target: str) -> str:
        """example.com -> example; strips TLD and common prefixes."""
        name = target.split(".")[0] if "." in target else target
        return re.sub(r"[^a-z0-9-]", "", name.lower())

    def _check_buckets(self, candidate_names: List[str], workspace) -> List[dict]:
        found = []
        for bucket in candidate_names:
            for provider, template in BUCKET_URL_TEMPLATES.items():
                url = template.format(bucket=bucket)
                status = self._head_check(url)
                # a bucket "exists" (even if access-denied) when we get anything
                # other than a connection failure or a clear not-found signal
                if status is not None and status not in (404,):
                    found.append({
                        "provider": provider,
                        "bucket_name": bucket,
                        "url": url,
                        "http_status": status,
                        "publicly_listable": status == 200,
                    })
        if found:
            raw_path = workspace.raw_path(self.name, "found_buckets.txt")
            raw_path.write_text("\n".join(f"{b['provider']}: {b['url']} ({b['http_status']})" for b in found))
        return found

    @staticmethod
    def _head_check(url: str, timeout: int = 10):
        req = Request(url, method="HEAD", headers={"User-Agent": "ReconAtlas/0.1"})
        try:
            with urlopen(req, timeout=timeout) as resp:
                return resp.status
        except HTTPError as e:
            # HTTPError is raised for 4xx/5xx but still tells us the bucket responded
            return e.code
        except URLError:
            return None

    def _run_trufflehog(self, github_org: str, workspace) -> (List[dict], List[str]):
        errors = []
        trufflehog_bin = tool_path(self.config, "trufflehog")
        if not binary_available(trufflehog_bin):
            errors.append(f"'{trufflehog_bin}' not found on PATH; skipping GitHub secret scan.")
            return [], errors

        result = run_command(
            [trufflehog_bin, "github", "--org", github_org, "--json"],
            timeout=self.config.get("timeouts", {}).get("github_scan_seconds", 600),
            logger=workspace.logger,
        )
        if not result.success:
            errors.append(result.error or f"trufflehog scan of org '{github_org}' failed")
            return [], errors

        raw_path = workspace.raw_path(self.name, "trufflehog_output.jsonl")
        raw_path.write_text(result.stdout)

        import json as _json
        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = _json.loads(line)
            except _json.JSONDecodeError:
                continue
            findings.append({
                "detector": entry.get("DetectorName"),
                "repo": entry.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("repository"),
                "verified": entry.get("Verified", False),
            })
        return findings, errors
