"""
Stage 8: Screenshot triage.

Final pass: grabs screenshots of every live host via EyeWitness so you
can visually skim hundreds of hosts quickly instead of opening each one
by hand. Optional by nature -- a missing EyeWitness binary shouldn't be
treated as a pipeline failure the way a missing amass/httpx would be,
since nothing downstream depends on this stage's output.
"""

from pathlib import Path
from typing import Dict

from core.config import tool_path
from core.module_base import ModuleResult, ReconModule
from core.runner import run_command, binary_available


class ScreenshotTriageModule(ReconModule):
    stage = 8
    name = "screenshot_triage"
    requires = ["live_hosts"]

    def run(self, target: str, workspace, prior_results: Dict) -> ModuleResult:
        live_hosts = prior_results["live_hosts"].data.get("live_hosts", [])
        urls = [h["url"] for h in live_hosts if h.get("url")]

        if not urls:
            return ModuleResult(
                module_name=self.name,
                success=False,
                errors=["No live host URLs from stage 3 to screenshot."],
            )

        eyewitness_bin = tool_path(self.config, "eyewitness")
        if not binary_available(eyewitness_bin):
            return ModuleResult(
                module_name=self.name,
                success=False,
                errors=[f"'{eyewitness_bin}' not found on PATH; skipping screenshot triage "
                        f"(optional stage, pipeline otherwise complete)."],
            )

        input_path = workspace.raw_path(self.name, "urls.txt")
        input_path.write_text("\n".join(urls))

        output_dir = Path(workspace.raw_path(self.name, "placeholder").parent) / "screenshots"
        output_dir.mkdir(parents=True, exist_ok=True)

        result = run_command(
            [eyewitness_bin, "--web", "-f", str(input_path), "-d", str(output_dir), "--no-prompt"],
            timeout=self.config.get("timeouts", {}).get("screenshot_seconds", 600),
            logger=workspace.logger,
        )

        if not result.success:
            return ModuleResult(
                module_name=self.name,
                success=False,
                errors=[result.error or "EyeWitness failed to run"],
            )

        screenshots = sorted(str(p) for p in output_dir.glob("*.png"))
        report_path = output_dir / "report.html"

        data = {
            "output_dir": str(output_dir),
            "screenshot_count": len(screenshots),
            "screenshots": screenshots,
            "report_html": str(report_path) if report_path.exists() else None,
        }

        success = len(screenshots) > 0
        errors = [] if success else ["EyeWitness ran but produced no screenshots."]

        return ModuleResult(module_name=self.name, success=success, data=data, errors=errors)
