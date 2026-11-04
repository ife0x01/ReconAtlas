"""
Workspace manager.

Each target gets its own directory under workspaces/<target>/:
  raw/          untouched stdout/output files from each external tool
  results.json  normalized, aggregated findings written incrementally
  run.log       timestamped log of what ran, in what order, with what result

Writing results incrementally (after every module, not just at the end)
means a crash mid-pipeline doesn't lose work already done -- you can
re-run with --stages to pick up from where it stopped.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


class Workspace:
    def __init__(self, target: str, base_dir: str = "workspaces"):
        self.target = target
        self.root = Path(base_dir) / self._safe_name(target)
        self.raw_dir = self.root / "raw"
        self.results_path = self.root / "results.json"
        self.log_path = self.root / "run.log"

        self.root.mkdir(parents=True, exist_ok=True)
        self.raw_dir.mkdir(parents=True, exist_ok=True)

        self._results: Dict[str, Any] = self._load_existing_results()
        self.logger = self._setup_logger()

    @staticmethod
    def _safe_name(target: str) -> str:
        return target.replace("/", "_").replace(":", "_")

    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger(f"recon.{self.target}")
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            fh = logging.FileHandler(self.log_path)
            fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            logger.addHandler(fh)
            sh = logging.StreamHandler()
            sh.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
            logger.addHandler(sh)
        return logger

    def _load_existing_results(self) -> Dict[str, Any]:
        if self.results_path.exists():
            with open(self.results_path, "r") as f:
                return json.load(f)
        return {"target": self.target, "started": self._now(), "modules": {}}

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def raw_path(self, module_name: str, filename: str) -> Path:
        """Path for a module to dump unparsed tool output, e.g. raw_path('subdomains', 'amass.txt')."""
        module_dir = self.raw_dir / module_name
        module_dir.mkdir(parents=True, exist_ok=True)
        return module_dir / filename

    def save_module_result(self, module_result) -> None:
        """Write a module's normalized result into results.json immediately."""
        self._results["modules"][module_result.module_name] = module_result.to_dict()
        self._results["last_updated"] = self._now()
        with open(self.results_path, "w") as f:
            json.dump(self._results, f, indent=2)

    def get_module_result(self, module_name: str):
        return self._results["modules"].get(module_name)

    def all_results(self) -> Dict[str, Any]:
        return self._results
