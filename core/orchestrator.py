"""
Orchestrator: runs the registered modules in stage order against a target.

Stage selection (--stages 1,2 or --full) is resolved here, not in the CLI,
so other entrypoints (tests, a future scheduled mode) can reuse it.
"""

from typing import Dict, List, Optional

from core.module_base import ModuleResult, ReconModule
from core.workspace import Workspace


class Orchestrator:
    def __init__(self, config: dict, registered_modules: List[type]):
        """
        registered_modules: list of ReconModule subclasses (not instances).
        Sorted by .stage so execution order is deterministic.
        """
        self.config = config
        self.module_classes = sorted(registered_modules, key=lambda m: m.stage)

    def run(
        self,
        target: str,
        workspace: Workspace,
        stages: Optional[List[int]] = None,
    ) -> Dict[str, ModuleResult]:
        """
        stages: list of stage numbers to run, or None to run everything.
        Returns dict of module_name -> ModuleResult for the modules that ran.
        """
        results: Dict[str, ModuleResult] = {}

        # seed `results` with any prior successful runs from disk, so a module
        # requiring an earlier stage can find it even if we're resuming a
        # partial run with --stages pointed only at later numbers.
        for module_name, saved in workspace.all_results().get("modules", {}).items():
            if saved.get("success"):
                results[module_name] = ModuleResult(
                    module_name=module_name,
                    success=True,
                    data=saved.get("data", {}),
                    errors=saved.get("errors", []),
                )

        for module_cls in self.module_classes:
            if stages is not None and module_cls.stage not in stages:
                continue

            module: ReconModule = module_cls(self.config)

            if not module.check_requirements(results):
                workspace.logger.warning(
                    f"Skipping stage {module.stage} ({module.name}): "
                    f"requires {module.requires}, which hasn't succeeded yet."
                )
                continue

            workspace.logger.info(f"--- Stage {module.stage}: {module.name} ---")
            try:
                result = module.run(target, workspace, results)
            except Exception as exc:
                workspace.logger.error(f"Stage {module.stage} ({module.name}) crashed: {exc}")
                result = ModuleResult(module_name=module.name, success=False, errors=[str(exc)])

            results[module.name] = result
            workspace.save_module_result(result)

            status = "OK" if result.success else "FAILED"
            workspace.logger.info(f"--- Stage {module.stage} ({module.name}) finished: {status} ---")

        return results
