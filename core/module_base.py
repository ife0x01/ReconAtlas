"""
Base interface that every recon module (stage) must implement.

Each module lives in modules/stageN_name.py and exposes a class
subclassing ReconModule. The orchestrator discovers modules, runs them
in order, and feeds each one the workspace + results accumulated so far.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class ModuleResult:
    """Normalized output every module returns, regardless of what it ran."""
    module_name: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    errors: list = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module_name,
            "success": self.success,
            "data": self.data,
            "errors": self.errors,
        }


class ReconModule(ABC):
    """
    Subclass this for every pipeline stage.

    stage: int           -- execution order (1 = first)
    name: str            -- short identifier, used in CLI --stages and in results.json
    requires: list[str]  -- names of modules that must run before this one
                            (orchestrator checks these were run successfully)
    """

    stage: int = 0
    name: str = "base"
    requires: list = []

    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    def run(self, target: str, workspace, prior_results: Dict[str, ModuleResult]) -> ModuleResult:
        """
        Execute this stage.

        target: the domain/org being assessed, e.g. "example.com"
        workspace: Workspace instance (see core/workspace.py) for raw/normalized output paths
        prior_results: dict of module_name -> ModuleResult from stages that already ran,
                        so e.g. stage 2 can read the live-host list stage 1 produced.
        """
        raise NotImplementedError

    def check_requirements(self, prior_results: Dict[str, ModuleResult]) -> bool:
        """Returns False if a required upstream module hasn't successfully run yet."""
        for req in self.requires:
            if req not in prior_results or not prior_results[req].success:
                return False
        return True
