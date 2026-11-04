#!/usr/bin/env python3
"""
ReconAtlas CLI.

Usage:
  python cli.py run example.com                 # run all registered stages
  python cli.py run example.com --stages 1,2    # run only stage 1 and 2
  python cli.py run example.com --config myconf.yaml
"""

import argparse
import sys
from typing import List, Optional

from core.config import load_config
from core.orchestrator import Orchestrator
from core.workspace import Workspace
from modules.stage1_scope import ScopeDiscoveryModule
from modules.stage2_subdomains import SubdomainEnumModule
from modules.stage3_live_hosts import LiveHostProbeModule
from modules.stage4_ports import PortEnumModule
from modules.stage5_content import ContentDiscoveryModule
from modules.stage6_exposure import ThirdPartyExposureModule
from modules.stage7_fingerprint import FingerprintModule
from modules.stage8_screenshots import ScreenshotTriageModule

# register every module here as it's built. Order in this list doesn't
# matter -- the orchestrator sorts by .stage -- but keeping it in stage
# order makes the file easier to read.
REGISTERED_MODULES = [
    ScopeDiscoveryModule,
    SubdomainEnumModule,
    LiveHostProbeModule,
    PortEnumModule,
    ContentDiscoveryModule,
    ThirdPartyExposureModule,
    FingerprintModule,
    ScreenshotTriageModule,
]


def parse_stages(stages_arg: Optional[str]) -> Optional[List[int]]:
    if not stages_arg:
        return None
    return [int(s.strip()) for s in stages_arg.split(",") if s.strip()]


def main():
    parser = argparse.ArgumentParser(description="Recon automation tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run recon against a target")
    run_parser.add_argument("target", help="Target domain, e.g. example.com")
    run_parser.add_argument(
        "--stages",
        help="Comma-separated stage numbers to run, e.g. 1,2. Default: all registered stages.",
        default=None,
    )
    run_parser.add_argument(
        "--config",
        help="Path to config.yaml. Default: ./config.yaml",
        default=None,
    )
    run_parser.add_argument(
        "--workspace-dir",
        help="Base directory for workspaces. Default: ./workspaces",
        default="workspaces",
    )

    args = parser.parse_args()

    if args.command == "run":
        try:
            config = load_config(args.config)
        except FileNotFoundError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)

        workspace = Workspace(args.target, base_dir=args.workspace_dir)
        orchestrator = Orchestrator(config, REGISTERED_MODULES)

        stages = parse_stages(args.stages)
        results = orchestrator.run(args.target, workspace, stages=stages)

        print(f"\nResults written to {workspace.results_path}")
        for module_name, result in results.items():
            status = "OK" if result.success else "FAILED"
            print(f"  [{status}] {module_name}")
            if not result.success and result.errors:
                for err in result.errors:
                    print(f"      - {err}")


if __name__ == "__main__":
    main()
