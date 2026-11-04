"""
Shared subprocess helper. Every module that shells out to an external
tool (amass, subfinder, httpx, etc.) goes through this so timeouts,
missing-binary errors, and logging are handled consistently in one place.
"""

import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class CommandResult:
    success: bool
    stdout: str
    stderr: str
    returncode: Optional[int]
    error: Optional[str] = None  # set when the binary couldn't even run (e.g. not installed)


def binary_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def run_command(cmd: List[str], timeout: int = 300, logger=None) -> CommandResult:
    """
    Runs a command, returns a CommandResult. Never raises -- failures
    (missing binary, timeout, non-zero exit) are all reported in the
    result so modules can decide how to handle them without try/except
    scattered everywhere.
    """
    binary = cmd[0]
    if not binary_available(binary):
        msg = f"'{binary}' not found on PATH. Install it or set its path in config.yaml."
        if logger:
            logger.error(msg)
        return CommandResult(success=False, stdout="", stderr="", returncode=None, error=msg)

    if logger:
        logger.info(f"Running: {' '.join(cmd)}")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        success = proc.returncode == 0
        if logger and not success:
            logger.warning(f"'{' '.join(cmd)}' exited {proc.returncode}: {proc.stderr.strip()[:500]}")
        return CommandResult(
            success=success,
            stdout=proc.stdout,
            stderr=proc.stderr,
            returncode=proc.returncode,
        )
    except subprocess.TimeoutExpired:
        msg = f"'{' '.join(cmd)}' timed out after {timeout}s"
        if logger:
            logger.error(msg)
        return CommandResult(success=False, stdout="", stderr="", returncode=None, error=msg)
