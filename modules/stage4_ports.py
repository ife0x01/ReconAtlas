"""
Stage 4: Service/port enumeration.

Runs naabu (fast SYN/connect port scanner) against live hosts from
stage 3. Naabu alone only tells you a port is open, not what's running
on it -- so for each host with open ports, we follow up with a light
nmap service/version scan (-sV) scoped to just those ports, rather than
a full nmap port sweep per host (slow and mostly redundant with naabu).

Falls back to nmap-only (both discovery and service ID) if naabu isn't
installed, since nmap alone can do the whole job, just slower.
"""

import re
from typing import Dict, List
from urllib.parse import urlparse

from core.config import tool_path
from core.module_base import ModuleResult, ReconModule
from core.runner import run_command, binary_available


class PortEnumModule(ReconModule):
    stage = 4
    name = "port_enum"
    requires = ["live_hosts"]

    def run(self, target: str, workspace, prior_results: Dict) -> ModuleResult:
        live_hosts = prior_results["live_hosts"].data.get("live_hosts", [])
        hostnames = sorted({self._extract_host(h) for h in live_hosts if self._extract_host(h)})

        if not hostnames:
            return ModuleResult(
                module_name=self.name,
                success=False,
                errors=["No live hosts from stage 3 to scan."],
            )

        naabu_bin = tool_path(self.config, "naabu")
        errors = []

        if binary_available(naabu_bin):
            host_ports = self._scan_with_naabu(hostnames, naabu_bin, workspace, errors)
        else:
            workspace.logger.warning("naabu not found; falling back to nmap for both discovery and service ID.")
            host_ports = None  # signals the nmap fallback path below to do discovery itself

        results_by_host = {}
        nmap_bin = tool_path(self.config, "nmap")
        nmap_available = binary_available(nmap_bin)

        if host_ports is not None:
            # naabu found ports; run nmap -sV scoped to just those ports per host
            for host, ports in host_ports.items():
                if not ports:
                    results_by_host[host] = {"open_ports": [], "services": []}
                    continue
                services = self._nmap_service_scan(host, ports, nmap_bin, workspace, errors) if nmap_available else []
                results_by_host[host] = {"open_ports": ports, "services": services}
            if not nmap_available:
                errors.append("nmap not found; open ports recorded but service/version detection skipped.")
        else:
            # full nmap fallback: discovery + service ID in one pass, common ports only to keep it fast
            if not nmap_available:
                return ModuleResult(
                    module_name=self.name,
                    success=False,
                    errors=["Neither naabu nor nmap found on PATH. Install at least one."],
                )
            for host in hostnames:
                services = self._nmap_service_scan(host, None, nmap_bin, workspace, errors)
                results_by_host[host] = {
                    "open_ports": sorted({s["port"] for s in services}),
                    "services": services,
                }

        raw_summary_path = workspace.raw_path(self.name, "port_summary.json")
        import json as _json
        raw_summary_path.write_text(_json.dumps(results_by_host, indent=2))

        total_open_ports = sum(len(v["open_ports"]) for v in results_by_host.values())
        data = {
            "hosts_scanned": len(hostnames),
            "results_by_host": results_by_host,
            "total_open_ports": total_open_ports,
            "summary_file": str(raw_summary_path),
        }

        success = total_open_ports > 0
        if not success:
            errors.append("Scan completed but found no open ports on any host.")

        return ModuleResult(module_name=self.name, success=success, data=data, errors=errors)

    @staticmethod
    def _extract_host(entry: dict) -> str:
        """Pulls a bare hostname out of a stage-3 live_hosts entry (strips scheme/port/path)."""
        host = entry.get("host")
        if host:
            return host
        url = entry.get("url", "")
        parsed = urlparse(url)
        return parsed.hostname or ""

    def _scan_with_naabu(self, hostnames: List[str], naabu_bin: str, workspace, errors: list) -> Dict[str, List[int]]:
        input_path = workspace.raw_path(self.name, "naabu_input.txt")
        input_path.write_text("\n".join(hostnames))

        result = run_command(
            [naabu_bin, "-list", str(input_path), "-silent", "-json"],
            timeout=self.config.get("timeouts", {}).get("default_seconds", 180),
            logger=workspace.logger,
        )

        host_ports: Dict[str, List[int]] = {h: [] for h in hostnames}

        if not result.success:
            errors.append(result.error or "naabu failed to run")
            return host_ports

        workspace.raw_path(self.name, "naabu_output.jsonl").write_text(result.stdout)

        import json as _json
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = _json.loads(line)
            except _json.JSONDecodeError:
                continue
            host = entry.get("host") or entry.get("ip")
            port = entry.get("port")
            if host in host_ports and isinstance(port, int):
                host_ports[host].append(port)

        for host in host_ports:
            host_ports[host] = sorted(set(host_ports[host]))

        return host_ports

    def _nmap_service_scan(self, host: str, ports: List[int], nmap_bin: str, workspace, errors: list) -> List[dict]:
        """
        Runs nmap -sV against a host. If `ports` is given, scopes the scan
        to those ports (-p). If None, scans nmap's default top-1000 ports --
        used only in the full-fallback path when naabu isn't available.
        """
        cmd = [nmap_bin, "-sV", "-Pn", host]
        if ports:
            cmd[1:1] = ["-p", ",".join(str(p) for p in ports)]

        result = run_command(
            cmd,
            timeout=self.config.get("timeouts", {}).get("default_seconds", 180),
            logger=workspace.logger,
        )

        if not result.success:
            errors.append(f"nmap scan failed for {host}: {result.error or 'non-zero exit'}")
            return []

        safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", host)
        workspace.raw_path(self.name, f"nmap_{safe_name}.txt").write_text(result.stdout)

        return self._parse_nmap_output(result.stdout)

    @staticmethod
    def _parse_nmap_output(raw_output: str) -> List[dict]:
        """
        Parses lines like: '443/tcp open  https   nginx 1.18.0'
        into structured {port, protocol, state, service, version} dicts.
        """
        services = []
        line_re = re.compile(
            r"^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+(.*))?$"
        )
        for line in raw_output.splitlines():
            match = line_re.match(line.strip())
            if not match:
                continue
            port, protocol, state, service, version = match.groups()
            if state != "open":
                continue
            services.append({
                "port": int(port),
                "protocol": protocol,
                "service": service,
                "version": (version or "").strip(),
            })
        return services
