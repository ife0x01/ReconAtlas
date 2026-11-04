"""
Mocks every external binary with canned, realistic output and runs the
real module.run() methods end-to-end, so we test actual logic paths
(parsing, merging, chaining between stages) rather than just the
graceful-degradation paths that run when tools are genuinely missing.

Not part of the shipped package -- dev-only test harness.
"""

import sys
import shutil
import logging
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))

from core.config import load_config
from core.orchestrator import Orchestrator
from core.workspace import Workspace
from core.runner import CommandResult
from modules.stage1_scope import ScopeDiscoveryModule
from modules.stage2_subdomains import SubdomainEnumModule
from modules.stage3_live_hosts import LiveHostProbeModule
from modules.stage4_ports import PortEnumModule
from modules.stage5_content import ContentDiscoveryModule
from modules.stage6_exposure import ThirdPartyExposureModule
from modules.stage7_fingerprint import FingerprintModule
from modules.stage8_screenshots import ScreenshotTriageModule

TARGET = "example.com"

# ---- canned fake outputs, keyed by binary name ----
FAKE_OUTPUTS = {
    "whois": "Domain Name: EXAMPLE.COM\nRegistrar: Fake Registrar Inc\n",
    "amass": "www.example.com\napi.example.com\nold.example.com\n",
    "subfinder": "www.example.com\nmail.example.com\nAPI.EXAMPLE.COM\n",
    "httpx": (
        '{"url":"https://www.example.com","host":"www.example.com","status_code":200,'
        '"title":"Example Home","tech":["nginx","React"],"webserver":"nginx"}\n'
        '{"url":"https://api.example.com","host":"api.example.com","status_code":401,'
        '"title":"","tech":[],"webserver":"nginx"}\n'
        'garbage line that is not json\n'
    ),
    "naabu": (
        '{"host":"www.example.com","port":80}\n'
        '{"host":"www.example.com","port":443}\n'
        '{"host":"api.example.com","port":443}\n'
    ),
    "nmap": (
        "Starting Nmap 7.94\n"
        "Nmap scan report for host\n"
        "PORT    STATE SERVICE VERSION\n"
        "80/tcp  open  http    nginx 1.18.0\n"
        "443/tcp open  https   nginx 1.18.0\n"
    ),
    "gobuster": (
        "/admin (Status: 403) [Size: 153]\n"
        "/api (Status: 200) [Size: 42]\n"
        "/app.js (Status: 200) [Size: 9001]\n"
    ),
    "waybackurls": (
        "https://www.example.com/old-page\n"
        "https://www.example.com/vendor/jquery.min.js\n"
        "https://api.example.com/v1/users?id=1\n"
    ),
    "trufflehog": (
        '{"DetectorName":"AWS","Verified":true,"SourceMetadata":{"Data":{"Git":{"repository":"https://github.com/exampleorg/repo1"}}}}\n'
    ),
    "wappalyzer": '{"technologies":[{"name":"nginx"},{"name":"React"}]}',
    "retire": '{"data":[{"file":"jquery.min.js","results":[{"component":"jquery","version":"1.9.0","vulnerabilities":[{"severity":"medium"}]}]}]}',
    "eyewitness": "EyeWitness run complete\n",
}

CALL_LOG = []


def fake_binary_available(binary):
    # pretend everything in FAKE_OUTPUTS is installed; whois/nmap too
    return binary in FAKE_OUTPUTS


def fake_run_command(cmd, timeout=300, logger=None):
    binary = cmd[0]
    CALL_LOG.append(cmd)
    if binary not in FAKE_OUTPUTS:
        return CommandResult(success=False, stdout="", stderr="", returncode=None, error=f"{binary} not mocked")

    stdout = FAKE_OUTPUTS[binary]
    returncode = 0
    # retire.js legitimately exits non-zero when it finds vulnerable libs --
    # module code accounts for this, so simulate it
    if binary == "retire":
        returncode = 13

    if binary == "eyewitness":
        # real eyewitness writes screenshots as a side effect, not via stdout --
        # simulate that side effect so stage 8's success path is actually exercised
        out_dir_idx = cmd.index("-d") + 1
        out_dir = Path(cmd[out_dir_idx])
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "www.example.com.png").write_bytes(b"\x89PNG fake")
        (out_dir / "api.example.com.png").write_bytes(b"\x89PNG fake")
        (out_dir / "report.html").write_text("<html>fake report</html>")

    return CommandResult(success=(returncode == 0), stdout=stdout, stderr="", returncode=returncode)


def fake_urlopen_head(url_or_req, timeout=10):
    """Simulate bucket-check HTTP HEAD requests: pretend one bucket exists."""
    import io
    from unittest.mock import MagicMock

    url = url_or_req.full_url if hasattr(url_or_req, "full_url") else url_or_req
    resp = MagicMock()
    if "example-backup" in url or "example-assets" in url:
        resp.status = 200
    else:
        from urllib.error import HTTPError
        raise HTTPError(url, 404, "Not Found", {}, io.BytesIO(b""))

    class CtxMgr:
        def __enter__(self_inner):
            return resp
        def __exit__(self_inner, *a):
            return False
    return CtxMgr()


def fake_urlopen_download(url_or_req, timeout=15):
    """For crt.sh JSON query and JS file downloads."""
    import io
    from unittest.mock import MagicMock

    url = url_or_req.full_url if hasattr(url_or_req, "full_url") else url_or_req

    if "crt.sh" in url:
        body = b'[{"name_value":"old.example.com\\nwww.example.com"}]'
    elif url.endswith(".js"):
        body = b"var fake = 'js content';"
    else:
        body = b""

    resp = MagicMock()
    resp.read.return_value = body
    resp.status = 200

    class CtxMgr:
        def __enter__(self_inner):
            return resp
        def __exit__(self_inner, *a):
            return False
    return CtxMgr()


def run_test():
    shutil.rmtree("workspaces/example.com", ignore_errors=True)
    config = load_config("config.yaml")
    config["github"]["org"] = "exampleorg"  # enable trufflehog path

    workspace = Workspace(TARGET, base_dir="workspaces")
    orchestrator = Orchestrator(config, [
        ScopeDiscoveryModule, SubdomainEnumModule, LiveHostProbeModule,
        PortEnumModule, ContentDiscoveryModule, ThirdPartyExposureModule,
        FingerprintModule, ScreenshotTriageModule,
    ])

    # every module does `from core.runner import run_command, binary_available`,
    # which binds its own local reference at import time -- patching
    # core.runner.X does NOT reach modules that already imported X by name.
    # Each importing module's reference has to be patched individually.
    run_cmd_targets = [
        "modules.stage1_scope.run_command",
        "modules.stage2_subdomains.run_command",
        "modules.stage3_live_hosts.run_command",
        "modules.stage4_ports.run_command",
        "modules.stage5_content.run_command",
        "modules.stage6_exposure.run_command",
        "modules.stage7_fingerprint.run_command",
        "modules.stage8_screenshots.run_command",
    ]
    bin_avail_targets = [
        "modules.stage4_ports.binary_available",
        "modules.stage5_content.binary_available",
        "modules.stage6_exposure.binary_available",
        "modules.stage7_fingerprint.binary_available",
        "modules.stage8_screenshots.binary_available",
    ]

    patchers = [patch(t, side_effect=fake_run_command) for t in run_cmd_targets]
    patchers += [patch(t, side_effect=fake_binary_available) for t in bin_avail_targets]
    patchers += [
        patch("modules.stage1_scope.urlopen", side_effect=fake_urlopen_download),
        patch("modules.stage6_exposure.urlopen", side_effect=fake_urlopen_head),
        patch("modules.stage7_fingerprint.urlopen", side_effect=fake_urlopen_download),
    ]

    for p in patchers:
        p.start()
    try:
        results = orchestrator.run(TARGET, workspace, stages=None)
    finally:
        for p in patchers:
            p.stop()

    print("\n==== RESULTS ====")
    all_ok = True
    for name, r in results.items():
        status = "OK" if r.success else "FAILED"
        if not r.success:
            all_ok = False
        print(f"[{status}] {name}")
        if r.errors:
            for e in r.errors:
                print(f"    ! {e}")

    print("\n==== KEY DATA CHECKS ====")
    checks = []

    sd = results.get("subdomain_enum")
    # amass{www,api,old} + subfinder{www,mail,API->api} + crt.sh{old,www} = {www,api,old,mail} = 4 unique
    checks.append(("subdomain_enum found 4 unique hosts (case-insens dedupe across 3 sources)",
                    sd and sd.data.get("count") == 4, sd.data.get("subdomains") if sd else None))

    lh = results.get("live_hosts")
    checks.append(("live_hosts found 2 hosts, 1 malformed json line skipped",
                    lh and lh.data.get("count") == 2, lh.data if lh else None))

    pe = results.get("port_enum")
    checks.append(("port_enum found open ports for both hosts",
                    pe and pe.data.get("total_open_ports", 0) > 0, pe.data if pe else None))

    cd = results.get("content_discovery")
    # gobuster mock is called once per live host (www + api) and returns the same
    # canned app.js hit both times -- that's correct given the mock, not a bug
    expected_js = {
        "https://www.example.com/app.js",
        "https://api.example.com/app.js",
        "https://www.example.com/vendor/jquery.min.js",
    }
    checks.append(("content_discovery js_files contains gobuster (both hosts) + wayback JS, no non-js",
                    cd and set(cd.data.get("js_files", [])) == expected_js,
                    cd.data.get("js_files") if cd else None))

    te = results.get("third_party_exposure")
    checks.append(("third_party_exposure found the fake 'backup'/'assets' buckets",
                    te and len(te.data.get("found_buckets", [])) >= 1,
                    te.data.get("found_buckets") if te else None))
    checks.append(("third_party_exposure got trufflehog finding",
                    te and len(te.data.get("github_findings", [])) == 1,
                    te.data.get("github_findings") if te else None))

    fp = results.get("fingerprint")
    checks.append(("fingerprint got wappalyzer results for both hosts",
                    fp and len(fp.data.get("wappalyzer_by_host", {})) == 2,
                    fp.data.get("wappalyzer_by_host") if fp else None))
    checks.append(("fingerprint got retire.js findings despite non-zero exit code",
                    fp and len(fp.data.get("retire_findings", [])) == 1,
                    fp.data.get("retire_findings") if fp else None))

    st = results.get("screenshot_triage")
    checks.append(("screenshot_triage found the 2 simulated .png files",
                    st and st.success and st.data.get("screenshot_count") == 2,
                    st.data if st else None))

    for desc, passed, detail in checks:
        mark = "PASS" if passed else "FAIL"
        print(f"[{mark}] {desc}")
        if not passed:
            all_ok = False
            print(f"       -> actual: {detail}")

    print("\n" + ("ALL CHECKS PASSED" if all_ok else "SOME CHECKS FAILED"))
    return all_ok


if __name__ == "__main__":
    ok = run_test()
    sys.exit(0 if ok else 1)
