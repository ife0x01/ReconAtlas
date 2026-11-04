# ReconAtlas

Org-wide asset recon pipeline. CLI, run manually per target. Orchestrates
external tools (amass, subfinder, etc.) rather than reimplementing them;
owns normalization, merging, and stages without a solid existing tool.

## Setup

```bash
pip install -r requirements.txt
cp config.example.yaml config.yaml   # already done; edit config.yaml with your API keys
```

External tools used (install separately, must be on PATH):
- `whois` (usually preinstalled on Linux/macOS)
- `amass` — https://github.com/OWASP/Amass
- `subfinder` — https://github.com/projectdiscovery/subfinder
- `httpx` — https://github.com/projectdiscovery/httpx
- `naabu` — https://github.com/projectdiscovery/naabu
- `nmap` — usually in your distro's package manager
- `gobuster` — https://github.com/OJ/gobuster
- `waybackurls` — https://github.com/tomnomnom/waybackurls
- `trufflehog` — https://github.com/trufflesecurity/trufflehog (optional, needs `github.org` set in config.yaml)
- `wappalyzer` (CLI build) — optional, httpx's tech-detect covers the basics if missing
- `retire` (retire.js) — optional, scans JS files from stage 5 for vulnerable versions
- `eyewitness` — optional, final screenshot pass

You also need a wordlist for directory brute-forcing (stage 5) —
`wordlists.directories` in config.yaml, e.g. a SecLists path.

Missing tools don't crash the pipeline — each module reports what it
couldn't run and the orchestrator continues with whatever succeeded.

## Usage

```bash
python cli.py run example.com                # run every registered stage
python cli.py run example.com --stages 1     # scope discovery only
python cli.py run example.com --stages 1,2   # scope discovery + subdomain enum
```

Output goes to `workspaces/<target>/`:
- `raw/<module_name>/` — untouched tool output
- `results.json` — normalized, aggregated findings (written incrementally, after every stage)
- `run.log` — timestamped log of the run

Re-running picks up prior successful stage results from `results.json`,
so `--stages 3` later can still see what stage 1/2 already found.

## Current stages

| Stage | Module | What it does |
|-------|--------|---------------|
| 1 | `scope_discovery` | WHOIS + crt.sh certificate transparency (passive, no direct target contact) |
| 2 | `subdomain_enum` | amass + subfinder, merged with stage 1's crt.sh hostnames, deduped |
| 3 | `live_hosts` | httpx probes stage 2's subdomains, keeps only responding hosts |
| 4 | `port_enum` | naabu for fast port discovery, nmap `-sV` scoped to open ports for service ID |
| 5 | `content_discovery` | gobuster dir brute force per live host + waybackurls (org-wide); JS file URLs separated out as plain output, no parsing |
| 6 | `third_party_exposure` | AWS S3 / Azure Blob / GCS bucket hunting via org-name permutations + optional trufflehog GitHub secret scan |
| 7 | `fingerprint` | wappalyzer-cli per host + retire.js on stage 5's JS files (flags outdated/vulnerable libraries) |
| 8 | `screenshot_triage` | EyeWitness screenshots of all live hosts for fast visual triage |

Stage 6 is org-wide and has no `requires` — it runs even if stages 1-5
failed, since bucket/secret hunting doesn't depend on subdomain discovery.
Stages 3, 4, 5, 7, 8 all `require = ["live_hosts"]` (stage 4 chains through
`port_enum` → `live_hosts` too) and skip in cascade if it didn't succeed.

## Adding a new stage

1. Create `modules/stageN_name.py`, subclass `ReconModule` from `core/module_base.py`
2. Set `stage`, `name`, and optionally `requires = ["other_module_name"]`
3. Implement `run(self, target, workspace, prior_results) -> ModuleResult`
4. Use `core/runner.py`'s `run_command()` for anything that shells out
5. Register the class in `cli.py`'s `REGISTERED_MODULES` list

## Testing without the real tools installed

`test_full_pipeline.py` mocks every external binary with realistic canned
output and runs the actual module logic end-to-end (parsing, merging,
stage-to-stage data flow, the resume/`--stages` seeding behavior) without
needing amass/httpx/nmap/etc. installed or any network access:

```bash
python3 test_full_pipeline.py
```

It asserts on real values (e.g. "4 unique subdomains after case-insensitive
dedupe across 3 sources", "nmap gets scoped to exactly the ports naabu
found"), not just "didn't crash" — useful as a regression check after
editing any module.

## Scope notes

- JS file URLs from stage 5 are intentionally left unparsed — endpoint/secret
  extraction from JS content is a separate concern, handled by BACHunter,
  which consumes this tool's `js_files` output as input.
- Stage 6 only *detects* bucket existence via HTTP HEAD requests. It does not
  attempt to list or read bucket contents (`aws s3 ls`/`cp`) — that's an
  active step with real access implications, left to the operator to run
  deliberately once a bucket is flagged, not automated here.
- All 8 planned stages are now implemented. Possible future additions:
  Nuclei templated vuln scanning on the final asset list, Azure/GCP-specific
  enumeration tools (MicroBurst, GCPBucketBrute) for deeper cloud coverage.
