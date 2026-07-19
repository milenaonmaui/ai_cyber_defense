# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Status

Implemented. `server.py` runs a working MCP server exposing the `scan_evtx` and `get_hayabusa_rules` tools, plus `detection://` resources over a curated `rules/` directory of Sigma rules and a local ATT&CK technique reference (`mappings/attack_techniques.json`).

## Project Overview

This project is an MCP (Model Context Protocol) server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) for EVTX (Windows Event Log) analysis, and is being expanded into a broader detection engineering knowledge base server.

Goals for the knowledge base expansion:
- Expose Sigma rules as browsable MCP resources (done — `detection://rules*`)
- Expose ATT&CK technique-to-rule mappings (done — `detection://attack/techniques/{technique_id}`)
- Allow Claude to query detection coverage, e.g. "which techniques have no matching rule?" (done per-technique via the `coverage` field; no aggregate/bulk "list all gaps" resource yet)
- Combine with the Hayabusa scanning tools (`scan_evtx`, `get_hayabusa_rules`) so coverage/mapping queries and live EVTX scans work together

Structure:
- `rules/` - curated Sigma detection rules (YAML), independent of the vendored `hayabusa/rules/` copy used for scanning. Organized into subdirectories by ATT&CK tactic, e.g. `rules/credential_access/`, `rules/lateral_movement/`. Backs the `detection://rules*` MCP resources.
- `mappings/attack_techniques.json` - compact `technique_id -> {name, description, tactics, platforms, url, is_subtechnique}` reference, generated offline by `scripts/build_attack_mappings.py` from the ~50MB [MITRE ATT&CK STIX bundle](https://github.com/mitre-attack/attack-stix-data) so the server itself needs no network access at request time. Regenerate with `python scripts/build_attack_mappings.py` (add `--source path/to/enterprise-attack.json` to use an already-downloaded copy instead of fetching it).
- `server.py` - MCP server, exposing both tools and `detection://` resources

## Stack

- Python, using the `mcp` library's low-level `Server` API (`mcp.server.lowlevel.Server`) — chosen over `FastMCP` for explicit control over tool schema and result construction
- Hayabusa CLI, installed locally under `hayabusa/`, invoked as a subprocess
- `pyyaml`, used to parse rule definition files under `hayabusa/rules/` for `get_hayabusa_rules`

## Setup

```
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
scripts/install_hayabusa.sh   # downloads the Hayabusa release for this platform into hayabusa/
```

## Architecture

- `server.py`
  - `scan_evtx(file_path, min_severity=None) -> dict`: the actual scan logic, independent of MCP. Validates the EVTX file exists, shells out to the Hayabusa binary (`hayabusa/hayabusa`, a symlink managed by the install script) running `json-timeline -f <file> -o <tmp>` with `-w -q -Q -K -C` (no wizard/banner/error-log/color, clobber output), run with `cwd=HAYABUSA_DIR` so Hayabusa's default relative rule paths (`./rules`, `./rules/config`) resolve. Parses the resulting JSON array from a temp file, filters by `Level` against `min_severity` (rank order: informational < low < medium < high < critical), and returns `{file, min_severity, total_findings, findings}`.
  - `ScanError`: raised for missing file, missing Hayabusa binary, invalid `min_severity`, non-zero/timeout subprocess exit, or unparseable output. Caught in the tool layer and turned into an MCP error result (`isError=True`) rather than propagating.
  - `get_hayabusa_rules(keyword=None, limit=100) -> dict`: lists Hayabusa/Sigma detection rules so a caller can see what's available before scanning. Recursively globs `hayabusa/rules/**/*.yml` (via `_iter_rule_summaries`), parses each with `yaml.safe_load`, and skips files that fail to parse or lack a `title`/`id` (e.g. files under `rules/config/`). Each summary carries `id`, `title`, `level`, `status`, `description`, `tags`, and `path` (relative to `hayabusa/rules/`). If `keyword` is given, does a case-insensitive substring match against title/description/id/tags. Results are capped by `limit` (default 100); the response reports `total_matches` (before truncation) vs `returned` so callers know if results were cut off. Returns `{keyword, total_matches, returned, rules}`.
  - `RulesError`: raised for a missing rules directory or invalid `limit`. Caught the same way as `ScanError`.
  - `list_tools()` / `call_tool()`: registered via `@server.list_tools()` / `@server.call_tool()` decorators on the low-level `Server` instance. `call_tool` dispatches by tool name to `scan_evtx` or `get_hayabusa_rules`, and returns either the result dict (auto-serialized to JSON text + `structuredContent` by the low-level API) or a `CallToolResult(isError=True)` on `ScanError`/`RulesError`.
  - Detection knowledge base resources, backed by `SIGMA_RULES_DIR` (`rules/` at the repo root, distinct from `HAYABUSA_DIR`'s vendored copy):
    - `_iter_sigma_rules()`: recursively globs `rules/**/*.yml`, parses each with `yaml.safe_load`, skips unparseable files or ones missing `title`/`id`. Each summary carries `rule_name` (filename stem, used as the resource identifier), `id`, `title`, `level`, `status`, `description`, `tags`, `techniques` (see `_extract_techniques`), and `path` (relative to `rules/`).
    - `_extract_techniques(tags)`: pulls ATT&CK technique IDs out of `attack.tXXXX` / `attack.tXXXX.XXX` tags via `TECHNIQUE_TAG_RE`, normalized to uppercase (e.g. `T1003.001`).
    - `list_sigma_rules() -> dict`: all rule summaries, backs the static `detection://rules` resource. Returns `{total, rules}`.
    - `get_sigma_rule(rule_name) -> str`: raw YAML text of one rule file, looked up by filename stem via `_find_sigma_rule_path`. Backs the `detection://rules/{rule_name}` resource template. Raises `ResourceError` if no rule matches.
    - `list_sigma_rules_by_technique(technique_id) -> dict`: rule summaries whose `techniques` include the given ID (case-insensitive). Backs `detection://rules/by-technique/{technique_id}`. Returns `{technique_id, total, rules}`.
    - `_load_attack_techniques()`: reads and `lru_cache`s `mappings/attack_techniques.json` (see Project Overview) into an `id -> technique` dict. Raises `ResourceError` if the file is missing (i.e. `scripts/build_attack_mappings.py` hasn't been run).
    - `get_attack_technique(technique_id) -> dict`: backs `detection://attack/techniques/{technique_id}`. Looks up the technique in `_load_attack_techniques()` (raises `ResourceError` if unknown), finds Sigma rules whose `techniques` include it, and assesses coverage: `"gap"` if no rule matches, `"covered"` if at least one matching rule has `status: stable` (see `STABLE_RULE_STATUSES`), else `"partial"`. Returns `{technique_id, name, description, tactics, platforms, url, is_subtechnique, coverage, detecting_rules}`.
    - `ResourceError`: raised for a missing `rules/` directory, an unknown rule name, a missing `mappings/attack_techniques.json`, or an unknown ATT&CK technique id. Caught in `read_resource` and re-raised as `ValueError`.
    - `list_resources()` / `list_resource_templates()` / `read_resource(uri)`: registered via `@server.list_resources()` / `@server.list_resource_templates()` / `@server.read_resource()`. `list_resources` advertises the static `detection://rules` resource; `list_resource_templates` advertises the `{rule_name}`, `by-technique/{technique_id}`, and `attack/techniques/{technique_id}` templates. `read_resource` parses the `detection://...` URI path segments itself (the low-level API does no template matching) and dispatches to `list_sigma_rules`, `list_sigma_rules_by_technique`, `get_sigma_rule`, or `get_attack_technique`, JSON-encoding dict results.
  - `main()` wires stdio transport (`mcp.server.stdio.stdio_server`) and runs the server loop.

## Testing

- `scripts/test_scan_evtx.py`: standalone script that imports `scan_evtx` directly from `server.py` (no MCP transport involved) and runs it against a sample file. Usage: `python scripts/test_scan_evtx.py [path/to/file.evtx] [min_severity]`.
- `test_samples/`: holds EVTX files pulled from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) for manual testing (e.g. `discovery_bloodhound.evtx`, which contains one `high`-severity "Log Cleared" finding).

## Next Steps

- No formal test suite (pytest) yet — `scripts/test_scan_evtx.py` is a manual smoke-test script, not an automated one.
- No lint/type-check tooling configured yet.
- No automated tests for the `detection://` resources yet.
- No aggregate coverage resource yet (e.g. "list every technique with coverage=gap across all of ATT&CK") — `detection://attack/techniques/{technique_id}` is per-technique only, and `mappings/attack_techniques.json` isn't kept fresh automatically (rerun `scripts/build_attack_mappings.py` to pick up ATT&CK updates).
