# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Status

Implemented. `server.py` runs a working MCP server exposing the `scan_evtx` tool.

## Project Overview

This project is an MCP (Model Context Protocol) server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) for EVTX (Windows Event Log) analysis.

## Stack

- Python, using the `mcp` library's low-level `Server` API (`mcp.server.lowlevel.Server`) — chosen over `FastMCP` for explicit control over tool schema and result construction
- Hayabusa CLI, installed locally under `hayabusa/`, invoked as a subprocess

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
  - `list_tools()` / `call_tool()`: registered via `@server.list_tools()` / `@server.call_tool()` decorators on the low-level `Server` instance. `call_tool` dispatches by tool name, calls `scan_evtx`, and returns either the result dict (auto-serialized to JSON text + `structuredContent` by the low-level API) or a `CallToolResult(isError=True)` on `ScanError`.
  - `main()` wires stdio transport (`mcp.server.stdio.stdio_server`) and runs the server loop.

## Testing

- `scripts/test_scan_evtx.py`: standalone script that imports `scan_evtx` directly from `server.py` (no MCP transport involved) and runs it against a sample file. Usage: `python scripts/test_scan_evtx.py [path/to/file.evtx] [min_severity]`.
- `test_samples/`: holds EVTX files pulled from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) for manual testing (e.g. `discovery_bloodhound.evtx`, which contains one `high`-severity "Log Cleared" finding).

## Next Steps

- No formal test suite (pytest) yet — `scripts/test_scan_evtx.py` is a manual smoke-test script, not an automated one.
- No lint/type-check tooling configured yet.
