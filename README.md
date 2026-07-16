# mcp-hayabusa

An MCP (Model Context Protocol) server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) for EVTX (Windows Event Log) analysis. It exposes a single `scan_evtx` tool that runs Hayabusa against an EVTX file and returns structured JSON findings, optionally filtered by minimum severity.

## Requirements

- Python 3.12+
- macOS or Linux (the install script fetches the matching Hayabusa release for your platform)

## Setup

```bash
git clone git@github.com:milenaonmaui/ai_cyber_defense.git
cd ai_cyber_defense

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

scripts/install_hayabusa.sh
```

`scripts/install_hayabusa.sh` downloads the latest Hayabusa release for your OS/architecture into `hayabusa/`, and creates a stable `hayabusa/hayabusa` symlink to the versioned binary. Re-run it any time to update Hayabusa.

## Running the server

```bash
python3 server.py
```

This starts the MCP server over stdio. Point an MCP-compatible client (e.g. Claude Code, Claude Desktop) at this command to make the `scan_evtx` tool available.

### `scan_evtx` tool

| Argument | Type | Required | Description |
|---|---|---|---|
| `file_path` | string | yes | Path to the `.evtx` file to scan |
| `min_severity` | string | no | One of `informational`, `low`, `medium`, `high`, `critical` — only findings at or above this level are returned |

Returns a JSON object:

```json
{
  "file": "...",
  "min_severity": "high",
  "total_findings": 1,
  "findings": [ { "Timestamp": "...", "RuleTitle": "...", "Level": "high", "...": "..." } ]
}
```

On failure (missing file, missing Hayabusa binary, invalid `min_severity`, or a scan error), the tool returns an MCP error result with a human-readable message.

## Testing

`scripts/test_scan_evtx.py` calls `scan_evtx()` directly (no MCP transport involved), against a sample EVTX file:

```bash
python3 scripts/test_scan_evtx.py                                   # uses test_samples/discovery_bloodhound.evtx
python3 scripts/test_scan_evtx.py path/to/file.evtx high            # custom file + min_severity
```

`test_samples/` contains sample EVTX files pulled from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) for manual testing.

## Project layout

```
server.py                    MCP server: scan_evtx logic + tool registration
scripts/install_hayabusa.sh  Downloads/updates the Hayabusa binary into hayabusa/
scripts/test_scan_evtx.py    Manual smoke test for scan_evtx()
test_samples/                Sample .evtx files for testing
hayabusa/                    Installed Hayabusa binary + rules (gitignored)
```
