"""MCP server that wraps Hayabusa for EVTX analysis."""

from __future__ import annotations

import asyncio
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import mcp.server.stdio
import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

BASE_DIR = Path(__file__).resolve().parent
HAYABUSA_DIR = BASE_DIR / "hayabusa"
HAYABUSA_BIN = HAYABUSA_DIR / "hayabusa"

# Ordered from least to most severe, matching Hayabusa's rule levels.
SEVERITY_LEVELS = ["informational", "low", "medium", "high", "critical"]


class ScanError(Exception):
    """Raised when scan_evtx cannot produce a result."""


def _severity_rank(level: str) -> int:
    try:
        return SEVERITY_LEVELS.index(level.lower())
    except ValueError:
        return -1


def _run_hayabusa(evtx_path: Path, output_path: Path) -> None:
    if not HAYABUSA_BIN.exists():
        raise ScanError(
            f"Hayabusa is not installed: expected binary at {HAYABUSA_BIN}. "
            "Run scripts/install_hayabusa.sh to install it."
        )

    command = [
        str(HAYABUSA_BIN),
        "json-timeline",
        "-f",
        str(evtx_path),
        "-o",
        str(output_path),
        "-w",  # no-wizard: scan for all events and alerts, don't prompt
        "-q",  # quiet: no launch banner
        "-Q",  # quiet-errors: don't write an error log file
        "-K",  # no-color
        "-C",  # clobber: overwrite output file
    ]

    try:
        result = subprocess.run(
            command,
            cwd=HAYABUSA_DIR,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError as exc:
        raise ScanError(f"Failed to execute Hayabusa binary at {HAYABUSA_BIN}: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScanError("Hayabusa scan timed out after 300 seconds") from exc

    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or "no output"
        raise ScanError(f"Hayabusa scan failed (exit code {result.returncode}): {stderr}")


def _load_findings(output_path: Path) -> list[dict[str, Any]]:
    if not output_path.exists():
        # No detections at all: Hayabusa doesn't create the file.
        return []

    text = output_path.read_text().strip()
    if not text:
        return []

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ScanError(f"Could not parse Hayabusa output as JSON: {exc}") from exc

    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise ScanError(f"Unexpected Hayabusa output shape: {type(data).__name__}")

    return data


def scan_evtx(file_path: str, min_severity: str | None = None) -> dict[str, Any]:
    """Scan an EVTX file with Hayabusa and return structured findings.

    Args:
        file_path: Path to the .evtx file to scan.
        min_severity: Optional minimum severity level to include
            (one of: informational, low, medium, high, critical).

    Raises:
        ScanError: if the file is missing, Hayabusa isn't installed,
            min_severity is invalid, or the scan itself fails.
    """
    evtx_path = Path(file_path).expanduser()
    if not evtx_path.exists():
        raise ScanError(f"EVTX file not found: {evtx_path}")
    if not evtx_path.is_file():
        raise ScanError(f"Not a file: {evtx_path}")

    min_rank = 0
    if min_severity is not None:
        min_rank = _severity_rank(min_severity)
        if min_rank == -1:
            raise ScanError(
                f"Invalid min_severity {min_severity!r}: must be one of {SEVERITY_LEVELS}"
            )

    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = Path(tmp_dir) / "hayabusa_output.json"
        _run_hayabusa(evtx_path, output_path)
        all_findings = _load_findings(output_path)

    if min_rank > 0:
        findings = [f for f in all_findings if _severity_rank(str(f.get("Level", ""))) >= min_rank]
    else:
        findings = all_findings

    return {
        "file": str(evtx_path),
        "min_severity": min_severity,
        "total_findings": len(findings),
        "findings": findings,
    }


server = Server("hayabusa")


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="scan_evtx",
            description="Scan a Windows EVTX event log file with Hayabusa and return structured detection findings.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the .evtx file to scan.",
                    },
                    "min_severity": {
                        "type": "string",
                        "enum": SEVERITY_LEVELS,
                        "description": "Only return findings at or above this severity level.",
                    },
                },
                "required": ["file_path"],
            },
        )
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any] | types.CallToolResult:
    if name != "scan_evtx":
        raise ValueError(f"Unknown tool: {name}")

    try:
        return scan_evtx(
            file_path=arguments["file_path"],
            min_severity=arguments.get("min_severity"),
        )
    except ScanError as exc:
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=str(exc))],
            isError=True,
        )


async def _main() -> None:
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="hayabusa",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


def main() -> None:
    asyncio.run(_main())


if __name__ == "__main__":
    main()
