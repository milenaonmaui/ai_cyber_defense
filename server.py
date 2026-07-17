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
import yaml
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

BASE_DIR = Path(__file__).resolve().parent
HAYABUSA_DIR = BASE_DIR / "hayabusa"
HAYABUSA_BIN = HAYABUSA_DIR / "hayabusa"
RULES_DIR = HAYABUSA_DIR / "rules"

DEFAULT_RULES_LIMIT = 100

# Ordered from least to most severe, matching Hayabusa's rule levels.
SEVERITY_LEVELS = ["informational", "low", "medium", "high", "critical"]


class ScanError(Exception):
    """Raised when scan_evtx cannot produce a result."""


class RulesError(Exception):
    """Raised when get_hayabusa_rules cannot produce a result."""


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
    evtx_path = Path(file_path).expanduser().resolve()
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


def _iter_rule_summaries() -> list[dict[str, Any]]:
    """Parse every rule YAML file under RULES_DIR into a compact summary dict.

    Files that fail to parse as YAML, or don't look like rule definitions
    (no title/id), are silently skipped rather than failing the whole scan.
    """
    summaries = []
    for rule_path in sorted(RULES_DIR.rglob("*.yml")):
        try:
            data = yaml.safe_load(rule_path.read_text())
        except yaml.YAMLError:
            continue

        if not isinstance(data, dict) or "title" not in data or "id" not in data:
            continue

        tags = data.get("tags") or []
        if not isinstance(tags, list):
            tags = [tags]

        summaries.append(
            {
                "id": data.get("id"),
                "title": data.get("title"),
                "level": data.get("level"),
                "status": data.get("status"),
                "description": (data.get("description") or "").strip(),
                "tags": tags,
                "path": str(rule_path.relative_to(RULES_DIR)),
            }
        )

    return summaries


def get_hayabusa_rules(
    keyword: str | None = None, limit: int = DEFAULT_RULES_LIMIT
) -> dict[str, Any]:
    """List available Hayabusa detection rules, optionally filtered by keyword.

    Args:
        keyword: Optional case-insensitive substring to match against a
            rule's title, description, tags, or id.
        limit: Maximum number of matching rules to return (default 100).

    Raises:
        RulesError: if the rules directory is missing or limit is invalid.
    """
    if not RULES_DIR.exists():
        raise RulesError(
            f"Hayabusa rules directory not found: {RULES_DIR}. "
            "Run scripts/install_hayabusa.sh to install it."
        )
    if limit < 1:
        raise RulesError(f"Invalid limit {limit!r}: must be a positive integer")

    all_rules = _iter_rule_summaries()

    if keyword:
        needle = keyword.lower()

        def _matches(rule: dict[str, Any]) -> bool:
            haystacks = [
                str(rule.get("title") or ""),
                str(rule.get("description") or ""),
                str(rule.get("id") or ""),
                " ".join(rule.get("tags") or []),
            ]
            return any(needle in h.lower() for h in haystacks)

        matches = [r for r in all_rules if _matches(r)]
    else:
        matches = all_rules

    return {
        "keyword": keyword,
        "total_matches": len(matches),
        "returned": min(len(matches), limit),
        "rules": matches[:limit],
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
        ),
        types.Tool(
            name="get_hayabusa_rules",
            description="List available Hayabusa detection rules, optionally filtered by a keyword matched against title, description, tags, or id.",
            inputSchema={
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": "Case-insensitive substring to filter rules by (matched against title, description, tags, and id).",
                    },
                    "limit": {
                        "type": "integer",
                        "description": f"Maximum number of matching rules to return (default {DEFAULT_RULES_LIMIT}).",
                        "minimum": 1,
                    },
                },
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any] | types.CallToolResult:
    try:
        if name == "scan_evtx":
            return scan_evtx(
                file_path=arguments["file_path"],
                min_severity=arguments.get("min_severity"),
            )
        if name == "get_hayabusa_rules":
            return get_hayabusa_rules(
                keyword=arguments.get("keyword"),
                limit=arguments.get("limit", DEFAULT_RULES_LIMIT),
            )
        raise ValueError(f"Unknown tool: {name}")
    except (ScanError, RulesError) as exc:
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
