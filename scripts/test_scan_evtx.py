#!/usr/bin/env python3
"""Quick manual check of scan_evtx() against a sample EVTX file.

Usage:
    python scripts/test_scan_evtx.py [path/to/file.evtx] [min_severity]
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server import ScanError, scan_evtx

DEFAULT_SAMPLE = Path(__file__).resolve().parent.parent / "test_samples" / "discovery_bloodhound.evtx"


def main() -> None:
    file_path = sys.argv[1] if len(sys.argv) > 1 else str(DEFAULT_SAMPLE)
    min_severity = sys.argv[2] if len(sys.argv) > 2 else None

    print(f"Scanning {file_path!r} (min_severity={min_severity!r})...")
    try:
        result = scan_evtx(file_path, min_severity)
    except ScanError as exc:
        print(f"ScanError: {exc}")
        sys.exit(1)

    print(f"total_findings: {result['total_findings']}")
    print(json.dumps(result["findings"][:3], indent=2))


if __name__ == "__main__":
    main()
