#!/usr/bin/env python3
"""Build mappings/attack_techniques.json from the MITRE ATT&CK STIX bundle.

Downloads (or reads, via --source) the enterprise-attack STIX 2.1 bundle,
extracts each non-deprecated/non-revoked technique (attack-pattern object),
and writes a compact id -> {name, description, tactics, platforms, url,
is_subtechnique} mapping. The full STIX bundle is ~50MB; the resulting
mapping is small enough to check into the repo, so the MCP server doesn't
need network access at runtime.

Usage:
    python scripts/build_attack_mappings.py [--source path/to/enterprise-attack.json]
"""

import argparse
import json
import sys
import urllib.request
from pathlib import Path

ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack.json"
)
OUTPUT_PATH = Path(__file__).resolve().parent.parent / "mappings" / "attack_techniques.json"


def _load_bundle(source: str | None) -> dict:
    if source:
        return json.loads(Path(source).read_text())
    with urllib.request.urlopen(ATTACK_STIX_URL) as resp:
        return json.loads(resp.read())


def _extract_techniques(bundle: dict) -> dict[str, dict]:
    techniques = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = None
        url = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                url = ref.get("url")
                break
        if not technique_id:
            continue

        tactics = sorted(
            {
                phase["phase_name"]
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            }
        )

        techniques[technique_id] = {
            "id": technique_id,
            "name": obj.get("name"),
            "description": (obj.get("description") or "").strip(),
            "tactics": tactics,
            "platforms": sorted(obj.get("x_mitre_platforms", [])),
            "url": url,
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
        }

    return dict(sorted(techniques.items()))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        help="Path to a locally downloaded enterprise-attack.json (skips the network fetch).",
    )
    args = parser.parse_args()

    print(f"Loading ATT&CK STIX bundle{' from ' + args.source if args.source else ' from ' + ATTACK_STIX_URL}...")
    bundle = _load_bundle(args.source)

    techniques = _extract_techniques(bundle)
    print(f"Extracted {len(techniques)} non-deprecated techniques.")

    OUTPUT_PATH.parent.mkdir(exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(techniques, indent=2) + "\n")
    print(f"Wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
