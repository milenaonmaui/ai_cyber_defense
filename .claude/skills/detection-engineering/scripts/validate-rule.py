#!/usr/bin/env python3
"""Validate a Sigma rule YAML file against this repo's detection-engineering standards.

Usage:
    python3 validate-rule.py <path/to/rule.yml>

Prints a JSON report to stdout and exits 0 if the rule passes every check, 1 otherwise
(including on argument/parse errors).
"""

import json
import re
import sys

import yaml

ATTACK_TAG_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
VALID_LEVELS = {"low", "medium", "high", "critical"}
TEST_CASE_COMMENT_RE = re.compile(r"^\s*#.*\btest\b", re.IGNORECASE)


def check_attack_tags(rule: dict) -> dict:
    tags = rule.get("tags") or []
    matches = [t for t in tags if isinstance(t, str) and ATTACK_TAG_RE.match(t.lower())]
    non_lowercase = [t for t in matches if t != t.lower()]
    passed = len(matches) > 0 and len(non_lowercase) == 0
    issues = []
    if not matches:
        issues.append("No 'attack.tXXXX' or 'attack.tXXXX.XXX' tag found in 'tags'.")
    if non_lowercase:
        issues.append(
            f"ATT&CK tag(s) not lowercase: {non_lowercase}. Expected e.g. 'attack.t1003.001'."
        )
    return {"passed": passed, "found": matches, "issues": issues}


def check_severity_level(rule: dict) -> dict:
    level = rule.get("level")
    issues = []
    passed = isinstance(level, str) and level in VALID_LEVELS
    if level is None:
        issues.append("No 'level' field present.")
    elif not passed:
        issues.append(
            f"Invalid 'level': {level!r}. Must be one of {sorted(VALID_LEVELS)}."
        )
    return {"passed": passed, "found": level, "issues": issues}


def check_falsepositives(rule: dict) -> dict:
    fps = rule.get("falsepositives")
    issues = []
    passed = isinstance(fps, list) and len(fps) > 0
    if not passed:
        issues.append("No non-empty 'falsepositives' list present.")
    elif [str(fp).strip().lower() for fp in fps] == ["unknown"]:
        issues.append(
            "'falsepositives' is only 'Unknown' — repo standards call for specific benign triggers."
        )
    return {"passed": passed, "found": fps, "issues": issues}


def check_test_case_comment(raw_text: str) -> dict:
    matches = [
        line.strip() for line in raw_text.splitlines() if TEST_CASE_COMMENT_RE.match(line)
    ]
    passed = len(matches) > 0
    issues = []
    if not passed:
        issues.append(
            "No test case comment found (expected a '# ...test...' comment referencing "
            "a sample, e.g. '# Test case: test_samples/<file>')."
        )
    return {"passed": passed, "found": matches, "issues": issues}


def validate(file_path: str) -> dict:
    try:
        with open(file_path, "r") as f:
            raw_text = f.read()
    except OSError as e:
        return {
            "file": file_path,
            "valid": False,
            "checks": {},
            "issues": [f"Could not read file: {e}"],
        }

    try:
        rule = yaml.safe_load(raw_text)
    except yaml.YAMLError as e:
        return {
            "file": file_path,
            "valid": False,
            "checks": {},
            "issues": [f"Could not parse YAML: {e}"],
        }

    if not isinstance(rule, dict):
        return {
            "file": file_path,
            "valid": False,
            "checks": {},
            "issues": ["Parsed YAML is not a mapping (not a valid Sigma rule)."],
        }

    checks = {
        "attack_tags": check_attack_tags(rule),
        "severity_level": check_severity_level(rule),
        "falsepositives": check_falsepositives(rule),
        "test_case_comment": check_test_case_comment(raw_text),
    }

    issues = [issue for check in checks.values() for issue in check["issues"]]
    valid = all(check["passed"] for check in checks.values())

    return {
        "file": file_path,
        "valid": valid,
        "checks": checks,
        "issues": issues,
    }


def main() -> int:
    if len(sys.argv) != 2:
        print(
            json.dumps(
                {
                    "valid": False,
                    "issues": ["Usage: validate-rule.py <path/to/rule.yml>"],
                }
            )
        )
        return 1

    report = validate(sys.argv[1])
    print(json.dumps(report, indent=2))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
