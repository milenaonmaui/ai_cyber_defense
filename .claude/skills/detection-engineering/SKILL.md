---
name: detection-engineering
description: Use when writing or creating Sigma rules, reviewing detection rules, discussing detection coverage, or working with YAML detection files (e.g. anything under rules/ or hayabusa/rules/). Enforces this repo's detection rule standards before a rule is considered done.
---

# Detection Engineering Standards

Applies to every Sigma rule in `rules/` (and any new rule proposed for it). Enforce these
standards whenever you write, edit, or review a rule — do not treat them as optional style
suggestions.

## Required standards

1. **ATT&CK technique mapping is mandatory.**
   Every rule's `tags` must include at least one `attack.tXXXX` (or `attack.tXXXX.XXX` for a
   sub-technique) entry, lowercase, e.g. `attack.t1003.001`. A rule with no technique tag is
   incomplete — do not approve or merge it as-is. Cross-check the technique ID actually exists
   (see `mappings/attack_techniques.json` or `detection://attack/techniques/{technique_id}`) —
   don't invent IDs.

2. **`level` must be one of `low`, `medium`, `high`, `critical` — with justification.**
   No other value (e.g. `informational`) is acceptable for a detection rule in this repo.
   The justification for the chosen severity doesn't have to be a separate YAML field, but it
   must exist somewhere human-readable — typically folded into `description`, e.g. "High: direct
   evidence of credential dumping via LSASS access, low false-positive rate." If a rule sets a
   severity with no reasoning anywhere in the file, ask for one before treating the rule as done.

3. **False positive conditions must be documented.**
   Every rule needs a `falsepositives` field listing realistic benign triggers (e.g. "Administrative
   scripts", "Backup software", "Legitimate use of PsExec by IT staff"). `falsepositives: - Unknown`
   alone is not sufficient — push for specifics based on what the detection logic actually matches.

4. **At least one test case is required.**
   Every rule needs a companion test case demonstrating it fires on expected malicious activity
   (e.g. a sample EVTX/log snippet, or a reference to one in `test_samples/`, plus the expected
   match). A rule with detection logic but no evidence it was ever validated against real or
   synthetic data is not done. If a rule lacks a test case, flag it and either add one or ask the
   user how they want it covered.

5. **Rule filenames must be lowercase with underscores.**
   E.g. `credential_dumping_lsass.yml`, not `Credential-Dumping-LSASS.yml` or
   `credentialDumpingLsass.yml`. This applies to the filename (which also becomes `rule_name` /
   the resource identifier for `detection://rules/{rule_name}`), not necessarily the YAML `title`
   field, which can stay human-readable.

## When reviewing an existing rule

Check all five items above in order and call out every violation found, not just the first one.
Point at the specific missing/invalid field rather than giving a vague "doesn't meet standards"
verdict. If a rule is otherwise well-formed except for one gap (e.g. missing `falsepositives`),
say so precisely so it's a quick fix.

## When writing a new rule

Don't hand back a rule missing any of the five items — treat them as required fields for a
"finished" rule, not follow-up polish. If you don't have enough information to fill one in
(e.g. you're unsure of the correct ATT&CK technique, or don't have a real sample to build a test
case from), say so explicitly and ask, rather than guessing or leaving it out silently.

## When discussing detection coverage

Coverage claims should be grounded in the technique mapping (standard 1) — a technique only
counts as "covered" if a rule both maps to it via `attack.tXXXX` and meets the other four
standards above. A rule that maps to a technique but has no test case or no documented false
positives is a weaker claim of coverage; say so rather than counting it the same as a fully
compliant rule.
