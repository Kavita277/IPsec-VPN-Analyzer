#!/usr/bin/env python3
"""CLI for the security assessment engine (Person 2 module).

Usage:
    python assess.py analysis/weak_01.json
    python assess.py analysis/ --policy nist-baseline --policy cnsa-strict
    python assess.py --compare before.json after.json
    python assess.py --list-policies
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from assessment import (
    InvalidAnalysisError,
    PolicyError,
    assess,
    compare,
    list_policies,
    load_policy,
)


def _inputs(paths: List[str]) -> List[Path]:
    files: List[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            files.extend(sorted(x for x in p.glob("*.json") if not x.name.endswith(".assessed.json")))
        else:
            files.append(p)
    return files


def _load(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise InvalidAnalysisError(f"File not found: {path}") from None
    except json.JSONDecodeError as exc:
        raise InvalidAnalysisError(f"{path} is not valid JSON: {exc}") from None


def _assessed(path: Path, policy: str) -> Dict[str, Any]:
    """Load a document; assess it first if it has not been assessed yet."""
    doc = _load(path)
    return doc if "findings" in doc and "posture" in doc else assess(doc, policy)


def _print_summary(result: Dict[str, Any], label: str) -> None:
    posture = result["posture"]
    score = "n/a" if posture["score"] is None else posture["score"]
    print(f"{label}  [{result['assessment']['policy']['id']}]  score {score}  {posture['rating']}")
    for f in result["findings"]:
        print(f"    {f['severity']:<13} {f['finding_id']:<15} {f['title']} ({f['scope']}: {f['evidence']['observed']})")


def _print_comparison(diff: Dict[str, Any]) -> None:
    pc = diff["posture_change"]
    print(f"Verdict: {pc['verdict']}  (score {diff['before']['score']} -> {diff['after']['score']}, "
          f"{pc['rating_before']} -> {pc['rating_after']})")
    for ch in diff["parameter_changes"]:
        print(f"  changed {ch['parameter']}: {ch['before']} -> {ch['after']}")
    for key, header in (("resolved", "resolved"), ("introduced", "introduced"), ("unchanged", "unchanged")):
        for f in diff[key]:
            print(f"  {header:<10} {f['severity']:<13} {f['finding_id']} ({f['scope']}: {f['observed']})")
    for w in diff["warnings"]:
        print(f"  warning: {w}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Assess analyzed IPsec sessions against a security policy.")
    ap.add_argument("inputs", nargs="*", help="Analysis JSON files or directories (output of analyze.py)")
    ap.add_argument("-p", "--policy", action="append", help="Policy id or path (repeatable; default: nist-baseline)")
    ap.add_argument("-o", "--output", default="assessments", help="Output directory (default: assessments)")
    ap.add_argument("--compare", nargs=2, metavar=("BEFORE", "AFTER"), help="Compare two sessions' findings and posture")
    ap.add_argument("--json", action="store_true", help="With --compare, print the diff as JSON")
    ap.add_argument("--list-policies", action="store_true", help="List bundled policies and exit")
    args = ap.parse_args()

    try:
        if args.list_policies:
            for pid in list_policies():
                pol = load_policy(pid)
                print(f"{pid:<16} {pol.name}")
            return 0

        policies = args.policy or ["nist-baseline"]

        if args.compare:
            before, after = (_assessed(Path(p), policies[0]) for p in args.compare)
            diff = compare(before, after)
            print(json.dumps(diff, indent=2)) if args.json else _print_comparison(diff)
            return 0

        files = _inputs(args.inputs)
        if not files:
            ap.error("give at least one analysis JSON file or directory")

        out_dir = Path(args.output)
        out_dir.mkdir(parents=True, exist_ok=True)
        for path in files:
            doc = _load(path)
            for policy in policies:
                result = assess(doc, policy)
                pid = result["assessment"]["policy"]["id"]
                out = out_dir / f"{path.stem}.{pid}.assessed.json"
                out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
                _print_summary(result, path.name)
                print(f"    -> {out}")
        return 0

    except (InvalidAnalysisError, PolicyError, ValueError) as err:
        print(f"[ERROR] {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
