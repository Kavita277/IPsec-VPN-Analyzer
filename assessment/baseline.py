"""Baseline comparison: what changed between two assessments of the same VPN.

Use it for before/after remediation checks and for regression tests after a
configuration or software change. Both inputs are assessed documents produced
by `assessment.assess`.
"""

from __future__ import annotations

from typing import Any, Dict, List

PARAMETERS = ("encryption", "integrity", "dh_group")


def _summary(doc: Dict[str, Any]) -> Dict[str, Any]:
    posture = doc.get("posture") or {}
    return {
        "session_id": (doc.get("session") or {}).get("session_id"),
        "capture_file": (doc.get("metadata") or {}).get("capture_file"),
        "negotiation_status": (doc.get("negotiation") or {}).get("status"),
        "policy": (doc.get("assessment") or {}).get("policy"),
        "ruleset_version": (doc.get("assessment") or {}).get("ruleset_version"),
        "score": posture.get("score"),
        "rating": posture.get("rating"),
        "basis": posture.get("basis"),
        "parameters": dict((doc.get("security_parameters") or {})),
    }


def _brief(finding: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "finding_id": finding["finding_id"],
        "key": finding["key"],
        "title": finding["title"],
        "severity": finding["severity"],
        "scope": finding["scope"],
        "observed": finding["evidence"]["observed"],
    }


def compare(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two assessed documents."""
    for name, doc in (("before", before), ("after", after)):
        if "findings" not in doc or "posture" not in doc:
            raise ValueError(f"The {name!r} document has not been assessed (no findings/posture)")

    b_sum, a_sum = _summary(before), _summary(after)
    b_find = {f["key"]: f for f in before["findings"]}
    a_find = {f["key"]: f for f in after["findings"]}

    resolved = [_brief(b_find[k]) for k in b_find if k not in a_find]
    introduced = [_brief(a_find[k]) for k in a_find if k not in b_find]
    unchanged = [_brief(a_find[k]) for k in a_find if k in b_find]

    changes: List[Dict[str, Any]] = []
    for parameter in PARAMETERS:
        old, new = b_sum["parameters"].get(parameter), a_sum["parameters"].get(parameter)
        if old != new:
            changes.append({"parameter": parameter, "before": old, "after": new})

    warnings: List[str] = []
    if b_sum["policy"] != a_sum["policy"]:
        warnings.append("The two assessments used different policies; differences may come from the policy, not the VPN.")
    if b_sum["ruleset_version"] != a_sum["ruleset_version"]:
        warnings.append("The two assessments used different ruleset versions.")
    if "offered" in (b_sum["basis"], a_sum["basis"]) and b_sum["basis"] != a_sum["basis"]:
        warnings.append("One assessment is based on offered proposals only (failed handshake); scores are not directly comparable.")

    score_delta = None
    if b_sum["score"] is not None and a_sum["score"] is not None:
        score_delta = a_sum["score"] - b_sum["score"]

    if score_delta is None:
        verdict = "not comparable"
    elif score_delta > 0:
        verdict = "improved"
    elif score_delta < 0:
        verdict = "regressed"
    else:
        verdict = "unchanged" if not resolved and not introduced else "changed"

    return {
        "before": b_sum,
        "after": a_sum,
        "parameter_changes": changes,
        "resolved": resolved,
        "introduced": introduced,
        "unchanged": unchanged,
        "posture_change": {
            "score_delta": score_delta,
            "rating_before": b_sum["rating"],
            "rating_after": a_sum["rating"],
            "verdict": verdict,
        },
        "warnings": warnings,
    }
