"""Posture calculation from individual findings.

The model is deliberately simple so a reviewer can reproduce it by hand:

    score  = max(0, 100 - sum(weight[severity] for every finding))
    rating = taken from the highest severity present

Weights change only with a ruleset version bump.
"""

from __future__ import annotations

from typing import Any, Dict, List

from assessment.models import Finding, Severity

WEIGHTS: Dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 25,
    Severity.MEDIUM: 10,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 0,
}

RATING_BY_HIGHEST = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High risk",
    Severity.MEDIUM: "Moderate risk",
    Severity.LOW: "Low risk",
    Severity.INFORMATIONAL: "Compliant",
}

BASIS_NOTE = {
    "negotiated": "Judged on the parameters the peers actually negotiated.",
    "offered": "The handshake did not complete, so this reflects the proposals that were offered, not an established tunnel.",
    "none": "No algorithm parameters were observed, so no posture can be stated.",
}


def compute_posture(findings: List[Finding], basis: str, has_session: bool) -> Dict[str, Any]:
    counts = {s.label: 0 for s in sorted(Severity, reverse=True)}
    for finding in findings:
        counts[finding.severity.label] += 1

    if not has_session or basis == "none":
        return {
            "score": None,
            "rating": "Not assessable",
            "highest_severity": None,
            "counts": counts,
            "basis": basis if has_session else "none",
            "basis_note": BASIS_NOTE["none"],
        }

    deduction = sum(WEIGHTS[f.severity] for f in findings)
    highest = max((f.severity for f in findings), default=Severity.INFORMATIONAL)
    return {
        "score": max(0, 100 - deduction),
        "rating": RATING_BY_HIGHEST[highest],
        "highest_severity": highest.label if findings else None,
        "counts": counts,
        "basis": basis,
        "basis_note": BASIS_NOTE[basis],
    }
