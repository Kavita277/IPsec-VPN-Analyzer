"""Build the verified-facts payload that the explanation layer is allowed to see.

Only values the rule engine already produced are included. The AI never sees
the raw packets and never gets to decide severity, score or what counts as a
finding.
"""

from __future__ import annotations

from typing import Any, Dict


def build_facts(assessed: Dict[str, Any]) -> Dict[str, Any]:
    negotiation = assessed.get("negotiation") or {}
    posture = assessed.get("posture") or {}
    meta = assessed.get("assessment") or {}
    return {
        "session_id": (assessed.get("session") or {}).get("session_id"),
        "ike_version": (assessed.get("protocol") or {}).get("ike_version"),
        "capture_file": (assessed.get("metadata") or {}).get("capture_file"),
        "policy": meta.get("policy"),
        "ruleset_version": meta.get("ruleset_version"),
        "negotiation_status": negotiation.get("status"),
        "offered_proposals": negotiation.get("offered_proposals") or [],
        "negotiated_proposal": negotiation.get("negotiated_proposal"),
        "posture": {
            "score": posture.get("score"),
            "rating": posture.get("rating"),
            "counts": posture.get("counts"),
            "basis": posture.get("basis"),
            "basis_note": posture.get("basis_note"),
        },
        "findings": [
            {
                "key": f["key"],
                "finding_id": f["finding_id"],
                "title": f["title"],
                "severity": f["severity"],
                "scope": f["scope"],
                "observed": f["evidence"]["observed"],
                "expected": f["evidence"]["expected"],
                "evidence": f["evidence"]["items"],
                "why_it_matters": f["why_it_matters"],
                "remediation": f["remediation"],
            }
            for f in assessed.get("findings", [])
        ],
    }
