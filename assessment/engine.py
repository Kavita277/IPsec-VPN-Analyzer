"""Assessment engine: analysis JSON in, findings and posture out.

The engine is deterministic. The same input, policy and ruleset version always
produce byte-identical output (there are no timestamps or random IDs).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict, List, Union

from assessment.models import Finding
from assessment.policy import Policy, load_policy
from assessment.rules import ALL_RULES, RULESET_VERSION, Context
from assessment.scoring import compute_posture

ASSESSMENT_SCHEMA = "assessment-1.0"
SUPPORTED_INPUT_SCHEMAS = {"1.0"}


class InvalidAnalysisError(ValueError):
    """Raised when the input does not look like a Person 1 analysis document."""


def validate_analysis(doc: Any) -> None:
    if not isinstance(doc, dict):
        raise InvalidAnalysisError("Analysis document must be a JSON object")
    version = doc.get("schema_version")
    if version not in SUPPORTED_INPUT_SCHEMAS:
        raise InvalidAnalysisError(
            f"Unsupported schema_version {version!r}; this ruleset reads {sorted(SUPPORTED_INPUT_SCHEMAS)}"
        )
    for key in ("session", "protocol", "negotiation", "security_parameters"):
        if not isinstance(doc.get(key), dict):
            raise InvalidAnalysisError(f"Analysis document is missing the {key!r} object")


def evaluate(doc: Dict[str, Any], policy: Policy) -> List[Finding]:
    ctx = Context(doc, policy)
    findings: List[Finding] = []
    for rule in ALL_RULES:
        findings.extend(rule.check(ctx))
    return sorted(findings, key=Finding.sort_key)


def assess(doc: Dict[str, Any], policy: Union[str, Path, Policy, None] = None) -> Dict[str, Any]:
    """Assess one analysis document and return it extended with findings and posture."""
    validate_analysis(doc)
    pol = load_policy(policy)
    ctx = Context(doc, pol)
    findings = evaluate(doc, pol)

    result = copy.deepcopy(doc)
    result["findings"] = [f.to_dict() for f in findings]
    result["posture"] = compute_posture(findings, ctx.basis, ctx.has_session)
    result["assessment"] = {
        "assessment_schema": ASSESSMENT_SCHEMA,
        "ruleset_version": RULESET_VERSION,
        "policy": pol.summary(),
        "rules_evaluated": [rule.meta.finding_id for rule in ALL_RULES],
    }
    return result


def assess_file(path: Union[str, Path], policy: Union[str, Path, Policy, None] = None) -> Dict[str, Any]:
    path = Path(path)
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InvalidAnalysisError(f"{path} is not valid JSON: {exc}") from None
    return assess(doc, policy)
