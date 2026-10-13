"""Explanation entry point with a guard between the model and the report.

The model may only word things. `guard` drops any part of its answer that
refers to a finding that does not exist, is malformed, or is empty, and the
template text fills the gap. Each piece records whether it came from the model
or the template, so a reader can tell.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ai.facts import build_facts
from ai.providers import ProviderError, TemplateProvider, get_provider, template_finding, template_summary

FINDING_ID = re.compile(r"IPSEC-[A-Z]+-\d{3}")
MAX_TEXT = 1500
MAX_STEPS = 8


def _clean(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value if value and len(value) <= MAX_TEXT else None


def _only_known_ids(text: str, allowed: set) -> bool:
    return all(found in allowed for found in FINDING_ID.findall(text))


def guard(raw: Any, facts: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only well-formed model output that stays inside the verified facts."""
    allowed_ids = {f["finding_id"] for f in facts["findings"]}
    valid_keys = {f["key"] for f in facts["findings"]}
    result: Dict[str, Any] = {"summary": None, "findings": {}, "rejected": []}
    if not isinstance(raw, dict):
        result["rejected"].append("response was not a JSON object")
        return result

    summary = _clean(raw.get("summary"))
    if summary and _only_known_ids(summary, allowed_ids):
        result["summary"] = summary
    elif raw.get("summary") is not None:
        result["rejected"].append("summary")

    items = raw.get("findings")
    if not isinstance(items, dict):
        result["rejected"].append("findings")
        return result
    for key, entry in items.items():
        if key not in valid_keys:
            result["rejected"].append(f"unknown finding {str(key)[:40]}")
            continue
        if not isinstance(entry, dict):
            result["rejected"].append(str(key))
            continue
        explanation, impact = _clean(entry.get("explanation")), _clean(entry.get("impact"))
        steps = entry.get("remediation_steps")
        steps = [s.strip() for s in steps if isinstance(s, str) and s.strip()] if isinstance(steps, list) else []
        steps = steps[:MAX_STEPS]
        text_blob = " ".join(filter(None, [explanation, impact, *steps]))
        if not (explanation and impact and steps) or not _only_known_ids(text_blob, allowed_ids):
            result["rejected"].append(str(key))
            continue
        result["findings"][key] = {"explanation": explanation, "impact": impact, "remediation_steps": steps}
    return result


def explain(assessed: Dict[str, Any], provider: Optional[str] = None, transport=None) -> Dict[str, Any]:
    """Return plain-language explanations for an assessed document.

    Never raises for provider problems: it falls back to template text and says why.
    """
    facts = build_facts(assessed)
    policy_id = (facts.get("policy") or {}).get("id", "")
    warnings: List[str] = []

    try:
        chosen = get_provider(provider, transport=transport)
    except ProviderError as exc:
        warnings.append(f"AI provider unavailable ({exc}); used template text.")
        chosen = TemplateProvider()

    guarded: Dict[str, Any] = {"summary": None, "findings": {}, "rejected": []}
    if chosen.name != "template":
        try:
            guarded = guard(chosen.generate(facts), facts)
        except ProviderError as exc:
            warnings.append(f"AI provider failed ({exc}); used template text.")
            chosen = TemplateProvider()
        if guarded["rejected"]:
            warnings.append(f"Discarded unusable AI output for: {', '.join(guarded['rejected'])}.")

    findings: Dict[str, Any] = {}
    for f in facts["findings"]:
        if f["key"] in guarded["findings"]:
            findings[f["key"]] = {**guarded["findings"][f["key"]], "source": chosen.name}
        else:
            findings[f["key"]] = {**template_finding(f, policy_id), "source": "template"}

    return {
        "summary": {
            "text": guarded["summary"] or template_summary(facts),
            "source": chosen.name if guarded["summary"] else "template",
        },
        "findings": findings,
        "ai": {"provider": chosen.name, "model": chosen.model, "warnings": warnings},
        "notice": (
            "Severity, score and findings come from the deterministic rule engine. "
            "Explanations only reword those verified facts."
        ),
    }
