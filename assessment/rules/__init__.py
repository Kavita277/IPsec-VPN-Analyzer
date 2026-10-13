"""Rule registry. Order here only affects evaluation order, not results."""

from __future__ import annotations

from typing import List

from assessment.rules.algorithms import ALGORITHM_RULES
from assessment.rules.base import Context, Rule
from assessment.rules.negotiation import NEGOTIATION_RULES

# Bump when a rule's logic, default severity or wording changes.
RULESET_VERSION = "1.0.0"

ALL_RULES: List[Rule] = [*NEGOTIATION_RULES, *ALGORITHM_RULES]


def get_rule(finding_id: str) -> Rule:
    for rule in ALL_RULES:
        if rule.meta.finding_id == finding_id:
            return rule
    raise KeyError(finding_id)


__all__ = ["ALL_RULES", "RULESET_VERSION", "Context", "Rule", "get_rule"]
