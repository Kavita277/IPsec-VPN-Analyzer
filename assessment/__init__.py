"""Security assessment engine (Person 2).

Turns normalized IPsec facts from the analyzer into deterministic,
evidence-backed findings and a posture score.
"""

from assessment.baseline import compare
from assessment.engine import InvalidAnalysisError, assess, assess_file
from assessment.models import Finding, Severity
from assessment.policy import Policy, PolicyError, list_policies, load_policy
from assessment.rules import ALL_RULES, RULESET_VERSION

__all__ = [
    "ALL_RULES",
    "Finding",
    "InvalidAnalysisError",
    "Policy",
    "PolicyError",
    "RULESET_VERSION",
    "Severity",
    "assess",
    "assess_file",
    "compare",
    "list_policies",
    "load_policy",
]
