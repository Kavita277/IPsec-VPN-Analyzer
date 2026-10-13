"""Core data types for the security assessment engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional


class Severity(IntEnum):
    """Finding severity, ordered so that comparisons and max() work."""

    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def from_label(cls, label: str) -> "Severity":
        try:
            return cls[str(label).strip().upper()]
        except KeyError:
            valid = ", ".join(s.label for s in cls)
            raise ValueError(f"Unknown severity {label!r}; expected one of: {valid}") from None

    def lowered(self, steps: int = 1) -> "Severity":
        """Return the severity `steps` levels lower, floored at Informational."""
        return Severity(max(int(Severity.INFORMATIONAL), int(self) - steps))


@dataclass
class Finding:
    """One evidence-backed security finding.

    Every finding answers the five questions from the team reference (section 21):
    what was observed, why it matters, which rule detected it, what evidence
    supports it, and how it can be remediated.
    """

    finding_id: str
    title: str
    severity: Severity
    category: str
    scope: str  # "negotiated" | "offered" | "session"
    session_id: Optional[str]
    parameter: str
    observed: Any
    expected: str
    why_it_matters: str
    remediation: str
    rule_version: str
    policy_id: str
    standards: List[str] = field(default_factory=list)
    evidence_items: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def key(self) -> str:
        """Stable identity used to match findings across two assessments."""
        return f"{self.finding_id}|{self.scope}|{self.parameter}|{self.observed}"

    def sort_key(self):
        return (-int(self.severity), self.finding_id, self.scope, self.parameter, str(self.observed))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "key": self.key,
            "title": self.title,
            "severity": self.severity.label,
            "category": self.category,
            "scope": self.scope,
            "session_id": self.session_id,
            "rule_version": self.rule_version,
            "policy_id": self.policy_id,
            "evidence": {
                "parameter": self.parameter,
                "observed": self.observed,
                "expected": self.expected,
                "items": [dict(item) for item in self.evidence_items],
            },
            "why_it_matters": self.why_it_matters,
            "remediation": self.remediation,
            "standards": list(self.standards),
        }
