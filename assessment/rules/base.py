"""Shared building blocks for rules: metadata, evaluation context, helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from assessment.models import Finding, Severity
from assessment.policy import Policy

RULE_VERSION = "1.0"

# Evidence field suffixes written by the Person 1 analyzer for each parameter.
EVIDENCE_SUFFIX = {
    "encryption": ".tf.id.encr",
    "integrity": ".tf.id.integ",
    "dh_group": ".tf.id.dh",
}

PARAMETER_LABEL = {
    "encryption": "encryption algorithm",
    "integrity": "integrity algorithm",
    "dh_group": "Diffie-Hellman group",
}

AEAD_MARKERS = ("GCM", "CCM", "CHACHA20-POLY1305")
BARE_AES = re.compile(r"^AES-(CBC|CTR|GCM|CCM.*)$")


def is_aead(encryption: Optional[str]) -> bool:
    return bool(encryption) and any(m in encryption for m in AEAD_MARKERS)


def has_unknown_key_length(encryption: Optional[str]) -> bool:
    """True for names like 'AES-CBC' where the analyzer saw no key length attribute."""
    return bool(encryption) and bool(BARE_AES.match(encryption))


@dataclass(frozen=True)
class RuleMeta:
    finding_id: str
    title: str
    category: str
    default_severity: Severity
    why_it_matters: str
    remediation: str
    standards: Tuple[str, ...] = ()
    version: str = RULE_VERSION


@dataclass(frozen=True)
class Rule:
    meta: RuleMeta
    check: Callable[["Context"], List[Finding]]


Target = Tuple[str, Optional[str]]  # (scope, value)


class Context:
    """Read-only view of one analysis document plus the policy to judge it by."""

    def __init__(self, doc: Dict[str, Any], policy: Policy) -> None:
        self.doc = doc
        self.policy = policy

        session = doc.get("session") or {}
        self.session_id: Optional[str] = session.get("session_id")
        self.ike_version: Optional[str] = (doc.get("protocol") or {}).get("ike_version")

        negotiation = doc.get("negotiation") or {}
        self.status: Optional[str] = negotiation.get("status")
        self.offered: List[Dict[str, Any]] = [
            p for p in (negotiation.get("offered_proposals") or []) if isinstance(p, dict)
        ]
        negotiated = negotiation.get("negotiated_proposal")
        self.negotiated: Optional[Dict[str, Any]] = negotiated if isinstance(negotiated, dict) else None

        params = doc.get("security_parameters") or {}
        selected = {key: params.get(key) for key in EVIDENCE_SUFFIX}
        if not any(selected.values()) and self.negotiated:
            selected = {key: self.negotiated.get(key) for key in EVIDENCE_SUFFIX}
        self.selected: Dict[str, Optional[str]] = selected

        self.evidence: List[Dict[str, Any]] = [e for e in (doc.get("evidence") or []) if isinstance(e, dict)]
        self._response_packets = {
            sa.get("packet")
            for sa in (doc.get("security_associations") or [])
            if isinstance(sa, dict) and sa.get("responder_spi")
        }

    # -- what the capture lets us judge ---------------------------------

    @property
    def has_session(self) -> bool:
        return self.session_id is not None

    @property
    def basis(self) -> str:
        """'negotiated' when the handshake completed, 'offered' when only proposals were seen."""
        if any(self.selected.values()):
            return "negotiated"
        if any(v for p in self.offered for k, v in p.items() if k in EVIDENCE_SUFFIX):
            return "offered"
        return "none"

    def targets(self, parameter: str) -> List[Target]:
        """Values of `parameter` to judge, tagged with the scope they were seen in."""
        if self.basis == "negotiated":
            value = self.selected.get(parameter)
            return [("negotiated", value)] if value else []
        seen: List[str] = []
        for proposal in self.offered:
            value = proposal.get(parameter)
            if value and value not in seen:
                seen.append(value)
        return [("offered", value) for value in seen]

    def offered_values(self, parameter: str) -> List[str]:
        seen: List[str] = []
        for proposal in self.offered:
            value = proposal.get(parameter)
            if value and value not in seen:
                seen.append(value)
        return seen

    # -- evidence --------------------------------------------------------

    def evidence_for(self, parameter: str, value: Optional[str], scope: str) -> List[Dict[str, Any]]:
        """Return the analyzer's own evidence entries that show `value` for `parameter`.

        Nothing is invented: if the analyzer recorded no matching entry, the
        list is empty. For negotiated values the responder's packets win.
        """
        suffix = EVIDENCE_SUFFIX[parameter]
        matches = [
            e for e in self.evidence
            if str(e.get("field", "")).endswith(suffix) and e.get("value") == value
        ]
        if scope == "negotiated":
            from_responder = [e for e in matches if e.get("packet") in self._response_packets]
            matches = from_responder or matches
        return sorted(matches, key=lambda e: (e.get("packet") or 0, str(e.get("field"))))

    def evidence_where(self, field_contains: str) -> List[Dict[str, Any]]:
        return sorted(
            (e for e in self.evidence if field_contains in str(e.get("field", ""))),
            key=lambda e: (e.get("packet") or 0, str(e.get("field"))),
        )

    # -- policy-aware text -----------------------------------------------

    def classify(self, parameter: str, value: Optional[str]) -> str:
        """Place a value in a policy tier.

        Returns one of: missing, null, forbidden, deprecated, unknown_key_length,
        approved, unapproved. An empty 'approved' list means "no allow-list".
        """
        if not value:
            return "missing"
        section = self.policy.section(parameter)
        if parameter == "encryption" and value == "NULL":
            return "null"
        if value in section["forbidden"]:
            return "forbidden"
        if value in section["deprecated"]:
            return "deprecated"
        if parameter == "encryption" and has_unknown_key_length(value):
            return "unknown_key_length"
        if not section["approved"] or value in section["approved"]:
            return "approved"
        return "unapproved"

    def approved_text(self, parameter: str) -> str:
        approved = self.policy.section(parameter)["approved"]
        return ", ".join(approved) if approved else "any value not forbidden or deprecated"

    def recommendation(self) -> str:
        rec = self.policy.recommended
        if not rec:
            return ""
        text = f"A proposal that satisfies policy '{self.policy.policy_id}': {rec.get('encryption')} / {rec.get('integrity')} / {rec.get('dh_group')}"
        if rec.get("strongswan"):
            text += f" (strongSwan swanctl.conf: proposals = {rec['strongswan']})"
        return text + "."

    # -- finding construction -------------------------------------------

    def make_finding(
        self,
        meta: RuleMeta,
        *,
        scope: str,
        parameter: str,
        observed: Any,
        expected: str,
        evidence_items: List[Dict[str, Any]],
        why_extra: str = "",
        remediation_extra: str = "",
        title: Optional[str] = None,
    ) -> Finding:
        severity = self.policy.severity_for(meta.finding_id, meta.default_severity)
        if scope == "offered":
            # A weak option that was only proposed protected no traffic in this capture.
            severity = severity.lowered(1)
        why = meta.why_it_matters
        if scope == "offered":
            why += " This value was only offered, not agreed, so severity is one level lower than if it had been negotiated."
        if why_extra:
            why += " " + why_extra
        remediation = meta.remediation
        if remediation_extra:
            remediation += " " + remediation_extra
        return Finding(
            finding_id=meta.finding_id,
            title=title or meta.title,
            severity=severity,
            category=meta.category,
            scope=scope,
            session_id=self.session_id,
            parameter=parameter,
            observed=observed,
            expected=expected,
            why_it_matters=why,
            remediation=remediation,
            rule_version=meta.version,
            policy_id=self.policy.policy_id,
            standards=list(meta.standards),
            evidence_items=evidence_items,
        )
