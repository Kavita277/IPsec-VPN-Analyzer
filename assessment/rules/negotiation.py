"""Protocol, negotiation-behaviour and observability rules."""

from __future__ import annotations

from typing import Any, Dict, List

from assessment.models import Finding, Severity
from assessment.rules.base import EVIDENCE_SUFFIX, Context, Rule, RuleMeta

RFC_7296 = "RFC 7296"
RFC_9395 = "RFC 9395"
RFC_8247 = "RFC 8247"

# --- PROTO-001: IKE version -------------------------------------------

_PROTO_001 = RuleMeta(
    finding_id="IPSEC-PROTO-001",
    title="IKE version not allowed by policy",
    category="protocol",
    default_severity=Severity.HIGH,
    why_it_matters=(
        "IKEv1 has been formally deprecated (RFC 9395). Its aggressive mode with pre-shared keys can "
        "expose material that is open to offline guessing, and current IPsec guidance expects IKEv2."
    ),
    remediation="Reconfigure both peers to use IKEv2 only.",
    standards=(RFC_9395, RFC_7296),
)


def _check_proto_001(ctx: Context) -> List[Finding]:
    if not ctx.ike_version or ctx.ike_version in ctx.policy.ike_versions:
        return []
    return [
        ctx.make_finding(
            _PROTO_001,
            scope="session",
            parameter="ike_version",
            observed=ctx.ike_version,
            expected=f"One of: {', '.join(ctx.policy.ike_versions)}",
            evidence_items=ctx.evidence_where(".version"),
        )
    ]


PROTO_001 = Rule(_PROTO_001, _check_proto_001)

# --- NEG-001: negotiation failed --------------------------------------

_NEG_001 = RuleMeta(
    finding_id="IPSEC-NEG-001",
    title="IKE negotiation failed",
    category="negotiation",
    default_severity=Severity.MEDIUM,
    why_it_matters=(
        "The tunnel was not established, so this session protects no traffic. A failure like "
        "NO_PROPOSAL_CHOSEN means the peers share no acceptable proposal. The risk is lost availability, "
        "and the temptation to loosen algorithms on the stricter side just to get the tunnel up."
    ),
    remediation=(
        "Compare the IKE proposals configured on both peers and align them on a policy-approved proposal. "
        "Do not add legacy algorithms to the stricter peer to make the tunnel come up."
    ),
    standards=(RFC_7296,),
)


def _check_neg_001(ctx: Context) -> List[Finding]:
    if ctx.status != "failed":
        return []
    notify = ctx.evidence_where("notify")
    names = sorted({str(e.get("value")) for e in notify})
    return [
        ctx.make_finding(
            _NEG_001,
            scope="session",
            parameter="negotiation.status",
            observed="failed",
            expected="successful",
            evidence_items=notify,
            why_extra=f"Responder error observed: {', '.join(names)}." if names else "",
        )
    ]


NEG_001 = Rule(_NEG_001, _check_neg_001)

# --- NEG-002: weak options offered but not selected -------------------

_NEG_002 = RuleMeta(
    finding_id="IPSEC-NEG-002",
    title="Weak options offered but not selected",
    category="negotiation",
    default_severity=Severity.LOW,
    why_it_matters=(
        "The initiator offered options that the policy forbids, deprecates or does not approve, although "
        "stronger ones were selected. A peer that accepts them, or a downgrade path to them, would "
        "weaken the session."
    ),
    remediation="Remove the non-compliant options from the proposal list so they can never be selected.",
    standards=(RFC_7296, RFC_8247),
)


def _check_neg_002(ctx: Context) -> List[Finding]:
    if ctx.basis != "negotiated":
        return []
    flagged: List[str] = []
    evidence: List[Dict[str, Any]] = []
    for parameter in EVIDENCE_SUFFIX:
        selected = ctx.selected.get(parameter)
        for value in ctx.offered_values(parameter):
            if value == selected:
                continue
            if ctx.classify(parameter, value) in {"forbidden", "deprecated", "unapproved", "null"}:
                flagged.append(f"{parameter}: {value}")
                evidence.extend(ctx.evidence_for(parameter, value, "offered"))
    if not flagged:
        return []
    return [
        ctx.make_finding(
            _NEG_002,
            scope="session",
            parameter="offered_proposals",
            observed=flagged,
            expected="Only policy-approved options offered",
            evidence_items=evidence,
        )
    ]


NEG_002 = Rule(_NEG_002, _check_neg_002)

# --- NEG-003: outcome not observable ----------------------------------

_NEG_003 = RuleMeta(
    finding_id="IPSEC-NEG-003",
    title="Negotiation outcome not observable",
    category="observability",
    default_severity=Severity.INFORMATIONAL,
    why_it_matters=(
        "The capture does not show whether the negotiation succeeded or failed, for example because no "
        "response was seen. Results rest on what was offered only."
    ),
    remediation="Capture both directions of the exchange, including the responder's reply.",
    standards=(RFC_7296,),
)


def _check_neg_003(ctx: Context) -> List[Finding]:
    if not ctx.has_session or ctx.status in {"successful", "failed"}:
        return []
    return [
        ctx.make_finding(
            _NEG_003,
            scope="session",
            parameter="negotiation.status",
            observed=ctx.status,
            expected="successful or failed",
            evidence_items=[],
        )
    ]


NEG_003 = Rule(_NEG_003, _check_neg_003)

# --- NEG-004: selected proposal was never offered ---------------------

_NEG_004 = RuleMeta(
    finding_id="IPSEC-NEG-004",
    title="Negotiated proposal was not among those offered",
    category="negotiation",
    default_severity=Severity.MEDIUM,
    why_it_matters=(
        "In IKEv2 the responder must choose from the initiator's offered proposals. A selection that "
        "matches none of them points to unexpected peer behaviour, a capture covering more than one "
        "exchange, or a parsing problem, and should be reviewed."
    ),
    remediation="Review the full handshake for this session and the peer implementation. Re-capture if the trace is incomplete.",
    standards=(RFC_7296,),
)


def _matches(offered: Dict[str, Any], negotiated: Dict[str, Any]) -> bool:
    return all(
        offered.get(key) == negotiated.get(key)
        for key in EVIDENCE_SUFFIX
        if negotiated.get(key) is not None
    )


def _check_neg_004(ctx: Context) -> List[Finding]:
    if not ctx.negotiated or not ctx.offered:
        return []
    if any(_matches(proposal, ctx.negotiated) for proposal in ctx.offered):
        return []
    return [
        ctx.make_finding(
            _NEG_004,
            scope="session",
            parameter="negotiated_proposal",
            observed={k: ctx.negotiated.get(k) for k in EVIDENCE_SUFFIX},
            expected="A proposal that was among the offered proposals",
            evidence_items=[],
        )
    ]


NEG_004 = Rule(_NEG_004, _check_neg_004)

# --- OBS-001 / OBS-002: nothing to assess -----------------------------

_OBS_001 = RuleMeta(
    finding_id="IPSEC-OBS-001",
    title="No IKE session found",
    category="observability",
    default_severity=Severity.INFORMATIONAL,
    why_it_matters=(
        "The analyzer found no IKEv2 session in this input, so nothing can be assessed. This is not the "
        "same as a secure result."
    ),
    remediation="Check that the capture contains IKE traffic on UDP 500 or 4500 and was taken on the right interface.",
    standards=(),
)


def _check_obs_001(ctx: Context) -> List[Finding]:
    if ctx.has_session:
        return []
    return [
        ctx.make_finding(
            _OBS_001,
            scope="session",
            parameter="session",
            observed=None,
            expected="At least one IKE session",
            evidence_items=[],
        )
    ]


OBS_001 = Rule(_OBS_001, _check_obs_001)

_OBS_002 = RuleMeta(
    finding_id="IPSEC-OBS-002",
    title="No algorithm parameters extracted",
    category="observability",
    default_severity=Severity.INFORMATIONAL,
    why_it_matters=(
        "A session was found but no encryption, integrity or key-exchange values were extracted, so "
        "algorithm strength cannot be judged. This is not the same as a secure result."
    ),
    remediation="Check that the capture includes the IKE_SA_INIT request and response.",
    standards=(),
)


def _check_obs_002(ctx: Context) -> List[Finding]:
    if not ctx.has_session or ctx.basis != "none":
        return []
    return [
        ctx.make_finding(
            _OBS_002,
            scope="session",
            parameter="security_parameters",
            observed=None,
            expected="Encryption, integrity and DH group values",
            evidence_items=[],
        )
    ]


OBS_002 = Rule(_OBS_002, _check_obs_002)

NEGOTIATION_RULES: List[Rule] = [PROTO_001, NEG_001, NEG_002, NEG_003, NEG_004, OBS_001, OBS_002]
