"""Algorithm rules: encryption, integrity and Diffie-Hellman group checks.

Each rule is a separate, independently testable unit with its own finding ID.
Rules judge the negotiated value when the handshake completed, and the offered
values (one severity level lower) when it did not.
"""

from __future__ import annotations

from typing import Iterable, List

from assessment.models import Finding, Severity
from assessment.rules.base import (
    Context,
    Rule,
    RuleMeta,
    is_aead,
)

NIST_77 = "NIST SP 800-77 Rev.1"
NIST_131A = "NIST SP 800-131A Rev.2"
NIST_57 = "NIST SP 800-57 Part 1 Rev.5"
RFC_8247 = "RFC 8247"
RFC_8221 = "RFC 8221"


def _tier_rule(meta: RuleMeta, parameter: str, tiers: Iterable[str]) -> Rule:
    wanted = set(tiers)

    def check(ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        for scope, value in ctx.targets(parameter):
            if ctx.classify(parameter, value) not in wanted:
                continue
            findings.append(
                ctx.make_finding(
                    meta,
                    scope=scope,
                    parameter=parameter,
                    observed=value,
                    expected=f"One of: {ctx.approved_text(parameter)}",
                    evidence_items=ctx.evidence_for(parameter, value, scope),
                    remediation_extra=ctx.recommendation(),
                )
            )
        return findings

    return Rule(meta, check)


# --- Encryption --------------------------------------------------------

ALG_001 = _tier_rule(
    RuleMeta(
        finding_id="IPSEC-ALG-001",
        title="Forbidden encryption algorithm",
        category="algorithm",
        default_severity=Severity.HIGH,
        why_it_matters=(
            "The policy forbids this cipher. Legacy ciphers such as single DES (56-bit key), RC5, IDEA, "
            "CAST and Blowfish are no longer approved for IPsec and either have practical attacks or "
            "are not covered by current IPsec algorithm requirements."
        ),
        remediation="Remove the cipher from the IKE and ESP proposals on both peers and use an approved AEAD or AES-based cipher.",
        standards=(RFC_8247, RFC_8221, NIST_131A),
    ),
    "encryption",
    {"forbidden"},
)

ALG_002 = _tier_rule(
    RuleMeta(
        finding_id="IPSEC-ALG-002",
        title="Deprecated encryption algorithm",
        category="algorithm",
        default_severity=Severity.MEDIUM,
        why_it_matters=(
            "The policy marks this cipher as deprecated. 64-bit block ciphers such as 3DES are exposed to "
            "birthday-bound attacks (Sweet32) on long-lived or high-volume tunnels, and NIST no longer "
            "allows 3DES for new encryption after 2023."
        ),
        remediation="Migrate peers to AES-based proposals and retire the deprecated cipher.",
        standards=(NIST_131A, RFC_8247),
    ),
    "encryption",
    {"deprecated"},
)

ALG_003 = _tier_rule(
    RuleMeta(
        finding_id="IPSEC-ALG-003",
        title="Encryption algorithm not approved by policy",
        category="algorithm",
        default_severity=Severity.MEDIUM,
        why_it_matters=(
            "This cipher is not on the policy's approved list. It is not necessarily broken, but the "
            "selected policy only allows the listed algorithms and key lengths."
        ),
        remediation="Configure an approved cipher and key length in the IKE and ESP proposals.",
        standards=(NIST_77, RFC_8221),
    ),
    "encryption",
    {"unapproved"},
)

ALG_004 = _tier_rule(
    RuleMeta(
        finding_id="IPSEC-ALG-004",
        title="NULL encryption negotiated",
        category="algorithm",
        default_severity=Severity.CRITICAL,
        why_it_matters=(
            "NULL encryption provides authentication without confidentiality. Traffic or IKE payloads "
            "protected this way are readable by anyone on the path."
        ),
        remediation="Remove NULL from every proposal. Use NULL only in controlled lab tests, never in production.",
        standards=(RFC_8221, NIST_77),
    ),
    "encryption",
    {"null"},
)

ALG_005 = _tier_rule(
    RuleMeta(
        finding_id="IPSEC-ALG-005",
        title="Encryption key length not observable",
        category="observability",
        default_severity=Severity.INFORMATIONAL,
        why_it_matters=(
            "The capture shows an AES mode without a key length attribute, so the key size (128, 192 or 256) "
            "cannot be judged. The analyzer does not guess it."
        ),
        remediation="Capture the full IKE_SA_INIT exchange, or check the key length in the peers' configuration.",
        standards=(RFC_8247,),
    ),
    "encryption",
    {"unknown_key_length"},
)


# --- Integrity ---------------------------------------------------------

INT_001 = _tier_rule(
    RuleMeta(
        finding_id="IPSEC-INT-001",
        title="Forbidden integrity algorithm",
        category="algorithm",
        default_severity=Severity.HIGH,
        why_it_matters=(
            "The policy forbids this integrity algorithm. MD5-based and DES-MAC constructions are obsolete "
            "and not recommended for IPsec."
        ),
        remediation="Replace the integrity algorithm with an approved HMAC-SHA2 variant on both peers.",
        standards=(RFC_8247, RFC_8221, NIST_131A),
    ),
    "integrity",
    {"forbidden"},
)

INT_002 = _tier_rule(
    RuleMeta(
        finding_id="IPSEC-INT-002",
        title="Deprecated integrity algorithm",
        category="algorithm",
        default_severity=Severity.LOW,
        why_it_matters=(
            "HMAC-SHA1 is still sound as a MAC, since collision attacks on SHA-1 do not apply to the HMAC "
            "construction. SHA-1 is deprecated across NIST guidance, though, and current IPsec profiles "
            "prefer the SHA-2 family."
        ),
        remediation="Move to HMAC-SHA2-256 or stronger on both peers.",
        standards=(NIST_131A, RFC_8247),
    ),
    "integrity",
    {"deprecated"},
)

INT_003 = _tier_rule(
    RuleMeta(
        finding_id="IPSEC-INT-003",
        title="Integrity algorithm not approved by policy",
        category="algorithm",
        default_severity=Severity.MEDIUM,
        why_it_matters=(
            "This integrity algorithm is not on the policy's approved list. The selected policy only "
            "allows the listed algorithms."
        ),
        remediation="Configure an approved integrity algorithm in the IKE and ESP proposals.",
        standards=(NIST_77, RFC_8221),
    ),
    "integrity",
    {"unapproved"},
)

_INT_004_META = RuleMeta(
    finding_id="IPSEC-INT-004",
    title="Integrity algorithm not observed",
    category="observability",
    default_severity=Severity.INFORMATIONAL,
    why_it_matters=(
        "A non-AEAD cipher was negotiated but no integrity transform was seen in the capture, so the "
        "integrity protection cannot be judged."
    ),
    remediation="Check that the capture includes the complete IKE_SA_INIT response, or review the peer configuration.",
    standards=(RFC_8247,),
)


def _check_int_004(ctx: Context) -> List[Finding]:
    if ctx.basis != "negotiated":
        return []
    if ctx.selected.get("integrity") or is_aead(ctx.selected.get("encryption")):
        return []
    return [
        ctx.make_finding(
            _INT_004_META,
            scope="negotiated",
            parameter="integrity",
            observed=None,
            expected="An integrity transform, unless an AEAD cipher is used",
            evidence_items=[],
        )
    ]


INT_004 = Rule(_INT_004_META, _check_int_004)


# --- Diffie-Hellman group ---------------------------------------------

DH_001 = _tier_rule(
    RuleMeta(
        finding_id="IPSEC-DH-001",
        title="Forbidden Diffie-Hellman group",
        category="algorithm",
        default_severity=Severity.HIGH,
        why_it_matters=(
            "MODP groups of 1536 bits or fewer give well under 112 bits of security. 1024-bit groups are "
            "within reach of well-resourced attackers through precomputation against common primes "
            "(the Logjam attack), which can expose the session keys, and RFC 8247 advises against them."
        ),
        remediation="Use a 2048-bit or larger MODP group, or an elliptic-curve group, in the IKE proposal on both peers.",
        standards=(RFC_8247, NIST_57, NIST_131A),
    ),
    "dh_group",
    {"forbidden", "deprecated"},
)

DH_002 = _tier_rule(
    RuleMeta(
        finding_id="IPSEC-DH-002",
        title="Diffie-Hellman group not approved by policy",
        category="algorithm",
        default_severity=Severity.MEDIUM,
        why_it_matters=(
            "This group is not on the policy's approved list. It is not necessarily weak in general, but "
            "the selected policy requires a larger or different group."
        ),
        remediation="Configure an approved Diffie-Hellman group in the IKE proposal on both peers.",
        standards=(NIST_57, RFC_8247),
    ),
    "dh_group",
    {"unapproved"},
)

_DH_003_META = RuleMeta(
    finding_id="IPSEC-DH-003",
    title="Diffie-Hellman group not observed",
    category="observability",
    default_severity=Severity.INFORMATIONAL,
    why_it_matters=(
        "The handshake completed but no key-exchange group was extracted, so key-exchange strength "
        "cannot be judged."
    ),
    remediation="Check that the capture includes the complete IKE_SA_INIT exchange.",
    standards=(RFC_8247,),
)


def _check_dh_003(ctx: Context) -> List[Finding]:
    if ctx.basis != "negotiated" or ctx.selected.get("dh_group"):
        return []
    return [
        ctx.make_finding(
            _DH_003_META,
            scope="negotiated",
            parameter="dh_group",
            observed=None,
            expected="A key-exchange group",
            evidence_items=[],
        )
    ]


DH_003 = Rule(_DH_003_META, _check_dh_003)

ALGORITHM_RULES: List[Rule] = [
    ALG_001, ALG_002, ALG_003, ALG_004, ALG_005,
    INT_001, INT_002, INT_003, INT_004,
    DH_001, DH_002, DH_003,
]
