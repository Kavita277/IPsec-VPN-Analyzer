"""Plain-language wording for each rule, used by the deterministic template provider.

Every sentence here restates what the rule engine already established. Nothing
adds a new claim about the capture. The text is keyed by finding ID, and a test
checks that every rule has an entry.
"""

from __future__ import annotations

from typing import Dict, List, TypedDict


class Plain(TypedDict):
    explain: str
    impact: str
    steps: List[str]


# Placeholders: {agreed}, {observed}, {expected}, {policy}, {notify}
PLAIN: Dict[str, Plain] = {
    "IPSEC-PROTO-001": {
        "explain": "This session used {observed}, but policy '{policy}' requires: {expected}.",
        "impact": "IKEv1 is deprecated. In its aggressive mode with pre-shared keys it can expose material that an attacker can try to guess offline.",
        "steps": ["In strongSwan, version = 2 in the connection block of swanctl.conf selects IKEv2 only."],
    },
    "IPSEC-ALG-001": {
        "explain": "{agreed} the cipher {observed}, which policy '{policy}' forbids.",
        "impact": "Ciphers on the forbidden list are either weak enough to be attacked in practice or no longer approved for IPsec, so the traffic they protect cannot be relied on to stay confidential.",
        "steps": [],
    },
    "IPSEC-ALG-002": {
        "explain": "{agreed} the cipher {observed}, which policy '{policy}' marks as deprecated.",
        "impact": "A deprecated cipher still works but is being phased out. For 3DES, the small 64-bit block size makes long-lived, high-volume tunnels vulnerable to the Sweet32 attack.",
        "steps": [],
    },
    "IPSEC-ALG-003": {
        "explain": "The encryption algorithm {observed} is not on the approved list for policy '{policy}'.",
        "impact": "This is a policy mismatch rather than a known break: the cipher or key length is outside what the policy allows. Approved values are: {expected}.",
        "steps": [],
    },
    "IPSEC-ALG-004": {
        "explain": "The session negotiated NULL encryption.",
        "impact": "NULL means the data is not encrypted at all. Anyone on the network path can read it.",
        "steps": [],
    },
    "IPSEC-ALG-005": {
        "explain": "The capture shows the cipher {observed} but not its key length (128, 192 or 256 bits).",
        "impact": "Without the key length the strength cannot be judged, and the analyzer does not guess it. This is a gap in what could be observed, not a weakness.",
        "steps": [],
    },
    "IPSEC-INT-001": {
        "explain": "{agreed} the integrity algorithm {observed}, which policy '{policy}' forbids.",
        "impact": "Integrity protection is what stops an attacker from changing traffic without being noticed. Forbidden algorithms are obsolete and should not be relied on for this.",
        "steps": [],
    },
    "IPSEC-INT-002": {
        "explain": "{agreed} the integrity algorithm {observed}, which policy '{policy}' marks as deprecated.",
        "impact": "HMAC-SHA1 has not been broken in this use, but SHA-1 is being phased out and current guidance expects the SHA-2 family. This is a low-urgency cleanup.",
        "steps": [],
    },
    "IPSEC-INT-003": {
        "explain": "The integrity algorithm {observed} is not on the approved list for policy '{policy}'.",
        "impact": "This is a policy mismatch rather than a known break. Approved values are: {expected}.",
        "steps": [],
    },
    "IPSEC-INT-004": {
        "explain": "A cipher without built-in integrity was negotiated, but no integrity algorithm appears in the capture.",
        "impact": "The integrity protection cannot be judged from this capture. This is a gap in what could be observed.",
        "steps": [],
    },
    "IPSEC-DH-001": {
        "explain": "{agreed} the key-exchange group {observed}, which policy '{policy}' forbids because it is too small.",
        "impact": "The key exchange is where the session keys come from. With a group this small, a well-resourced attacker who records the handshake may be able to work out the keys and read the session (the Logjam class of attack).",
        "steps": [],
    },
    "IPSEC-DH-002": {
        "explain": "The key-exchange group {observed} is not on the approved list for policy '{policy}'.",
        "impact": "This is a policy mismatch rather than a known break. Approved groups are: {expected}.",
        "steps": [],
    },
    "IPSEC-DH-003": {
        "explain": "The handshake completed, but no key-exchange group appears in the capture.",
        "impact": "Key-exchange strength cannot be judged from this capture. This is a gap in what could be observed.",
        "steps": [],
    },
    "IPSEC-NEG-001": {
        "explain": "The tunnel did not come up. The responder rejected the initiator's proposal{notify}.",
        "impact": "No traffic is protected by this session. The usual cause is that the two gateways share no acceptable proposal. The risk is lost connectivity, and the temptation to weaken the stricter gateway just to get the tunnel running.",
        "steps": [
            "Compare the IKE proposals on both gateways and align them on a policy-approved proposal.",
            "Check the logs on both gateways for the rejected proposal (strongSwan: swanctl --log).",
        ],
    },
    "IPSEC-NEG-002": {
        "explain": "The initiator also offered options that policy '{policy}' does not allow: {observed}.",
        "impact": "They were not selected this time, but a peer that accepts them would downgrade the session to a weaker setting.",
        "steps": [],
    },
    "IPSEC-NEG-003": {
        "explain": "The capture does not show whether the negotiation succeeded or failed.",
        "impact": "The findings for this session rest on what was offered only.",
        "steps": [],
    },
    "IPSEC-NEG-004": {
        "explain": "The proposal that was selected does not match any proposal that was offered.",
        "impact": "In IKEv2 the responder must choose from the initiator's offered list. A mismatch points to unexpected behaviour, a capture that mixes several exchanges, or a parsing problem, so the result should be reviewed before it is trusted.",
        "steps": [],
    },
    "IPSEC-OBS-001": {
        "explain": "No IKE session was found in this input.",
        "impact": "Nothing could be assessed. This is not the same as a secure result.",
        "steps": [],
    },
    "IPSEC-OBS-002": {
        "explain": "A session was found, but no encryption, integrity or key-exchange values could be extracted.",
        "impact": "Algorithm strength cannot be judged. This is not the same as a secure result.",
        "steps": [],
    },
}

CLOSING_STEP = "Capture the traffic again and re-run the assessment to confirm the result."
