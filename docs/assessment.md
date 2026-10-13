# Security Assessment Engine (Person 2)

Takes the normalized JSON from `analyze.py` and returns deterministic, evidence-backed findings and a posture score. No AI is involved in the verdict.

```
analysis/*.json  ->  assess.py  ->  assessments/*.assessed.json
 (Person 1)          rules + policy   findings + posture (Person 3 reads this)
```

## Usage

```bash
python assess.py analysis/weak_01.json                     # default policy: nist-baseline
python assess.py analysis/ -p nist-baseline -p cnsa-strict # whole folder, two policies
python assess.py --compare before.json after.json          # before/after remediation
python assess.py --list-policies
python -m pytest assessment                                # tests
```

Output files are named `<capture>.<policy>.assessed.json` and validate against `docs/schema/assessment_v1.json`. All input fields are preserved; `findings`, `posture` and `assessment` are added.

From Python:

```python
from assessment import assess, compare
result = assess(analysis_dict, "cnsa-strict")   # policy id or path to a policy JSON
diff = compare(before_result, after_result)
```

## Policies

Policies live in `assessment/policies/*.json`. Per parameter (`encryption`, `integrity`, `dh_group`) they list `forbidden`, `deprecated` and `approved` values using the analyzer's names (`AES-256-CBC`, `HMAC-SHA2-256`, `MODP-2048`). They also set the allowed IKE versions, a recommended proposal (with a strongSwan `proposals =` string used in remediation text), and optional per-rule severity overrides.

| Policy | Intent |
| --- | --- |
| `nist-baseline` | General baseline. Forbids DES, MD5, MODP ≤ 1536. Flags 3DES and SHA-1 as deprecated. Accepts AES-128 and up, SHA-2, MODP ≥ 2048. |
| `cnsa-strict` | CNSA 1.0 style. AES-256 only, SHA-384 or stronger, MODP ≥ 3072 or P-384/P-521. |

An empty `approved` list means "no allow-list": anything not forbidden or deprecated passes. Add your own policy by copying a file and passing its path with `-p`.

The policies are a reasonable reading of the cited standards, not an official compliance test. Check the lists against your own requirements before relying on them.

## Rules (ruleset 1.0.0)

| ID | Default severity | Fires when |
| --- | --- | --- |
| IPSEC-PROTO-001 | High | IKE version is not allowed by the policy |
| IPSEC-ALG-001 | High | Encryption is on the policy's forbidden list |
| IPSEC-ALG-002 | Medium | Encryption is deprecated (3DES in the baseline) |
| IPSEC-ALG-003 | Medium | Encryption is not on the approved list |
| IPSEC-ALG-004 | Critical | NULL encryption |
| IPSEC-ALG-005 | Informational | AES with no observed key length (not guessed) |
| IPSEC-INT-001 | High | Integrity is forbidden (MD5, DES-MAC) |
| IPSEC-INT-002 | Low | Integrity is deprecated (HMAC-SHA1 in the baseline) |
| IPSEC-INT-003 | Medium | Integrity is not on the approved list |
| IPSEC-INT-004 | Informational | No integrity seen with a non-AEAD cipher |
| IPSEC-DH-001 | High | DH group is forbidden (MODP ≤ 1536 in both bundled policies) |
| IPSEC-DH-002 | Medium | DH group is not on the approved list |
| IPSEC-DH-003 | Informational | Handshake completed but no DH group seen |
| IPSEC-NEG-001 | Medium | Negotiation failed (cites the responder's notify) |
| IPSEC-NEG-002 | Low | Weak options were offered although stronger ones were selected |
| IPSEC-NEG-003 | Informational | Outcome of the negotiation is unknown |
| IPSEC-NEG-004 | Medium | The selected proposal matches none of the offered ones |
| IPSEC-OBS-001 | Informational | No IKE session in the input |
| IPSEC-OBS-002 | Informational | Session found but no parameters extracted |

Each rule is a separate function with its own metadata in `assessment/rules/`. When you change a rule's logic, wording or severity, bump `RULESET_VERSION` in `assessment/rules/__init__.py` and update the pinned results in `assessment/tests/test_regression.py`.

### Offered versus negotiated

If the handshake completed, rules judge what was negotiated (`scope: "negotiated"`). If it failed, they judge what was offered (`scope: "offered"`) and the severity is **one level lower**, because a proposal that was never agreed protected no traffic. `posture.basis` says which case applies, so a reader can see that a failed handshake's score reflects proposals, not a live tunnel.

### Evidence

Every finding's `evidence.items` are entries copied unchanged from the analyzer's `evidence[]` (packet, field, value, session_id). For a negotiated value the responder's packet is cited. If the analyzer recorded no matching entry the list is empty; the engine never invents one.

## Posture

```
score  = max(0, 100 - sum(weight[severity]))      Critical 40, High 25, Medium 10, Low 3, Informational 0
rating = from the highest severity present        Critical / High risk / Moderate risk / Low risk / Compliant
```

A session with no extractable parameters is `Not assessable` with a `null` score, never "Compliant".

## Limits

- Only what the analyzer extracts can be judged. ESP payloads are not decrypted, and the current output has no SA lifetimes, PRF, authentication method or ESP transforms, so no rules exist for them yet.
- A key length that was not observed is reported as `IPSEC-ALG-005`, not assumed.
- `IPSEC-NEG-004` compares the negotiated proposal with the offered list as the analyzer extracted it. If the analyzer groups multi-proposal offers differently in future, re-check this rule.
