"""One test group per rule: it fires when it should, stays quiet when it should."""

import pytest

from assessment import assess
from assessment.rules import ALL_RULES, get_rule
from assessment.tests.helpers import SID, failed_doc, find, ids, make_doc

BASE = "nist-baseline"
STRICT = "cnsa-strict"


def test_secure_default_has_no_findings():
    assert ids(assess(make_doc(), BASE)) == []


def test_rule_ids_are_unique_and_well_formed():
    all_ids = [r.meta.finding_id for r in ALL_RULES]
    assert len(all_ids) == len(set(all_ids))
    assert all(i.startswith("IPSEC-") for i in all_ids)
    for rule in ALL_RULES:
        assert rule.meta.why_it_matters and rule.meta.remediation and rule.meta.title


# ---- encryption -------------------------------------------------------

@pytest.mark.parametrize("enc", ["DES", "RC5", "IDEA", "CAST", "Blowfish"])
def test_alg_001_forbidden_cipher(enc):
    result = assess(make_doc(enc=enc), BASE)
    assert ids(result) == ["IPSEC-ALG-001"]
    assert find(result, "IPSEC-ALG-001")["severity"] == "High"


def test_alg_001_not_for_approved_cipher():
    assert "IPSEC-ALG-001" not in ids(assess(make_doc(enc="AES-128-GCM"), BASE))


def test_alg_002_3des_deprecated_by_default_forbidden_in_strict():
    base = assess(make_doc(enc="3DES-CBC"), BASE)
    assert ids(base) == ["IPSEC-ALG-002"]
    assert find(base, "IPSEC-ALG-002")["severity"] == "Medium"
    strict = assess(make_doc(enc="3DES-CBC"), STRICT)
    assert "IPSEC-ALG-001" in ids(strict) and "IPSEC-ALG-002" not in ids(strict)


def test_alg_003_unapproved_under_strict_only():
    assert ids(assess(make_doc(enc="AES-128-CBC"), BASE)) == []
    strict = assess(make_doc(enc="AES-128-CBC", integ="HMAC-SHA2-384", dh="ECP-384"), STRICT)
    assert ids(strict) == ["IPSEC-ALG-003"]


def test_alg_004_null_encryption_is_critical_and_not_double_reported():
    result = assess(make_doc(enc="NULL"), BASE)
    assert ids(result) == ["IPSEC-ALG-004"]
    assert find(result, "IPSEC-ALG-004")["severity"] == "Critical"


def test_alg_005_unknown_key_length_is_informational_not_a_guess():
    result = assess(make_doc(enc="AES-CBC"), BASE)
    assert ids(result) == ["IPSEC-ALG-005"]
    assert find(result, "IPSEC-ALG-005")["severity"] == "Informational"


# ---- integrity --------------------------------------------------------

@pytest.mark.parametrize("integ", ["HMAC-MD5", "HMAC-MD5-128", "KPDK-MD5", "DES-MAC"])
def test_int_001_forbidden_integrity(integ):
    assert ids(assess(make_doc(integ=integ), BASE)) == ["IPSEC-INT-001"]


def test_int_002_sha1_is_low_and_deprecated():
    result = assess(make_doc(integ="HMAC-SHA1"), BASE)
    assert ids(result) == ["IPSEC-INT-002"]
    assert find(result, "IPSEC-INT-002")["severity"] == "Low"


def test_int_003_unapproved_integrity():
    assert "IPSEC-INT-003" in ids(assess(make_doc(integ="HMAC-SHA2-256"), STRICT))
    assert "IPSEC-INT-003" in ids(assess(make_doc(integ="AES-CMAC-96"), BASE))
    assert "IPSEC-INT-003" not in ids(assess(make_doc(integ="HMAC-SHA2-384"), STRICT))


def test_int_004_missing_integrity_only_matters_for_non_aead():
    assert ids(assess(make_doc(integ=None), BASE)) == ["IPSEC-INT-004"]
    assert ids(assess(make_doc(enc="AES-256-GCM", integ=None), BASE)) == []


# ---- DH group ---------------------------------------------------------

@pytest.mark.parametrize("dh", ["MODP-768", "MODP-1024", "MODP-1536"])
def test_dh_001_forbidden_group_is_high(dh):
    result = assess(make_doc(dh=dh), BASE)
    assert ids(result) == ["IPSEC-DH-001"]
    assert find(result, "IPSEC-DH-001")["severity"] == "High"


def test_dh_002_group_not_approved_under_strict():
    assert ids(assess(make_doc(dh="MODP-2048"), BASE)) == []
    assert "IPSEC-DH-002" in ids(assess(make_doc(dh="MODP-2048"), STRICT))
    assert "IPSEC-DH-002" in ids(assess(make_doc(dh="DH-Group-26"), BASE))


def test_dh_003_missing_group_after_success():
    assert ids(assess(make_doc(dh=None), BASE)) == ["IPSEC-DH-003"]


# ---- protocol and negotiation ----------------------------------------

def test_proto_001_ikev1_flagged():
    result = assess(make_doc(ike="IKEv1"), BASE)
    assert ids(result) == ["IPSEC-PROTO-001"]
    assert find(result, "IPSEC-PROTO-001")["evidence"]["items"]


def test_proto_001_quiet_for_ikev2_and_unknown_version():
    assert "IPSEC-PROTO-001" not in ids(assess(make_doc(ike="IKEv2"), BASE))
    assert "IPSEC-PROTO-001" not in ids(assess(make_doc(ike=None), BASE))


def test_neg_001_failed_negotiation_cites_notify_evidence():
    result = assess(failed_doc(), BASE)
    finding = find(result, "IPSEC-NEG-001")
    assert finding["severity"] == "Medium"
    assert finding["evidence"]["items"][0]["value"] == "NO_PROPOSAL_CHOSEN"
    assert "NO_PROPOSAL_CHOSEN" in finding["why_it_matters"]


def test_neg_002_weak_option_offered_but_not_selected():
    offered = [
        {"encryption": "AES-256-CBC", "integrity": "HMAC-SHA2-256", "dh_group": "MODP-2048"},
        {"encryption": "AES-256-CBC", "integrity": "HMAC-SHA2-256", "dh_group": "MODP-1024"},
    ]
    result = assess(make_doc(offered=offered), BASE)
    assert ids(result) == ["IPSEC-NEG-002"]
    finding = find(result, "IPSEC-NEG-002")
    assert finding["severity"] == "Low"
    assert finding["evidence"]["observed"] == ["dh_group: MODP-1024"]
    assert finding["evidence"]["items"]


def test_neg_002_quiet_when_all_offers_compliant():
    assert "IPSEC-NEG-002" not in ids(assess(make_doc(), BASE))


def test_neg_003_status_unknown():
    result = assess(make_doc(status=None, negotiated=None), BASE)
    assert "IPSEC-NEG-003" in ids(result)
    assert "IPSEC-NEG-003" not in ids(assess(make_doc(), BASE))


def test_neg_004_selected_proposal_not_offered():
    offered = [{"encryption": "AES-256-CBC", "integrity": "HMAC-SHA2-256", "dh_group": "MODP-3072"}]
    result = assess(make_doc(offered=offered), BASE)
    assert "IPSEC-NEG-004" in ids(result)
    assert "IPSEC-NEG-004" not in ids(assess(make_doc(), BASE))


def test_obs_001_no_session():
    result = assess(make_doc(session=False), BASE)
    assert ids(result) == ["IPSEC-OBS-001"]
    assert result["posture"]["rating"] == "Not assessable"


def test_obs_002_session_without_parameters():
    result = assess(make_doc(enc=None, integ=None, dh=None, offered=[]), BASE)
    assert "IPSEC-OBS-002" in ids(result)
    assert result["posture"]["rating"] == "Not assessable"


# ---- cross-cutting behaviour -----------------------------------------

def test_offered_scope_is_one_level_lower_than_negotiated():
    negotiated = assess(make_doc(dh="MODP-1024"), BASE)
    offered = assess(failed_doc(dh="MODP-1024"), BASE)
    assert find(negotiated, "IPSEC-DH-001")["severity"] == "High"
    assert find(offered, "IPSEC-DH-001")["severity"] == "Medium"
    assert find(offered, "IPSEC-DH-001")["scope"] == "offered"


def test_offered_informational_does_not_go_below_informational():
    result = assess(failed_doc(enc="AES-CBC"), BASE)
    assert find(result, "IPSEC-ALG-005")["severity"] == "Informational"


def test_evidence_is_never_invented():
    result = assess(make_doc(dh="MODP-1024", evidence=False), BASE)
    assert find(result, "IPSEC-DH-001")["evidence"]["items"] == []


def test_negotiated_evidence_prefers_responder_packet():
    items = find(assess(make_doc(dh="MODP-1024"), BASE), "IPSEC-DH-001")["evidence"]["items"]
    assert [i["packet"] for i in items] == [2]
    assert items[0]["session_id"] == SID


def test_policy_severity_override_applies():
    from assessment.policy import load_policy

    policy = load_policy("nist-baseline")
    policy.data["severities"] = {"IPSEC-INT-002": "High"}
    assert find(assess(make_doc(integ="HMAC-SHA1"), policy), "IPSEC-INT-002")["severity"] == "High"


def test_each_rule_fires_only_its_own_id_for_a_single_defect():
    cases = {
        "IPSEC-ALG-001": make_doc(enc="DES"),
        "IPSEC-INT-001": make_doc(integ="HMAC-MD5"),
        "IPSEC-DH-001": make_doc(dh="MODP-1024"),
    }
    for finding_id, doc in cases.items():
        assert ids(assess(doc, BASE)) == [finding_id]
        get_rule(finding_id)
