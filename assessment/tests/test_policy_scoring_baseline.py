"""Policies, scoring and baseline comparison."""

import copy

import pytest

from assessment import assess, compare, list_policies, load_policy
from assessment.models import Finding, Severity
from assessment.policy import PolicyError, validate_policy
from assessment.scoring import WEIGHTS, compute_posture
from assessment.tests.helpers import failed_doc, make_doc


# ---- policies ---------------------------------------------------------

def test_bundled_policies_load_and_validate():
    names = list_policies()
    assert {"nist-baseline", "cnsa-strict"} <= set(names)
    for name in names:
        policy = load_policy(name)
        validate_policy(policy.data)
        assert policy.recommended.get("strongswan")


def test_recommended_proposal_satisfies_its_own_policy():
    for name in list_policies():
        policy = load_policy(name)
        rec = policy.recommended
        result = assess(make_doc(enc=rec["encryption"], integ=rec["integrity"], dh=rec["dh_group"]), policy)
        assert result["findings"] == [], name


def test_unknown_policy_error_lists_choices():
    with pytest.raises(PolicyError, match="nist-baseline"):
        load_policy("does-not-exist")


def test_policy_rejects_value_both_forbidden_and_approved():
    data = copy.deepcopy(load_policy("nist-baseline").data)
    data["dh_group"]["approved"].append("MODP-1024")
    with pytest.raises(PolicyError, match="both forbidden and approved"):
        validate_policy(data)


def test_policy_rejects_bad_severity_override():
    data = copy.deepcopy(load_policy("nist-baseline").data)
    data["severities"] = {"IPSEC-INT-002": "Severe"}
    with pytest.raises(PolicyError):
        validate_policy(data)


def test_same_session_gets_different_results_under_different_policies():
    doc = make_doc()  # AES-256-CBC / HMAC-SHA2-256 / MODP-2048
    assert assess(doc, "nist-baseline")["posture"]["rating"] == "Compliant"
    assert assess(doc, "cnsa-strict")["posture"]["rating"] == "Moderate risk"


# ---- scoring ----------------------------------------------------------

def _finding(severity):
    return Finding("X", "t", severity, "algorithm", "negotiated", "s", "p", "v", "e", "w", "r", "1.0", "pol")


def test_posture_weights_and_rating():
    posture = compute_posture([_finding(Severity.HIGH), _finding(Severity.LOW)], "negotiated", True)
    assert posture["score"] == 100 - WEIGHTS[Severity.HIGH] - WEIGHTS[Severity.LOW] == 72
    assert posture["rating"] == "High risk"
    assert posture["counts"]["High"] == 1 and posture["counts"]["Low"] == 1


def test_posture_floors_at_zero():
    assert compute_posture([_finding(Severity.CRITICAL)] * 5, "negotiated", True)["score"] == 0


def test_posture_clean_is_compliant_100():
    posture = compute_posture([], "negotiated", True)
    assert (posture["score"], posture["rating"]) == (100, "Compliant")


def test_informational_only_is_still_compliant():
    posture = compute_posture([_finding(Severity.INFORMATIONAL)], "negotiated", True)
    assert (posture["score"], posture["rating"]) == (100, "Compliant")


def test_failed_handshake_posture_states_its_basis():
    posture = assess(failed_doc(dh="MODP-1024"), "nist-baseline")["posture"]
    assert posture["basis"] == "offered"
    assert "did not complete" in posture["basis_note"]


def test_not_assessable_has_no_score():
    posture = assess(make_doc(session=False), "nist-baseline")["posture"]
    assert posture["score"] is None and posture["rating"] == "Not assessable"


# ---- baseline comparison ---------------------------------------------

def test_before_after_remediation_improves():
    before = assess(make_doc(integ="HMAC-SHA1", dh="MODP-1024"), "nist-baseline")
    after = assess(make_doc(), "nist-baseline")
    diff = compare(before, after)
    assert diff["posture_change"]["verdict"] == "improved"
    assert diff["posture_change"]["score_delta"] == 28
    assert {f["finding_id"] for f in diff["resolved"]} == {"IPSEC-DH-001", "IPSEC-INT-002"}
    assert diff["introduced"] == [] and diff["unchanged"] == []
    assert {c["parameter"] for c in diff["parameter_changes"]} == {"integrity", "dh_group"}


def test_regression_is_detected_and_reports_new_findings():
    before = assess(make_doc(), "nist-baseline")
    after = assess(make_doc(dh="MODP-1024"), "nist-baseline")
    diff = compare(before, after)
    assert diff["posture_change"]["verdict"] == "regressed"
    assert [f["finding_id"] for f in diff["introduced"]] == ["IPSEC-DH-001"]


def test_identical_assessments_are_unchanged():
    a = assess(make_doc(dh="MODP-1024"), "nist-baseline")
    diff = compare(a, copy.deepcopy(a))
    assert diff["posture_change"]["verdict"] == "unchanged"
    assert len(diff["unchanged"]) == 1 and not diff["warnings"]


def test_policy_mismatch_warns():
    doc = make_doc()
    diff = compare(assess(doc, "nist-baseline"), assess(doc, "cnsa-strict"))
    assert any("different policies" in w for w in diff["warnings"])


def test_compare_requires_assessed_documents():
    with pytest.raises(ValueError, match="not been assessed"):
        compare(make_doc(), make_doc())
