"""Regression tests against Person 1's real StrongSwan captures.

These pin the exact findings for the three lab scenarios. If a rule, policy or
severity changes on purpose, update EXPECTED and bump RULESET_VERSION.
"""

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from assessment import RULESET_VERSION, assess
from assessment.engine import InvalidAnalysisError

ROOT = Path(__file__).resolve().parents[2]
ANALYSIS = ROOT / "analysis"

# (sample, policy) -> (score, rating, [(finding_id, severity, scope, observed)])
EXPECTED = {
    ("secure_01", "nist-baseline"): (100, "Compliant", []),
    ("weak_01", "nist-baseline"): (72, "High risk", [
        ("IPSEC-DH-001", "High", "negotiated", "MODP-1024"),
        ("IPSEC-INT-002", "Low", "negotiated", "HMAC-SHA1"),
    ]),
    ("misconfigured_01", "nist-baseline"): (80, "Moderate risk", [
        ("IPSEC-DH-001", "Medium", "offered", "MODP-1024"),
        ("IPSEC-NEG-001", "Medium", "session", "failed"),
        ("IPSEC-INT-002", "Informational", "offered", "HMAC-SHA1"),
    ]),
    ("secure_01", "cnsa-strict"): (80, "Moderate risk", [
        ("IPSEC-DH-002", "Medium", "negotiated", "MODP-2048"),
        ("IPSEC-INT-003", "Medium", "negotiated", "HMAC-SHA2-256"),
    ]),
    ("weak_01", "cnsa-strict"): (55, "High risk", [
        ("IPSEC-DH-001", "High", "negotiated", "MODP-1024"),
        ("IPSEC-ALG-003", "Medium", "negotiated", "AES-128-CBC"),
        ("IPSEC-INT-003", "Medium", "negotiated", "HMAC-SHA1"),
    ]),
    ("misconfigured_01", "cnsa-strict"): (74, "Moderate risk", [
        ("IPSEC-DH-001", "Medium", "offered", "MODP-1024"),
        ("IPSEC-NEG-001", "Medium", "session", "failed"),
        ("IPSEC-ALG-003", "Low", "offered", "AES-128-CBC"),
        ("IPSEC-INT-003", "Low", "offered", "HMAC-SHA1"),
    ]),
}


def _load(sample):
    return json.loads((ANALYSIS / f"{sample}.json").read_text())


@pytest.mark.parametrize("sample,policy", sorted(EXPECTED))
def test_sample_findings_are_pinned(sample, policy):
    score, rating, findings = EXPECTED[(sample, policy)]
    result = assess(_load(sample), policy)
    assert result["posture"]["score"] == score
    assert result["posture"]["rating"] == rating
    actual = [(f["finding_id"], f["severity"], f["scope"], f["evidence"]["observed"]) for f in result["findings"]]
    assert actual == findings


@pytest.mark.parametrize("sample", ["secure_01", "weak_01", "misconfigured_01"])
def test_every_finding_cites_real_evidence_from_the_analyzer(sample):
    doc = _load(sample)
    known = {(e["packet"], e["field"], e["value"], e["session_id"]) for e in doc["evidence"]}
    for policy in ("nist-baseline", "cnsa-strict"):
        for finding in assess(doc, policy)["findings"]:
            assert finding["evidence"]["items"], f"{finding['finding_id']} has no evidence"
            for item in finding["evidence"]["items"]:
                assert (item["packet"], item["field"], item["value"], item["session_id"]) in known


def test_assessment_is_deterministic_and_does_not_mutate_input():
    doc = _load("weak_01")
    snapshot = copy.deepcopy(doc)
    first = json.dumps(assess(doc, "nist-baseline"), sort_keys=True)
    second = json.dumps(assess(doc, "nist-baseline"), sort_keys=True)
    assert first == second
    assert doc == snapshot


def test_original_analysis_fields_are_preserved():
    doc = _load("secure_01")
    result = assess(doc, "nist-baseline")
    for key, value in doc.items():
        assert result[key] == value
    assert {"findings", "posture", "assessment"} <= set(result)
    assert result["assessment"]["ruleset_version"] == RULESET_VERSION


def test_every_finding_answers_the_five_questions():
    for sample in ("weak_01", "misconfigured_01"):
        for finding in assess(_load(sample), "nist-baseline")["findings"]:
            assert finding["evidence"]["observed"] is not None          # what was observed
            assert finding["why_it_matters"]                            # why it matters
            assert finding["finding_id"] and finding["rule_version"]    # which rule
            assert finding["evidence"]["items"]                         # what evidence
            assert finding["remediation"]                               # how to fix


@pytest.mark.parametrize("bad", [None, [], {"schema_version": "9.9"}, {"schema_version": "1.0"}])
def test_invalid_input_is_rejected(bad):
    with pytest.raises(InvalidAnalysisError):
        assess(bad, "nist-baseline")


# ---- CLI --------------------------------------------------------------

def _run(*args):
    return subprocess.run([sys.executable, str(ROOT / "assess.py"), *args], capture_output=True, text=True, cwd=ROOT)


def test_cli_writes_one_file_per_sample_and_policy(tmp_path):
    proc = _run(str(ANALYSIS), "-p", "nist-baseline", "-p", "cnsa-strict", "-o", str(tmp_path))
    assert proc.returncode == 0, proc.stderr
    written = sorted(p.name for p in tmp_path.glob("*.assessed.json"))
    assert len(written) == 6
    assert "weak_01.nist-baseline.assessed.json" in written


def test_cli_compare_prints_verdict(tmp_path):
    proc = _run("--compare", str(ANALYSIS / "weak_01.json"), str(ANALYSIS / "secure_01.json"))
    assert proc.returncode == 0, proc.stderr
    assert "Verdict: improved" in proc.stdout
    assert "resolved" in proc.stdout


def test_cli_reports_errors_with_nonzero_exit(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    proc = _run(str(bad), "-o", str(tmp_path))
    assert proc.returncode == 1 and "[ERROR]" in proc.stderr
    assert _run(str(ANALYSIS / "weak_01.json"), "-p", "nope", "-o", str(tmp_path)).returncode == 1


def test_cli_lists_policies():
    proc = _run("--list-policies")
    assert proc.returncode == 0 and "cnsa-strict" in proc.stdout


def test_outputs_validate_against_published_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((ROOT / "docs" / "schema" / "assessment_v1.json").read_text())
    for sample in ("secure_01", "weak_01", "misconfigured_01"):
        for policy in ("nist-baseline", "cnsa-strict"):
            jsonschema.validate(assess(_load(sample), policy), schema)
