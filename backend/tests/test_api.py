"""API and report tests (no tshark, network or API key needed)."""

import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import app as backend_app
from backend.report import build_model, render_html, render_markdown
from ai import explain

ROOT = Path(__file__).resolve().parents[2]
client = TestClient(backend_app.app)


@pytest.fixture(autouse=True)
def no_ai_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


def _sample(name, policy="nist-baseline"):
    r = client.get(f"/api/samples/{name}", params={"policy": policy})
    assert r.status_code == 200, r.text
    return r.json()["results"][0]


def test_health_and_policies():
    assert client.get("/api/health").json()["status"] == "ok"
    ids = {p["id"] for p in client.get("/api/policies").json()}
    assert {"nist-baseline", "cnsa-strict"} <= ids


def test_samples_listing_and_assessment():
    names = {s["name"] for s in client.get("/api/samples").json()}
    assert names == {"secure_01", "weak_01", "misconfigured_01"}
    assert _sample("weak_01")["posture"]["score"] == 72
    assert _sample("weak_01", "cnsa-strict")["posture"]["score"] == 55


def test_unknown_sample_and_policy():
    assert client.get("/api/samples/nope").status_code == 404
    assert client.get("/api/samples/weak_01", params={"policy": "bogus"}).status_code == 400
    assert client.get("/api/samples/..%2Fsecret").status_code in (404, 400)


def test_assess_json_body_and_validation():
    doc = json.loads((ROOT / "analysis" / "secure_01.json").read_text())
    assert client.post("/api/assess", json=doc).json()["results"][0]["posture"]["rating"] == "Compliant"
    assert client.post("/api/assess", json={"schema_version": "9"}).status_code == 422
    assert client.post("/api/assess", json=[1, 2]).status_code == 422


def test_upload_json_file():
    data = (ROOT / "analysis" / "weak_01.json").read_bytes()
    r = client.post("/api/upload", files={"file": ("weak_01.json", data, "application/json")})
    assert r.status_code == 200 and r.json()["source"] == "json"


@pytest.mark.parametrize("name,data,status", [
    ("x.txt", b"hello", 415),
    ("x.json", b"{broken", 422),
    ("x.json", b"", 422),
])
def test_upload_rejections(name, data, status):
    assert client.post("/api/upload", files={"file": (name, data)}).status_code == status


def test_upload_too_large(monkeypatch):
    monkeypatch.setattr(backend_app, "MAX_UPLOAD_BYTES", 10)
    assert client.post("/api/upload", files={"file": ("a.json", b"x" * 50)}).status_code == 413


def test_pcap_upload_reports_missing_tshark_clearly(monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    monkeypatch.delenv("TSHARK_PATH", raising=False)
    r = client.post("/api/upload", files={"file": ("c.pcap", b"\xd4\xc3\xb2\xa1" + b"\0" * 40)})
    assert r.status_code == 503
    assert "tshark" in r.json()["detail"].lower() and "JSON" in r.json()["detail"]


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
@pytest.mark.parametrize("name,path,score", [
    ("secure_01", "samples/secure/secure_01.pcap", 100),
    ("weak_01", "samples/weak/weak_01.pcap", 72),
    ("misconfigured_01", "samples/misconfigured/misconfigured_01.pcap", 80),
])
def test_real_pcap_end_to_end(name, path, score):
    """PCAP -> tshark -> analyzer -> assessment, matching the committed analysis."""
    data = (ROOT / path).read_bytes()
    r = client.post("/api/upload", files={"file": (Path(path).name, data)})
    assert r.status_code == 200, r.text
    result = r.json()["results"][0]
    assert result["posture"]["score"] == score
    committed = json.loads((ROOT / "analysis" / f"{name}.json").read_text())
    assert all(result[k] == committed[k] for k in committed)


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
def test_garbage_pcap_is_a_client_error_not_a_crash():
    r = client.post("/api/upload", files={"file": ("junk.pcap", b"this is not a capture file at all" * 4)})
    assert r.status_code in (200, 422), r.text
    if r.status_code == 200:  # tshark tolerated it but found nothing to assess
        assert r.json()["results"][0]["posture"]["rating"] == "Not assessable"


def test_pcap_upload_happy_path_with_stubbed_analyzer(monkeypatch):
    doc = json.loads((ROOT / "analysis" / "weak_01.json").read_text())
    monkeypatch.setattr(backend_app, "_run_pcap_analysis", lambda data, filename: [doc, doc])
    r = client.post("/api/upload", files={"file": ("two.pcap", b"data")})
    assert r.status_code == 200 and r.json()["source"] == "pcap" and len(r.json()["results"]) == 2


def test_pcap_filename_is_sanitised():
    assert backend_app._safe_name("../../etc/pass wd.pcap") == "pass_wd.pcap"
    assert backend_app._safe_name(None) == "upload"


def test_compare_endpoint():
    r = client.post("/api/compare", json={"before": _sample("weak_01"), "after": _sample("secure_01")})
    assert r.status_code == 200 and r.json()["posture_change"]["verdict"] == "improved"
    assert client.post("/api/compare", json={"before": {}, "after": {}}).status_code == 422


def test_explain_endpoint_and_provider_restriction():
    r = client.post("/api/explain", json={"assessed": _sample("weak_01")})
    assert r.status_code == 200 and r.json()["ai"]["provider"] == "template"
    assert client.post("/api/explain", json={"assessed": _sample("weak_01"), "provider": "anthropic"}).status_code == 400
    assert client.post("/api/explain", json={"assessed": {}}).status_code == 422


# ---- reports ----------------------------------------------------------

def test_markdown_report_contains_the_evidence_chain():
    r = client.post("/api/report", params={"format": "md"}, json={"assessed": _sample("weak_01")})
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    text = r.text
    for needle in ("IPSEC-DH-001", "MODP-1024", "isakmp.tf.id.dh", "Why it matters", "Remediation", "vpn_c0a15c9a873db101", "Ruleset version"):
        assert needle in text


def test_html_report_is_standalone_and_escapes():
    assessed = _sample("weak_01")
    assessed["metadata"]["capture_file"] = "<script>alert(1)</script>.pcap"
    r = client.post("/api/report", json={"assessed": assessed})
    assert r.status_code == 200 and r.text.startswith("<!doctype html>")
    assert "<script>alert(1)" not in r.text and "&lt;script&gt;" in r.text
    assert "http://" not in r.text and "https://" not in r.text  # no external resources


def test_report_for_clean_and_failed_sessions():
    assert "No findings were raised" in client.post("/api/report", params={"format": "md"}, json={"assessed": _sample("secure_01")}).text
    failed = client.post("/api/report", params={"format": "md"}, json={"assessed": _sample("misconfigured_01")}).text
    assert "NO_PROPOSAL_CHOSEN" in failed and "only offered, not agreed" in failed


def test_report_includes_comparison():
    cmp_ = client.post("/api/compare", json={"before": _sample("weak_01"), "after": _sample("secure_01")}).json()
    r = client.post("/api/report", params={"format": "md"}, json={"assessed": _sample("secure_01"), "comparison": cmp_})
    assert "Before and after" in r.text and "improved" in r.text
    assert client.post("/api/report", json={"assessed": _sample("secure_01"), "comparison": {"x": 1}}).status_code == 422


def test_report_reuses_a_valid_explanation_and_rejects_a_tampered_one():
    assessed = _sample("weak_01")
    expl = explain(assessed)
    expl["summary"]["text"] = "Custom summary the user already saw."
    ok = client.post("/api/report", params={"format": "md"}, json={"assessed": assessed, "explanation": expl}).text
    assert "Custom summary the user already saw." in ok
    expl["summary"]["text"] = "This also has IPSEC-ALG-004 which is critical."
    bad = client.post("/api/report", params={"format": "md"}, json={"assessed": assessed, "explanation": expl}).text
    assert "IPSEC-ALG-004 which is critical" not in bad


def test_report_bad_format_and_input():
    assert client.post("/api/report", params={"format": "pdf"}, json={"assessed": _sample("weak_01")}).status_code == 422
    assert client.post("/api/report", json={"assessed": 5}).status_code == 422


def test_renderers_agree_on_content():
    assessed = _sample("misconfigured_01")
    model = build_model(assessed, explain(assessed))
    md, html_text = render_markdown(model), render_html(model)
    for f in assessed["findings"]:
        assert f["finding_id"] in md and f["finding_id"] in html_text


def test_methodology_exposes_scoring_inputs():
    m = client.get("/api/methodology", params={"policy": "cnsa-strict"}).json()
    assert m["policy"]["id"] == "cnsa-strict" and m["policy"]["ike_versions"]
    assert m["weights"] == {"Critical": 40, "High": 25, "Medium": 10, "Low": 3, "Informational": 0}
    assert [r["rating"] for r in m["ratings"]][-1] == "Compliant"
    assert len(m["rules"]) == 19 and all(r["id"].startswith("IPSEC-") for r in m["rules"])
    assert "MODP-1024" in m["policy"]["parameters"]["dh_group"]["forbidden"]
    assert client.get("/api/methodology", params={"policy": "bogus"}).status_code == 400
