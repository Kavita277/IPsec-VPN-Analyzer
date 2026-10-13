"""The AI layer: template coverage, the guard, provider fallbacks."""

import copy
import json
import re
from pathlib import Path

import pytest

from ai import AnthropicProvider, ProviderError, build_facts, explain, get_provider, guard
from ai.plain_language import PLAIN
from ai.providers import SYSTEM_PROMPT, TemplateProvider
from assessment import assess
from assessment.rules import ALL_RULES
from assessment.tests.helpers import make_doc

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ("secure_01", "weak_01", "misconfigured_01")


def _assessed(sample="weak_01", policy="nist-baseline"):
    return assess(json.loads((ROOT / "analysis" / f"{sample}.json").read_text()), policy)


def _fake_transport(reply_text, seen=None):
    def transport(url, headers, body, timeout):
        if seen is not None:
            seen.append((url, headers, json.loads(body)))
        return json.dumps({"content": [{"type": "text", "text": reply_text}]}).encode()
    return transport


def _provider(reply_text, seen=None):
    return AnthropicProvider("sk-test-secret", model="test-model", transport=_fake_transport(reply_text, seen))


def _good_reply(assessed):
    return json.dumps({
        "summary": "This VPN uses a key exchange that is too small.",
        "findings": {
            f["key"]: {"explanation": f"About {f['title']}.", "impact": "Could be weakened.", "remediation_steps": ["Fix it."]}
            for f in assessed["findings"]
        },
    })


# ---- template ---------------------------------------------------------

def test_every_rule_has_plain_language_text():
    assert {r.meta.finding_id for r in ALL_RULES} <= set(PLAIN)


def test_plain_templates_only_use_known_placeholders():
    allowed = {"agreed", "observed", "expected", "policy", "notify"}
    for fid, entry in PLAIN.items():
        for text in [entry["explain"], entry["impact"], *entry["steps"]]:
            assert set(re.findall(r"{(\w+)}", text)) <= allowed, fid


@pytest.mark.parametrize("sample", SAMPLES)
@pytest.mark.parametrize("policy", ["nist-baseline", "cnsa-strict"])
def test_template_explains_every_finding_without_leftover_braces(sample, policy):
    assessed = _assessed(sample, policy)
    result = explain(assessed)
    assert set(result["findings"]) == {f["key"] for f in assessed["findings"]}
    for entry in result["findings"].values():
        assert entry["source"] == "template"
        assert entry["explanation"] and entry["impact"] and entry["remediation_steps"]
        text = " ".join([entry["explanation"], entry["impact"], *entry["remediation_steps"]])
        assert "{" not in text and "}" not in text
    assert "{" not in result["summary"]["text"]


def test_offered_findings_are_not_described_as_used():
    entry = next(v for k, v in explain(_assessed("misconfigured_01"))["findings"].items() if "|offered|" in k)
    assert "offered" in entry["explanation"] and "did not protect any traffic" in entry["impact"]


def test_not_assessable_summary_does_not_claim_security():
    result = explain(assess(make_doc(session=False), "nist-baseline"))
    assert "not the same as a secure result" in result["summary"]["text"]


def test_explain_never_changes_the_assessment():
    assessed = _assessed()
    snapshot = copy.deepcopy(assessed)
    explain(assessed)
    explain(assessed, provider="template")
    assert assessed == snapshot


def test_facts_contain_only_engine_output():
    facts = build_facts(_assessed())
    assert set(facts) >= {"posture", "findings", "policy", "offered_proposals"}
    assert all("remediation" in f and "evidence" in f for f in facts["findings"])
    assert "security_associations" not in facts and "metadata" not in facts


# ---- guard ------------------------------------------------------------

def test_guard_accepts_well_formed_output():
    assessed = _assessed()
    out = guard(json.loads(_good_reply(assessed)), build_facts(assessed))
    assert out["rejected"] == [] and len(out["findings"]) == 2 and out["summary"]


@pytest.mark.parametrize("raw", [None, [], "text", {"findings": "x"}])
def test_guard_rejects_malformed_output(raw):
    out = guard(raw, build_facts(_assessed()))
    assert out["findings"] == {} and out["rejected"]


def test_guard_drops_unknown_findings_and_invented_ids():
    assessed = _assessed()
    facts = build_facts(assessed)
    key = facts["findings"][0]["key"]
    raw = {
        "summary": "Also see IPSEC-ALG-004 which is critical.",
        "findings": {
            "IPSEC-XXX-999|made|up|thing": {"explanation": "a", "impact": "b", "remediation_steps": ["c"]},
            key: {"explanation": "Related to IPSEC-ALG-004.", "impact": "b", "remediation_steps": ["c"]},
        },
    }
    out = guard(raw, facts)
    assert out["summary"] is None and out["findings"] == {}
    assert len(out["rejected"]) == 3


def test_guard_rejects_entries_with_missing_fields():
    facts = build_facts(_assessed())
    key = facts["findings"][0]["key"]
    out = guard({"summary": "ok", "findings": {key: {"explanation": "only this"}}}, facts)
    assert out["findings"] == {} and key in out["rejected"]


# ---- providers --------------------------------------------------------

def test_llm_text_is_used_and_labelled(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-secret")
    assessed = _assessed()
    result = explain(assessed, provider="anthropic", transport=_fake_transport(_good_reply(assessed)))
    assert result["ai"]["provider"] == "anthropic"
    assert result["summary"]["source"] == "anthropic"
    assert all(v["source"] == "anthropic" for v in result["findings"].values())


def test_llm_output_inside_prose_and_code_fences_is_parsed(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-secret")
    assessed = _assessed()
    reply = "Here you go:\n```json\n" + _good_reply(assessed) + "\n```"
    assert explain(assessed, provider="anthropic", transport=_fake_transport(reply))["ai"]["provider"] == "anthropic"


def test_partial_llm_output_is_filled_from_template(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-secret")
    assessed = _assessed()
    first = assessed["findings"][0]["key"]
    reply = json.dumps({"summary": "S.", "findings": {first: {"explanation": "e", "impact": "i", "remediation_steps": ["r"]}}})
    result = explain(assessed, provider="anthropic", transport=_fake_transport(reply))
    sources = {k: v["source"] for k, v in result["findings"].items()}
    assert sources[first] == "anthropic" and list(sources.values()).count("template") == len(sources) - 1


def test_provider_failure_falls_back_without_leaking_the_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-secret")

    def broken(url, headers, body, timeout):
        raise ProviderError("API returned HTTP 529")

    result = explain(_assessed(), provider="anthropic", transport=broken)
    assert result["ai"]["provider"] == "template"
    assert any("HTTP 529" in w for w in result["ai"]["warnings"])
    assert "sk-test-secret" not in json.dumps(result)


def test_invalid_json_from_model_falls_back(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-secret")
    result = explain(_assessed(), provider="anthropic", transport=_fake_transport("I cannot help with that."))
    assert result["ai"]["provider"] == "template" and result["ai"]["warnings"]


def test_request_sends_only_facts_and_key_only_in_header():
    seen = []
    assessed = _assessed()
    _provider(_good_reply(assessed), seen).generate(build_facts(assessed))
    url, headers, body = seen[0]
    assert url.startswith("https://api.anthropic.com/") and headers["x-api-key"] == "sk-test-secret"
    assert "sk-test-secret" not in json.dumps(body)
    assert body["system"] == SYSTEM_PROMPT and body["model"] == "test-model"
    sent = json.loads(body["messages"][0]["content"])
    assert sent == build_facts(assessed)


def test_auto_without_key_uses_template(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert isinstance(get_provider("auto"), TemplateProvider)
    result = explain(_assessed(), provider="anthropic")
    assert result["ai"]["provider"] == "template"
    assert any("ANTHROPIC_API_KEY" in w for w in result["ai"]["warnings"])


def test_unknown_provider_name_falls_back():
    result = explain(_assessed(), provider="nope")
    assert result["ai"]["provider"] == "template" and result["ai"]["warnings"]
