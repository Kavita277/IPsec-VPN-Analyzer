"""Explanation providers.

TemplateProvider is deterministic, offline and always available. It is the
default and the fallback. AnthropicProvider asks an LLM to word the explanation
from the verified facts; its output is checked by `guard` before use.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional

from ai.plain_language import CLOSING_STEP, PLAIN


class ProviderError(RuntimeError):
    """The provider could not produce usable output."""


class _Blank(dict):
    def __missing__(self, key: str) -> str:
        return ""


def _text(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in value.items())
    return "not observed" if value is None else str(value)


OFFERED_NOTE = (
    " Because the handshake did not complete, this was only offered, not agreed, "
    "so it did not protect any traffic in this capture."
)


def _fill(template: str, finding: Dict[str, Any], policy_id: str) -> str:
    notify = sorted({str(e.get("value")) for e in finding.get("evidence", []) if "notify" in str(e.get("field", ""))})
    return template.format_map(
        _Blank(
            observed=_text(finding["observed"]),
            expected=_text(finding["expected"]),
            policy=policy_id,
            agreed="The gateways agreed to use" if finding.get("scope") == "negotiated" else "The initiator offered",
            notify=f" (responder returned {', '.join(notify)})" if notify else "",
        )
    )


def template_finding(finding: Dict[str, Any], policy_id: str) -> Dict[str, Any]:
    plain = PLAIN.get(finding["finding_id"])
    if plain is None:
        explain, impact, steps = finding["title"] + ".", finding["why_it_matters"], []
    else:
        explain = _fill(plain["explain"], finding, policy_id)
        impact = _fill(plain["impact"], finding, policy_id)
        steps = [_fill(s, finding, policy_id) for s in plain["steps"]]
    if finding.get("scope") == "offered":
        impact += OFFERED_NOTE
    return {
        "explanation": explain,
        "impact": impact,
        "remediation_steps": [finding["remediation"], *steps, CLOSING_STEP],
    }


def template_summary(facts: Dict[str, Any]) -> str:
    posture = facts["posture"]
    findings = facts["findings"]
    if posture["rating"] == "Not assessable":
        return (
            "No security posture can be stated for this input. Either no IKE session or no algorithm "
            "parameters could be extracted, which is not the same as a secure result."
        )
    policy = (facts.get("policy") or {}).get("name", "the selected")
    sid = facts.get("session_id")
    parts = [
        f"Session {sid} was assessed against the {policy} policy and rated {posture['rating']}, "
        f"with a score of {posture['score']} out of 100."
    ]
    real = [f for f in findings if f["severity"] != "Informational"]
    if not real:
        parts.append("No findings above informational level were raised.")
    else:
        counts = posture["counts"]
        listed = ", ".join(f"{counts[s]} {s.lower()}" for s in ("Critical", "High", "Medium", "Low") if counts.get(s))
        parts.append(f"The rule engine raised {len(real)} finding{'s' if len(real) != 1 else ''} ({listed}).")
        top = real[0]
        parts.append(f"The most serious is \"{top['title']}\" ({_text(top['observed'])}).")
    info = len(findings) - len(real)
    if info:
        parts.append(f"{info} informational note{'s' if info != 1 else ''} describe{'' if info != 1 else 's'} gaps in what could be observed.")
    return " ".join(parts)


class TemplateProvider:
    name = "template"
    model: Optional[str] = None

    def generate(self, facts: Dict[str, Any]) -> Dict[str, Any]:
        policy_id = (facts.get("policy") or {}).get("id", "")
        return {
            "summary": template_summary(facts),
            "findings": {f["key"]: template_finding(f, policy_id) for f in facts["findings"]},
        }


SYSTEM_PROMPT = """You explain IPsec security findings that a deterministic rule engine has already produced.

Rules you must follow:
- Use only the facts in the JSON the user sends. Do not add, remove, re-rate or re-score any finding.
- Do not state any algorithm weakness, attack, CVE, standard or number that is not in the facts.
- If something was not observed in the capture, say it was not observed. Never guess.
- Write for a network administrator who is not an IPsec specialist. Plain, short sentences.
- Refer to findings only by the "key" values given. Do not invent finding IDs.

Reply with a single JSON object and nothing else:
{"summary": "<3-4 sentences on the overall posture>",
 "findings": {"<key>": {"explanation": "<what was observed and why it matters>",
                        "impact": "<what could go wrong>",
                        "remediation_steps": ["<step>", "..."]}}}
Include one entry for every finding key."""

Transport = Callable[[str, Dict[str, str], bytes, float], bytes]


def _urllib_transport(url: str, headers: Dict[str, str], body: bytes, timeout: float) -> bytes:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        raise ProviderError(f"API returned HTTP {exc.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ProviderError(f"could not reach the API ({type(exc).__name__})") from None


class AnthropicProvider:
    name = "anthropic"
    URL = "https://api.anthropic.com/v1/messages"

    def __init__(self, api_key: str, model: Optional[str] = None, transport: Optional[Transport] = None,
                 timeout: float = 60.0) -> None:
        self.api_key = api_key
        self.model = model or os.environ.get("IPSEC_AI_MODEL", "claude-sonnet-5-5")
        self.transport = transport or _urllib_transport
        self.timeout = timeout

    def generate(self, facts: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "model": self.model,
            "max_tokens": 4000,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": json.dumps(facts, ensure_ascii=False)}],
        }
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        raw = self.transport(self.URL, headers, json.dumps(payload).encode("utf-8"), self.timeout)
        try:
            data = json.loads(raw)
            text = "".join(b.get("text", "") for b in data["content"] if b.get("type") == "text")
            start, end = text.find("{"), text.rfind("}")
            return json.loads(text[start : end + 1])
        except (ValueError, KeyError, TypeError):
            raise ProviderError("the model did not return valid JSON") from None


def get_provider(name: Optional[str] = None, transport: Optional[Transport] = None):
    """Pick a provider. 'auto' (default) uses Anthropic only when ANTHROPIC_API_KEY is set."""
    choice = (name or os.environ.get("IPSEC_AI_PROVIDER", "auto")).lower()
    key = os.environ.get("ANTHROPIC_API_KEY")
    if choice == "template" or (choice == "auto" and not key):
        return TemplateProvider()
    if choice in ("auto", "anthropic"):
        if not key:
            raise ProviderError("ANTHROPIC_API_KEY is not set")
        return AnthropicProvider(key, transport=transport)
    raise ProviderError(f"unknown AI provider {choice!r}")
