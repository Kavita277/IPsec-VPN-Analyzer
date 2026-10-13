"""Assessment report export (Markdown and standalone HTML).

Both formats render the same model, so they always say the same thing. The
HTML is self-contained and prints cleanly, so "Save as PDF" in a browser gives
a PDF without any extra dependency.
"""

from __future__ import annotations

import html
from typing import Any, Dict, List, Optional

TITLE = "IPsec VPN Security Assessment"
SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]

LIMITS = [
    "Only what appears in the capture can be judged. ESP payloads are not decrypted.",
    "Severity, score and findings come from a deterministic, versioned rule set. Explanations only reword those verified facts.",
    "A value that was not observed is reported as not observed. It is never assumed.",
    "A failed handshake is judged on the proposals that were offered, not on an established tunnel.",
]


def build_model(assessed: Dict[str, Any], explanation: Dict[str, Any], comparison: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    meta = assessed.get("assessment") or {}
    posture = assessed.get("posture") or {}
    negotiation = assessed.get("negotiation") or {}
    params = assessed.get("security_parameters") or {}
    findings: List[Dict[str, Any]] = []
    for f in assessed.get("findings", []):
        text = (explanation.get("findings") or {}).get(f["key"], {})
        findings.append({**f, "ai_text": text})
    return {
        "session_id": (assessed.get("session") or {}).get("session_id"),
        "capture_file": (assessed.get("metadata") or {}).get("capture_file"),
        "ike_version": (assessed.get("protocol") or {}).get("ike_version"),
        "status": negotiation.get("status"),
        "policy": meta.get("policy") or {},
        "ruleset_version": meta.get("ruleset_version"),
        "posture": posture,
        "summary": explanation.get("summary") or {},
        "ai": explanation.get("ai") or {},
        "negotiated": {k: params.get(k) for k in ("encryption", "integrity", "dh_group")},
        "offered": negotiation.get("offered_proposals") or [],
        "findings": findings,
        "comparison": comparison,
    }


def _v(value: Any) -> str:
    if value is None:
        return "not observed"
    if isinstance(value, list):
        return ", ".join(str(x) for x in value)
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in value.items())
    return str(value)


def _source_label(source: Optional[str]) -> str:
    return "template text" if source in (None, "template") else f"AI-generated ({source})"


# --- Markdown ----------------------------------------------------------

def _md(value: Any) -> str:
    return _v(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(m: Dict[str, Any]) -> str:
    p = m["posture"]
    score = "n/a" if p.get("score") is None else f"{p['score']}/100"
    out: List[str] = [f"# {TITLE}", ""]
    out += [
        f"- **Session:** {_md(m['session_id'])}",
        f"- **Capture file:** {_md(m['capture_file'])}",
        f"- **Policy:** {_md(m['policy'].get('name'))} (`{_md(m['policy'].get('id'))}` v{_md(m['policy'].get('version'))})",
        f"- **Ruleset version:** {_md(m['ruleset_version'])}",
        f"- **Rating:** {_md(p.get('rating'))} (score {score})",
        "",
        "## Summary", "",
        m["summary"].get("text", ""), "",
        f"*Wording: {_source_label(m['summary'].get('source'))}. {p.get('basis_note', '')}*", "",
        "## Session overview", "",
        "| Item | Value |", "| --- | --- |",
        f"| IKE version | {_md(m['ike_version'])} |",
        f"| Negotiation status | {_md(m['status'])} |",
        f"| Negotiated encryption | {_md(m['negotiated']['encryption'])} |",
        f"| Negotiated integrity | {_md(m['negotiated']['integrity'])} |",
        f"| Negotiated DH group | {_md(m['negotiated']['dh_group'])} |",
        "",
    ]
    if m["offered"]:
        out += ["### Offered proposals", "", "| Encryption | Integrity | DH group |", "| --- | --- | --- |"]
        out += [f"| {_md(o.get('encryption'))} | {_md(o.get('integrity'))} | {_md(o.get('dh_group'))} |" for o in m["offered"]]
        out.append("")

    out += ["## Findings", ""]
    if not m["findings"]:
        out += ["No findings were raised under this policy.", ""]
    else:
        out += ["| ID | Severity | Scope | Observed | Title |", "| --- | --- | --- | --- | --- |"]
        out += [
            f"| {f['finding_id']} | {f['severity']} | {f['scope']} | {_md(f['evidence']['observed'])} | {_md(f['title'])} |"
            for f in m["findings"]
        ]
        out.append("")
        for f in m["findings"]:
            ev, text = f["evidence"], f["ai_text"]
            out += [
                f"### {f['finding_id']}: {f['title']} ({f['severity']})", "",
                f"- **Observed:** {_md(ev['observed'])} ({f['scope']})",
                f"- **Policy expects:** {_md(ev['expected'])}",
                f"- **Detected by:** rule {f['finding_id']} v{f['rule_version']}, policy `{f['policy_id']}`",
                "", "**Why it matters.** " + f["why_it_matters"], "",
            ]
            if text:
                out += [f"**In plain language** *({_source_label(text.get('source'))}).* {text.get('explanation', '')} {text.get('impact', '')}", ""]
            out += ["**Evidence from the capture**", ""]
            if ev["items"]:
                out += ["| Packet | Field | Value |", "| --- | --- | --- |"]
                out += [f"| {i['packet']} | `{_md(i['field'])}` | {_md(i['value'])} |" for i in ev["items"]]
            else:
                out.append("No matching entry was recorded by the analyzer.")
            out += ["", "**Remediation**", ""]
            steps = text.get("remediation_steps") or [f["remediation"]]
            out += [f"{n}. {s}" for n, s in enumerate(steps, 1)]
            out.append("")

    c = m.get("comparison")
    if c:
        pc = c["posture_change"]
        out += ["## Before and after", "",
                f"Verdict: **{pc['verdict']}**. Score {_md(c['before']['score'])} to {_md(c['after']['score'])}; "
                f"rating {_md(pc['rating_before'])} to {_md(pc['rating_after'])}.", ""]
        if c["parameter_changes"]:
            out += ["| Parameter | Before | After |", "| --- | --- | --- |"]
            out += [f"| {x['parameter']} | {_md(x['before'])} | {_md(x['after'])} |" for x in c["parameter_changes"]]
            out.append("")
        for key, label in (("resolved", "Resolved"), ("introduced", "Introduced"), ("unchanged", "Unchanged")):
            if c[key]:
                out += [f"**{label}:** " + "; ".join(f"{x['finding_id']} ({x['severity']}, {_md(x['observed'])})" for x in c[key]), ""]
        for w in c["warnings"]:
            out += [f"> {w}", ""]

    out += ["## Method and limits", ""] + [f"- {x}" for x in LIMITS] + [""]
    if m["ai"].get("warnings"):
        out += ["## AI notes", ""] + [f"- {w}" for w in m["ai"]["warnings"]] + [""]
    return "\n".join(out)


# --- HTML --------------------------------------------------------------

CSS = """
:root{--fg:#1b2430;--muted:#5b6675;--line:#d9dee5;--bg:#fff;--soft:#f4f6f9;
--crit:#8e1b1b;--high:#b3380d;--med:#8a5a00;--low:#1d5fa8;--info:#4a5563}
@media (prefers-color-scheme:dark){:root{--fg:#e7ebf0;--muted:#a3adba;--line:#2f3a48;--bg:#12171d;--soft:#1a212a;
--crit:#ff8d8d;--high:#ffa57a;--med:#f2c45f;--low:#7fb6f2;--info:#aab4c0}}
body{font:15px/1.55 system-ui,Segoe UI,Roboto,sans-serif;color:var(--fg);background:var(--bg);max-width:860px;margin:0 auto;padding:24px 16px}
h1{font-size:1.7rem;margin:0 0 .5rem}h2{font-size:1.25rem;margin:2rem 0 .5rem;border-bottom:1px solid var(--line);padding-bottom:.25rem}
h3{font-size:1.05rem;margin:1.5rem 0 .4rem}table{border-collapse:collapse;width:100%;margin:.5rem 0;font-size:.92rem}
th,td{border:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}th{background:var(--soft)}
code{background:var(--soft);padding:1px 4px;border-radius:3px;word-break:break-all}
.meta{color:var(--muted)}.sev{font-weight:700}.Critical{color:var(--crit)}.High{color:var(--high)}
.Medium{color:var(--med)}.Low{color:var(--low)}.Informational{color:var(--info)}
.note{border-left:3px solid var(--line);padding:.2rem .8rem;color:var(--muted)}
@media print{body{max-width:none;padding:0}h3{break-after:avoid}table{break-inside:avoid}}
"""


def _e(value: Any) -> str:
    return html.escape(_v(value))


def _table(headers: List[str], rows: List[List[str]]) -> str:
    head = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def render_html(m: Dict[str, Any]) -> str:
    p = m["posture"]
    score = "n/a" if p.get("score") is None else f"{p['score']}/100"
    h: List[str] = [f"<h1>{html.escape(TITLE)}</h1>", '<p class="meta">']
    h.append("<br>".join([
        f"Session: <code>{_e(m['session_id'])}</code>",
        f"Capture file: {_e(m['capture_file'])}",
        f"Policy: {_e(m['policy'].get('name'))} (<code>{_e(m['policy'].get('id'))}</code> v{_e(m['policy'].get('version'))})",
        f"Ruleset version: {_e(m['ruleset_version'])}",
        f"Rating: <strong>{_e(p.get('rating'))}</strong> (score {html.escape(score)})",
    ]) + "</p>")
    h += ["<h2>Summary</h2>", f"<p>{_e(m['summary'].get('text', ''))}</p>",
          f'<p class="note">Wording: {html.escape(_source_label(m["summary"].get("source")))}. {_e(p.get("basis_note", ""))}</p>']

    h.append("<h2>Session overview</h2>")
    h.append(_table(["Item", "Value"], [
        ["IKE version", _e(m["ike_version"])], ["Negotiation status", _e(m["status"])],
        ["Negotiated encryption", _e(m["negotiated"]["encryption"])],
        ["Negotiated integrity", _e(m["negotiated"]["integrity"])],
        ["Negotiated DH group", _e(m["negotiated"]["dh_group"])],
    ]))
    if m["offered"]:
        h.append("<h3>Offered proposals</h3>")
        h.append(_table(["Encryption", "Integrity", "DH group"],
                        [[_e(o.get("encryption")), _e(o.get("integrity")), _e(o.get("dh_group"))] for o in m["offered"]]))

    h.append("<h2>Findings</h2>")
    if not m["findings"]:
        h.append("<p>No findings were raised under this policy.</p>")
    else:
        h.append(_table(["ID", "Severity", "Scope", "Observed", "Title"], [
            [html.escape(f["finding_id"]), f'<span class="sev {html.escape(f["severity"])}">{html.escape(f["severity"])}</span>',
             html.escape(f["scope"]), _e(f["evidence"]["observed"]), html.escape(f["title"])] for f in m["findings"]]))
        for f in m["findings"]:
            ev, text = f["evidence"], f["ai_text"]
            h.append(f'<h3>{html.escape(f["finding_id"])}: {html.escape(f["title"])} '
                     f'(<span class="sev {html.escape(f["severity"])}">{html.escape(f["severity"])}</span>)</h3>')
            h.append("<p>" + "<br>".join([
                f"<strong>Observed:</strong> {_e(ev['observed'])} ({html.escape(f['scope'])})",
                f"<strong>Policy expects:</strong> {_e(ev['expected'])}",
                f"<strong>Detected by:</strong> rule {html.escape(f['finding_id'])} v{html.escape(f['rule_version'])}, policy <code>{html.escape(f['policy_id'])}</code>",
            ]) + "</p>")
            h.append(f"<p><strong>Why it matters.</strong> {html.escape(f['why_it_matters'])}</p>")
            if text:
                h.append(f"<p><strong>In plain language</strong> <em>({html.escape(_source_label(text.get('source')))}).</em> "
                         f"{html.escape(text.get('explanation', ''))} {html.escape(text.get('impact', ''))}</p>")
            h.append("<p><strong>Evidence from the capture</strong></p>")
            if ev["items"]:
                h.append(_table(["Packet", "Field", "Value"],
                                [[_e(i["packet"]), f"<code>{_e(i['field'])}</code>", _e(i["value"])] for i in ev["items"]]))
            else:
                h.append("<p>No matching entry was recorded by the analyzer.</p>")
            steps = text.get("remediation_steps") or [f["remediation"]]
            h.append("<p><strong>Remediation</strong></p><ol>" + "".join(f"<li>{html.escape(s)}</li>" for s in steps) + "</ol>")

    c = m.get("comparison")
    if c:
        pc = c["posture_change"]
        h.append("<h2>Before and after</h2>")
        h.append(f"<p>Verdict: <strong>{html.escape(pc['verdict'])}</strong>. Score {_e(c['before']['score'])} to {_e(c['after']['score'])}; "
                 f"rating {_e(pc['rating_before'])} to {_e(pc['rating_after'])}.</p>")
        if c["parameter_changes"]:
            h.append(_table(["Parameter", "Before", "After"],
                            [[html.escape(x["parameter"]), _e(x["before"]), _e(x["after"])] for x in c["parameter_changes"]]))
        for key, label in (("resolved", "Resolved"), ("introduced", "Introduced"), ("unchanged", "Unchanged")):
            if c[key]:
                h.append(f"<p><strong>{label}:</strong> " + "; ".join(
                    f"{html.escape(x['finding_id'])} ({html.escape(x['severity'])}, {_e(x['observed'])})" for x in c[key]) + "</p>")
        for w in c["warnings"]:
            h.append(f'<p class="note">{html.escape(w)}</p>')

    h.append("<h2>Method and limits</h2><ul>" + "".join(f"<li>{html.escape(x)}</li>" for x in LIMITS) + "</ul>")
    if m["ai"].get("warnings"):
        h.append("<h2>AI notes</h2><ul>" + "".join(f"<li>{html.escape(w)}</li>" for w in m["ai"]["warnings"]) + "</ul>")

    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>{html.escape(TITLE)}</title><style>{CSS}</style></head><body>{''.join(h)}</body></html>")
