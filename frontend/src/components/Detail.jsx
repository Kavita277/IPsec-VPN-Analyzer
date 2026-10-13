import React from "react";
import { value } from "../severity.js";

// The evidence chain for one finding: observation, policy, rule, evidence, meaning, fix.
export default function Detail({ finding, text }) {
  if (!finding) return <p className="muted">Select a finding to follow it back to the packets.</p>;
  const ev = finding.evidence;
  const steps = text?.remediation_steps?.length ? text.remediation_steps : [finding.remediation];

  return (
    <article className="chain" aria-label={`Finding ${finding.finding_id}`}>
      <header>
        <p className={`chip sev-${finding.severity}`}>{finding.severity}</p>
        <h3>{finding.title}</h3>
      </header>

      <section>
        <h4>Observed</h4>
        <p><code>{value(ev.observed)}</code> <span className="muted">({finding.scope === "offered" ? "offered, not agreed" : finding.scope === "negotiated" ? "negotiated" : "session level"})</span></p>
      </section>
      <section>
        <h4>Policy expects</h4>
        <p>{ev.expected}</p>
      </section>
      <section>
        <h4>Rule</h4>
        <p><code>{finding.finding_id}</code> version {finding.rule_version}, policy <code>{finding.policy_id}</code></p>
        {finding.standards.length > 0 && <p className="muted small">Related: {finding.standards.join(", ")}</p>}
      </section>
      <section>
        <h4>Evidence</h4>
        {ev.items.length ? (
          <table className="evidence">
            <thead><tr><th scope="col">Packet</th><th scope="col">Field</th><th scope="col">Value</th></tr></thead>
            <tbody>
              {ev.items.map((i, n) => (
                <tr key={n}><td>{i.packet}</td><td><code>{i.field}</code></td><td><code>{value(i.value)}</code></td></tr>
              ))}
            </tbody>
          </table>
        ) : <p className="muted">The analyzer recorded no matching entry for this finding.</p>}
      </section>
      <section>
        <h4>What it means</h4>
        {text ? (
          <>
            <p>{text.explanation} {text.impact}
              <span className="muted small"> {text.source === "template" ? "Template wording." : `Written by ${text.source}.`}</span>
            </p>
            <details>
              <summary>Technical rationale from the rule</summary>
              <p>{finding.why_it_matters}</p>
            </details>
          </>
        ) : <p>{finding.why_it_matters}</p>}
      </section>
      <section>
        <h4>How to fix it</h4>
        <ol>{steps.map((s, n) => <li key={n}>{s}</li>)}</ol>
      </section>
    </article>
  );
}
