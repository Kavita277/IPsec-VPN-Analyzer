import React from "react";
import { PARAM_LABEL, value } from "../severity.js";

const PARAMS = Object.keys(PARAM_LABEL);

// Where a value sits in the policy: the same lookup the rules make.
function tier(section, v) {
  if (!v) return null;
  if (section.forbidden.includes(v)) return { label: "forbidden by policy", cls: "sev-High" };
  if (section.deprecated.includes(v)) return { label: "deprecated by policy", cls: "sev-Medium" };
  if (section.approved.includes(v)) return { label: "approved", cls: "ok" };
  if (!section.approved.length) return { label: "no allow-list, not forbidden", cls: "ok" };
  return { label: "not on the approved list", cls: "sev-Medium" };
}

// Explains what the verdict is built from, using this session's own values and the live policy.
export default function RiskBasis({ doc, methodology }) {
  if (!methodology) return null;
  const { policy, weights, ratings, rules } = methodology;
  const neg = doc.negotiation || {};
  const failed = neg.status === "failed";
  const offered = neg.offered_proposals || [];
  const findings = doc.findings;
  const fired = new Set(findings.map((f) => f.finding_id));
  const worst = (pred) => findings.filter(pred)[0]; // findings arrive most severe first

  const rows = [
    {
      name: "IKE version",
      seen: doc.protocol?.ike_version,
      policy: `Allowed: ${policy.ike_versions.join(", ")}`,
      finding: worst((f) => f.finding_id === "IPSEC-PROTO-001"),
    },
    {
      name: "Handshake outcome",
      seen: neg.status,
      policy: "A completed handshake is judged on what was agreed. A failed one is judged on what was offered, one severity level lower.",
      finding: worst((f) => f.category === "negotiation"),
    },
    ...PARAMS.map((param) => {
      const chosen = doc.security_parameters?.[param];
      const offers = [...new Set(offered.map((o) => o[param]).filter(Boolean))];
      const seen = chosen || (offers.length ? `${offers.join(", ")} (offered)` : null);
      const verdicts = (chosen ? [chosen] : offers).map((v) => ({ v, t: tier(policy.parameters[param], v) }));
      return {
        name: PARAM_LABEL[param],
        seen,
        verdicts,
        policy: `Forbidden: ${policy.parameters[param].forbidden.length} values. Deprecated: ${policy.parameters[param].deprecated.length}. ${policy.parameters[param].approved.length ? `Approved: ${policy.parameters[param].approved.length}.` : "No allow-list."}`,
        finding: worst((f) => f.evidence.parameter === param),
      };
    }),
  ];

  const deductions = findings.filter((f) => weights[f.severity] > 0);
  const total = deductions.reduce((n, f) => n + weights[f.severity], 0);

  return (
    <section className="basis" aria-labelledby="basis-h">
      <h2 id="basis-h">How this verdict is reached</h2>

      <div className="callout">
        <strong>This is a configuration audit, not a malware or attack detector.</strong>
        <p>
          It answers "was this tunnel set up with algorithms that meet the policy?". It does not look at who the peers are, what traffic
          flowed, or whether anyone attacked the tunnel. ESP payloads are encrypted and never read. A <em>Compliant</em> rating means
          the negotiated settings are acceptable, not that the traffic is safe. A <em>Critical</em> or <em>High risk</em> rating means the
          tunnel is weakly protected and could be broken or downgraded by an attacker, not that an attacker is present.
        </p>
      </div>

      <h3>What happens to a file you upload</h3>
      <ol className="steps">
        <li><strong>A .pcap or .pcapng capture</strong> is read by tshark. Only IKEv2 packets (UDP 500 and 4500) are kept. Packets are grouped into sessions, and from each session the analyzer extracts the proposals offered, the proposal chosen, the handshake outcome and the packet numbers that show each value.</li>
        <li><strong>An analysis .json file</strong> skips that step and is checked against the analysis schema. It then goes through the same rules, so a hand-edited JSON is judged exactly like a capture that produced it.</li>
        <li><strong>The rule engine</strong> compares every extracted value with the selected policy (<code>{policy.name}</code>). Each rule that fails becomes a finding with a severity and the packets that prove it. No finding is created without a rule, and the AI cannot add or change one.</li>
        <li><strong>The score</strong> is arithmetic over the findings, shown below. The same input, policy and ruleset always give the same result.</li>
      </ol>

      <h3>What was checked in this session</h3>
      <table className="basis-table">
        <caption className="sr-only">Parameters inspected, what the policy says about them, and the outcome for this session</caption>
        <thead><tr><th scope="col">Checked</th><th scope="col">Seen in this session</th><th scope="col">Policy ({policy.id})</th><th scope="col">Result</th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.name}>
              <th scope="row">{r.name}</th>
              <td>{r.seen ? <code>{r.seen}</code> : <span className="muted">{failed ? "none agreed" : value(null)}</span>}</td>
              <td className="small">
                {r.policy}
                {r.verdicts?.map(({ v, t }) => t && <div key={v}><code>{v}</code>: <span className={t.cls}>{t.label}</span></div>)}
              </td>
              <td>{r.finding ? <><span className={`sev-${r.finding.severity}`}><strong>{r.finding.severity}</strong></span> <span className="small">{r.finding.finding_id}</span></> : <span className="ok">Pass</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3>How the score and rating follow</h3>
      <p className="small muted">Score = 100 minus a weight per finding ({methodology.severities.map((s) => `${s} ${weights[s]}`).join(", ")}), never below 0. Rating comes from the single worst finding.</p>
      <p className="calc">
        {doc.posture.score === null ? (
          <>No algorithm parameters were observed, so there is no score and the rating is <strong>Not assessable</strong>. It is never shown as Compliant.</>
        ) : (
          <>
            <code>100{deductions.map((f) => ` − ${weights[f.severity]}`).join("")} = {Math.max(0, 100 - total)}</code>
            {deductions.length > 0 && <span className="muted small"> ({deductions.map((f) => `${f.severity} ${f.finding_id}`).join(", ")})</span>}
            {" "}Worst finding: <strong className={doc.posture.highest_severity ? `sev-${doc.posture.highest_severity}` : "ok"}>{doc.posture.highest_severity ?? "none"}</strong> → rating <strong>{doc.posture.rating}</strong>.
          </>
        )}
      </p>
      <ul className="scale">
        {ratings.map((r) => (
          <li key={r.severity} className={r.rating === doc.posture.rating ? "now" : ""}>
            <span className={`sev-${r.severity}`}>{r.severity}</span> → {r.rating}
          </li>
        ))}
      </ul>

      <details>
        <summary>All {rules.length} rules and which ones fired for this session</summary>
        <table className="basis-table">
          <thead><tr><th scope="col">Rule</th><th scope="col">What it checks</th><th scope="col">Default severity</th><th scope="col">This session</th></tr></thead>
          <tbody>
            {rules.map((r) => (
              <tr key={r.id}>
                <th scope="row"><code>{r.id}</code></th>
                <td>{r.title}</td>
                <td className={`sev-${r.severity}`}>{r.severity}</td>
                <td>{fired.has(r.id) ? <strong>Fired</strong> : <span className="muted">Passed</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>

      <p className="small muted">
        Not judged yet: SA lifetimes, PRF, authentication method, ESP transforms, certificates, and anything inside encrypted payloads.
        {" "}A capture that lacks the handshake (for example, one started after the tunnel came up) cannot be assessed.
      </p>
    </section>
  );
}
