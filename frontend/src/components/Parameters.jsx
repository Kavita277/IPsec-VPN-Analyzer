import React from "react";
import { PARAM_LABEL, value } from "../severity.js";

// For each parameter: what was negotiated, what was offered, and the worst finding on each value.
export default function Parameters({ doc, onPick }) {
  const neg = doc.negotiation || {};
  const offered = neg.offered_proposals || [];
  const failed = neg.status === "failed";

  const flag = (param, val) => {
    const hits = doc.findings.filter((f) => f.evidence.parameter === param && f.evidence.observed === val);
    if (!hits.length) return null;
    const f = hits[0]; // findings arrive sorted most severe first
    return (
      <button type="button" className={`chip sev-${f.severity}`} onClick={() => onPick(f.key)} title={f.title}>
        {f.severity}
      </button>
    );
  };

  return (
    <table className="params">
      <caption className="sr-only">Negotiated and offered parameters</caption>
      <thead>
        <tr><th scope="col">Parameter</th><th scope="col">Negotiated</th><th scope="col">Offered</th></tr>
      </thead>
      <tbody>
        {Object.entries(PARAM_LABEL).map(([param, label]) => {
          const chosen = doc.security_parameters?.[param];
          const offers = [...new Set(offered.map((o) => o[param]).filter(Boolean))];
          return (
            <tr key={param}>
              <th scope="row">{label}</th>
              <td>
                {chosen ? <><code>{chosen}</code> {flag(param, chosen)}</> : <span className="muted">{failed ? "none agreed" : "not observed"}</span>}
              </td>
              <td>
                {offers.length ? offers.map((o) => <div key={o}><code>{o}</code> {flag(param, o)}</div>) : <span className="muted">{value(null)}</span>}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
