import React from "react";
import { SEVERITIES } from "../severity.js";

export default function Posture({ doc, explanation }) {
  const p = doc.posture;
  const total = SEVERITIES.reduce((n, s) => n + (p.counts[s] || 0), 0);
  const summary = explanation?.summary;

  return (
    <section className="posture" aria-label="Overall posture">
      <div className="posture-head">
        <h2 className={`rating ${p.highest_severity ? `sev-${p.highest_severity}` : ""}`}>{p.rating}</h2>
        <p className="score">
          {p.score === null ? "No score" : <><strong>{p.score}</strong> out of 100</>}
          <span className="muted"> under {doc.assessment.policy.name}</span>
        </p>
      </div>

      {total > 0 && (
        <div className="sevbar" role="img" aria-label={SEVERITIES.filter((s) => p.counts[s]).map((s) => `${p.counts[s]} ${s}`).join(", ")}>
          <div className="sevbar-track">
            {SEVERITIES.filter((s) => p.counts[s]).map((s) => (
              <span key={s} className={`seg bg-${s}`} style={{ flexGrow: p.counts[s] }} />
            ))}
          </div>
          <ul className="sevbar-legend">
            {SEVERITIES.filter((s) => p.counts[s]).map((s) => (
              <li key={s}><span className={`swatch bg-${s}`} aria-hidden="true" />{p.counts[s]} {s.toLowerCase()}</li>
            ))}
          </ul>
        </div>
      )}

      <p className="summary">{summary ? summary.text : "Writing the summary…"}</p>
      <p className="muted small">
        {p.basis_note}
        {summary && <> Wording: {summary.source === "template" ? "built from fixed templates" : `written by ${summary.source}`}. The score and findings come from the rule engine, not the AI.</>}
      </p>
    </section>
  );
}
