import React from "react";
import { SEVERITIES, value } from "../severity.js";

export default function Findings({ findings, selected, onSelect }) {
  if (!findings.length) {
    return <p className="empty">No findings under this policy. Try the strict policy to see what a tighter standard flags.</p>;
  }
  return (
    <div className="findings">
      {SEVERITIES.map((sev) => {
        const group = findings.filter((f) => f.severity === sev);
        if (!group.length) return null;
        return (
          <div key={sev} className="fgroup">
            <h3 className={`sev-${sev}`}>{sev} <span className="muted">({group.length})</span></h3>
            <ul>
              {group.map((f) => (
                <li key={f.key}>
                  <button type="button" className={`frow ${f.key === selected ? "on" : ""}`} aria-pressed={f.key === selected} onClick={() => onSelect(f.key)}>
                    <span className="ftitle">{f.title}</span>
                    <span className="fmeta">
                      <code>{value(f.evidence.observed)}</code>
                      {f.scope === "offered" && <span className="tag">offered only</span>}
                      <span className="muted">{f.finding_id}</span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        );
      })}
    </div>
  );
}
