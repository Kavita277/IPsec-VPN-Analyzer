import React, { useEffect, useState } from "react";
import { api } from "../api.js";
import { value } from "../severity.js";

// Before and after: pick two sessions, see which findings were resolved or introduced.
export default function Compare({ options, policy, comparison, onResult, onError }) {
  const [before, setBefore] = useState("");
  const [after, setAfter] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!options.length) return;
    const has = (id) => options.some((o) => o.id === id);
    setBefore((b) => (has(b) ? b : has("sample:weak_01") ? "sample:weak_01" : options[0].id));
    setAfter((a) => (has(a) ? a : has("sample:secure_01") ? "sample:secure_01" : options[options.length - 1].id));
  }, [options]);

  useEffect(() => {
    const b = options.find((o) => o.id === before);
    const a = options.find((o) => o.id === after);
    if (!a || !b) return;
    let live = true;
    setBusy(true);
    Promise.all([b.load(policy), a.load(policy)])
      .then(([bd, ad]) => api.compare(bd, ad).then((diff) => live && onResult({ diff, label: `${b.label} to ${a.label}`, afterDoc: ad })))
      .catch((e) => live && onError(e.message))
      .finally(() => live && setBusy(false));
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [before, after, policy, options]);

  const diff = comparison?.diff;
  const Picker = ({ label, val, set }) => (
    <label className="field">
      <span>{label}</span>
      <select value={val} onChange={(e) => set(e.target.value)}>
        {options.map((o) => <option key={o.id} value={o.id}>{o.label}</option>)}
      </select>
    </label>
  );

  return (
    <section className="compare" aria-busy={busy}>
      <p className="lede">Pick a session before a change and one after it. The same policy is applied to both, so any difference comes from the VPN.</p>
      <div className="pickers">
        <Picker label="Before" val={before} set={setBefore} />
        <Picker label="After" val={after} set={setAfter} />
      </div>

      {diff && (
        <div className="diff">
          <h2 className={`verdict v-${diff.posture_change.verdict.replace(" ", "-")}`}>
            {diff.posture_change.verdict === "improved" && "Improved"}
            {diff.posture_change.verdict === "regressed" && "Got worse"}
            {diff.posture_change.verdict === "unchanged" && "No change"}
            {diff.posture_change.verdict === "changed" && "Changed, same score"}
            {diff.posture_change.verdict === "not comparable" && "Cannot compare scores"}
          </h2>
          <p>
            Score {value(diff.before.score)} to {value(diff.after.score)}
            {diff.posture_change.score_delta !== null && ` (${diff.posture_change.score_delta > 0 ? "+" : ""}${diff.posture_change.score_delta})`}.
            Rating {diff.posture_change.rating_before} to {diff.posture_change.rating_after}.
          </p>

          {diff.parameter_changes.length > 0 && (
            <table className="params">
              <thead><tr><th scope="col">Parameter</th><th scope="col">Before</th><th scope="col">After</th></tr></thead>
              <tbody>
                {diff.parameter_changes.map((c) => (
                  <tr key={c.parameter}><th scope="row">{c.parameter}</th><td><code>{value(c.before)}</code></td><td><code>{value(c.after)}</code></td></tr>
                ))}
              </tbody>
            </table>
          )}

          <div className="difflists">
            {[["resolved", "Resolved"], ["introduced", "Introduced"], ["unchanged", "Still present"]].map(([k, title]) => (
              <div key={k}>
                <h3>{title} <span className="muted">({diff[k].length})</span></h3>
                {diff[k].length === 0 ? <p className="muted">None</p> : (
                  <ul>{diff[k].map((f) => (
                    <li key={f.key}><span className={`chip sev-${f.severity}`}>{f.severity}</span> {f.title} <code>{value(f.observed)}</code></li>
                  ))}</ul>
                )}
              </div>
            ))}
          </div>
          {diff.warnings.map((w) => <p key={w} className="note">{w}</p>)}
        </div>
      )}
    </section>
  );
}
