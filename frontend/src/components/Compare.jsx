import React, { useEffect, useState } from "react";
import { api } from "../api.js";
import { value } from "../severity.js";
import { ArrowRightIcon, CheckCircleIcon, AlertTriangleIcon, InfoIcon, GitCompareIcon } from "./Icons.jsx";

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
  const pChange = diff?.posture_change;

  return (
    <div className="compare-view" aria-busy={busy}>
      {/* Compare Introduction & Selectors */}
      <div className="card compare-header-card">
        <div className="compare-intro">
          <div className="compare-badge-icon">
            <GitCompareIcon size={22} />
          </div>
          <div>
            <h3 className="compare-main-title">Before & After Differential Assessment</h3>
            <p className="compare-main-desc">
              Evaluate cryptographic hardening by comparing an initial capture against a remediated session under the <strong>{policy}</strong> policy.
            </p>
          </div>
        </div>

        <div className="compare-selectors-grid">
          <label className="field-select-box">
            <span className="field-select-label">BEFORE SESSION (PRE-REMEDIATION)</span>
            <select className="select-input" value={before} onChange={(e) => setBefore(e.target.value)}>
              {options.map((o) => (
                <option key={o.id} value={o.id}>{o.label}</option>
              ))}
            </select>
          </label>

          <div className="compare-arrow-divider">
            <ArrowRightIcon size={20} />
          </div>

          <label className="field-select-box">
            <span className="field-select-label">AFTER SESSION (POST-REMEDIATION)</span>
            <select className="select-input" value={after} onChange={(e) => setAfter(e.target.value)}>
              {options.map((o) => (
                <option key={o.id} value={o.id}>{o.label}</option>
              ))}
            </select>
          </label>
        </div>
      </div>

      {diff && (
        <div className="compare-results-body">
          {/* Side by Side Session Cards with Verdict Banner */}
          <div className="compare-verdict-banner">
            <div className={`verdict-pill v-${pChange?.verdict?.replace(" ", "-")}`}>
              {pChange?.verdict === "improved" && <CheckCircleIcon size={20} />}
              {pChange?.verdict === "regressed" && <AlertTriangleIcon size={20} />}
              <span className="verdict-word">
                {pChange?.verdict === "improved" && "Security Posture Improved"}
                {pChange?.verdict === "regressed" && "Security Posture Regressed"}
                {pChange?.verdict === "unchanged" && "Posture Unchanged"}
                {pChange?.verdict === "changed" && "Configuration Changed, Same Score"}
                {pChange?.verdict === "not comparable" && "Cannot Compare Scores"}
              </span>
            </div>

            <div className="verdict-summary-stats">
              {pChange?.score_delta !== null && (
                <span className={`delta-badge ${pChange?.score_delta > 0 ? "positive" : pChange?.score_delta < 0 ? "negative" : "neutral"}`}>
                  Score {pChange?.score_delta > 0 ? `+${pChange.score_delta}` : pChange?.score_delta} pts
                </span>
              )}
              {diff.resolved?.length > 0 && (
                <span className="resolved-badge">
                  {diff.resolved.length} finding{diff.resolved.length > 1 ? "s" : ""} resolved
                </span>
              )}
            </div>
          </div>

          {/* Left / Right Comparison Cards */}
          <div className="compare-cards-dual">
            {/* Before Session Card */}
            <div className="card compare-session-card before-card">
              <span className="session-side-tag">BEFORE SESSION</span>
              <h4 className="compare-session-title">{options.find((o) => o.id === before)?.label || "Before Session"}</h4>

              <div className="compare-score-row">
                <div className="compare-big-score">
                  <span className="score-num">{value(diff.before?.score)}</span>
                  <span className="score-out">/ 100</span>
                </div>
                <div className={`rating-pill sev-${diff.before?.highest_severity || "none"}`}>
                  <span>{diff.before?.rating || "Evaluated"}</span>
                </div>
              </div>

              <div className="compare-counts-row">
                <span>Active Findings: <strong>{diff.before?.finding_count ?? "0"}</strong></span>
              </div>
            </div>

            {/* Transition Arrow Indicator */}
            <div className="dual-center-arrow">
              <div className="arrow-circle">
                <ArrowRightIcon size={24} />
              </div>
            </div>

            {/* After Session Card */}
            <div className="card compare-session-card after-card">
              <span className="session-side-tag">AFTER SESSION</span>
              <h4 className="compare-session-title">{options.find((o) => o.id === after)?.label || "After Session"}</h4>

              <div className="compare-score-row">
                <div className="compare-big-score">
                  <span className="score-num">{value(diff.after?.score)}</span>
                  <span className="score-out">/ 100</span>
                </div>
                <div className={`rating-pill sev-${diff.after?.highest_severity || "none"}`}>
                  <span>{diff.after?.rating || "Evaluated"}</span>
                </div>
              </div>

              <div className="compare-counts-row">
                <span>Active Findings: <strong>{diff.after?.finding_count ?? "0"}</strong></span>
              </div>
            </div>
          </div>

          {/* Parameter Transition Table */}
          {diff.parameter_changes?.length > 0 && (
            <div className="card compare-table-card">
              <h4 className="table-card-title">Parameter Evolution</h4>
              <div className="table-responsive">
                <table className="compare-diff-table">
                  <thead>
                    <tr>
                      <th scope="col">Cryptographic Parameter</th>
                      <th scope="col">Before Value</th>
                      <th scope="col"></th>
                      <th scope="col">After Value</th>
                      <th scope="col">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {diff.parameter_changes.map((c) => {
                      const isSame = c.before === c.after;
                      return (
                        <tr key={c.parameter}>
                          <th scope="row" className="param-th">{c.parameter}</th>
                          <td><code className="val-box">{value(c.before)}</code></td>
                          <td className="arrow-td"><ArrowRightIcon size={14} /></td>
                          <td><code className="val-box highlight">{value(c.after)}</code></td>
                          <td>
                            <span className={`diff-status-pill ${isSame ? "unchanged" : "updated"}`}>
                              {isSame ? "Unchanged" : "Updated"}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Tri-Column Findings Delta: Resolved / Introduced / Still Present */}
          <div className="compare-delta-grid">
            {/* Resolved */}
            <div className="card delta-col-card resolved-col">
              <div className="delta-col-header">
                <span className="delta-dot dot-green" />
                <h4>Resolved Findings ({diff.resolved.length})</h4>
              </div>
              {diff.resolved.length === 0 ? (
                <p className="muted small empty-note">No findings resolved between these sessions.</p>
              ) : (
                <ul className="delta-list">
                  {diff.resolved.map((f) => (
                    <li key={f.key} className="delta-item item-resolved">
                      <span className={`finding-sev-badge sev-${f.severity}`}>{f.severity}</span>
                      <div className="delta-item-text">
                        <span className="delta-title">{f.title}</span>
                        <code className="delta-val">{value(f.observed)}</code>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* Introduced */}
            <div className="card delta-col-card introduced-col">
              <div className="delta-col-header">
                <span className="delta-dot dot-red" />
                <h4>Introduced Findings ({diff.introduced.length})</h4>
              </div>
              {diff.introduced.length === 0 ? (
                <p className="muted small empty-note">No new regressions introduced.</p>
              ) : (
                <ul className="delta-list">
                  {diff.introduced.map((f) => (
                    <li key={f.key} className="delta-item item-introduced">
                      <span className={`finding-sev-badge sev-${f.severity}`}>{f.severity}</span>
                      <div className="delta-item-text">
                        <span className="delta-title">{f.title}</span>
                        <code className="delta-val">{value(f.observed)}</code>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* Still Present */}
            <div className="card delta-col-card unchanged-col">
              <div className="delta-col-header">
                <span className="delta-dot dot-gray" />
                <h4>Still Present ({diff.unchanged.length})</h4>
              </div>
              {diff.unchanged.length === 0 ? (
                <p className="muted small empty-note">No persistent findings remaining.</p>
              ) : (
                <ul className="delta-list">
                  {diff.unchanged.map((f) => (
                    <li key={f.key} className="delta-item item-unchanged">
                      <span className={`finding-sev-badge sev-${f.severity}`}>{f.severity}</span>
                      <div className="delta-item-text">
                        <span className="delta-title">{f.title}</span>
                        <code className="delta-val">{value(f.observed)}</code>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>

          {diff.warnings?.length > 0 && (
            <div className="card compare-warnings-card">
              {diff.warnings.map((w, idx) => (
                <p key={idx} className="warning-text">
                  <InfoIcon size={16} />
                  <span>{w}</span>
                </p>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
