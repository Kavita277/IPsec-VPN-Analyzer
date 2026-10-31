import React from "react";
import { value } from "../severity.js";
import {
  AlertTriangleIcon,
  CheckCircleIcon,
  FileTextIcon,
  InfoIcon,
  SparklesIcon,
  LockIcon,
} from "./Icons.jsx";

export default function Detail({ finding, text }) {
  if (!finding) {
    return (
      <div className="card empty-card evidence-empty">
        <InfoIcon size={28} />
        <h4>No Finding Selected</h4>
        <p className="muted">Select a finding from the list to follow its step-by-step evidence chain back to the raw capture packets.</p>
      </div>
    );
  }

  const ev = finding.evidence || {};
  const steps = text?.remediation_steps?.length ? text.remediation_steps : [finding.remediation];
  const items = ev.items || [];

  return (
    <article className="card evidence-chain-card" aria-label={`Evidence chain for finding ${finding.finding_id}`}>
      {/* Evidence Chain Header */}
      <div className="evidence-chain-header">
        <div className="chain-title-wrap">
          <span className={`finding-sev-badge sev-${finding.severity}`}>
            {finding.severity}
          </span>
          <span className="chain-rule-pill">{finding.finding_id}</span>
        </div>
        <h3 className="chain-main-title">{finding.title}</h3>
      </div>

      {/* Vertical Step Timeline */}
      <div className="vertical-timeline">
        {/* Step 1: OBSERVED */}
        <div className="timeline-step">
          <div className="timeline-node node-observed">
            <span>1</span>
          </div>
          <div className="timeline-content">
            <span className="step-tag">STEP 1: OBSERVED VALUE</span>
            <div className="step-observed-box">
              <code className="step-observed-code">{value(ev.observed)}</code>
              <span className="step-scope-badge">
                {finding.scope === "offered"
                  ? "Offered Proposal (Not agreed)"
                  : finding.scope === "negotiated"
                  ? "Negotiated Tunnel"
                  : "Session Scope"}
              </span>
            </div>
          </div>
        </div>

        {/* Step 2: POLICY CHECK */}
        <div className="timeline-step">
          <div className="timeline-node node-policy">
            <span>2</span>
          </div>
          <div className="timeline-content">
            <span className="step-tag">STEP 2: POLICY EXPECTATION</span>
            <p className="step-policy-text">{ev.expected || "Value permitted by active standard"}</p>
          </div>
        </div>

        {/* Step 3: RULE TRIGGERED */}
        <div className="timeline-step">
          <div className="timeline-node node-rule">
            <span>3</span>
          </div>
          <div className="timeline-content">
            <span className="step-tag">STEP 3: RULE TRIGGERED</span>
            <p className="step-rule-name">
              <strong>{finding.finding_id}</strong> (v{finding.rule_version}) under policy <code>{finding.policy_id}</code>
            </p>
            {finding.standards && finding.standards.length > 0 && (
              <p className="step-standards-cite muted small">
                Referenced Standards: {finding.standards.join(", ")}
              </p>
            )}
          </div>
        </div>

        {/* Step 4: PACKET EVIDENCE */}
        <div className="timeline-step">
          <div className="timeline-node node-evidence">
            <span>4</span>
          </div>
          <div className="timeline-content">
            <span className="step-tag">STEP 4: PACKET PROVENANCE</span>
            {items.length ? (
              <div className="evidence-table-wrap">
                <table className="evidence-table">
                  <thead>
                    <tr>
                      <th scope="col">Packet #</th>
                      <th scope="col">Dissected Field</th>
                      <th scope="col">Extracted Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((it, n) => (
                      <tr key={n}>
                        <td><span className="packet-badge">#{it.packet}</span></td>
                        <td><code className="field-code">{it.field}</code></td>
                        <td><code className="val-code">{value(it.value)}</code></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="muted small">No specific packet offset mapped. Derived from session negotiation state.</p>
            )}
          </div>
        </div>

        {/* Step 5: WHAT IT MEANS */}
        <div className="timeline-step">
          <div className="timeline-node node-meaning">
            <span>5</span>
          </div>
          <div className="timeline-content">
            <div className="step-tag-row">
              <span className="step-tag">STEP 5: TECHNICAL IMPACT & MEANING</span>
              {text?.source && (
                <span className="ai-source-pill">
                  <SparklesIcon size={12} />
                  <span>{text.source === "template" ? "Deterministic Template" : `Generated by ${text.source}`}</span>
                </span>
              )}
            </div>

            {text ? (
              <div className="meaning-box">
                <p className="meaning-explanation">{text.explanation}</p>
                {text.impact && <p className="meaning-impact">{text.impact}</p>}
                <details className="meaning-details">
                  <summary>View raw technical rule rationale</summary>
                  <p className="raw-rationale">{finding.why_it_matters}</p>
                </details>
              </div>
            ) : (
              <p className="meaning-explanation">{finding.why_it_matters}</p>
            )}
          </div>
        </div>

        {/* Step 6: RECOMMENDED ACTION */}
        <div className="timeline-step timeline-step-last">
          <div className="timeline-node node-remediation">
            <span>6</span>
          </div>
          <div className="timeline-content">
            <span className="step-tag">STEP 6: RECOMMENDED REMEDIATION</span>
            <div className="remediation-steps-box">
              <ol className="remediation-list">
                {steps.map((st, n) => (
                  <li key={n} className="remediation-step-item">
                    {st}
                  </li>
                ))}
              </ol>
            </div>
          </div>
        </div>
      </div>
    </article>
  );
}
