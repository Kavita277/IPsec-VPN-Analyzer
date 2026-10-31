import React, { useState } from "react";
import { SEVERITIES, value } from "../severity.js";
import { AlertTriangleIcon, CheckCircleIcon, InfoIcon, ArrowRightIcon } from "./Icons.jsx";

export default function Findings({ findings, selected, onSelect, comparison }) {
  const [activeFilter, setActiveFilter] = useState("ALL");

  if (!findings || !findings.length) {
    return (
      <div className="card empty-card">
        <CheckCircleIcon size={32} />
        <h4>No Policy Violations Found</h4>
        <p className="muted">This session complies with all rules in the active policy. Select the strict policy to test under tighter requirements.</p>
      </div>
    );
  }

  // Count severities
  const counts = {
    ALL: findings.length,
    Critical: findings.filter((f) => f.severity === "Critical").length,
    High: findings.filter((f) => f.severity === "High").length,
    Medium: findings.filter((f) => f.severity === "Medium").length,
    Low: findings.filter((f) => f.severity === "Low").length,
    Informational: findings.filter((f) => f.severity === "Informational").length,
  };

  const resolvedCount = comparison?.diff?.resolved?.length || 0;

  const filteredFindings = activeFilter === "ALL"
    ? findings
    : findings.filter((f) => f.severity === activeFilter);

  return (
    <div className="findings-container">
      {/* Findings Top Metrics Bar */}
      <div className="findings-metrics-bar">
        <div className="findings-stat-pill">
          <span className="stat-label">Total Findings</span>
          <span className="stat-num">{counts.ALL}</span>
        </div>
        <div className="findings-stat-pill high">
          <span className="stat-label">Critical / High</span>
          <span className="stat-num">{counts.Critical + counts.High}</span>
        </div>
        <div className="findings-stat-pill med">
          <span className="stat-label">Medium / Low</span>
          <span className="stat-num">{counts.Medium + counts.Low}</span>
        </div>
        {resolvedCount > 0 && (
          <div className="findings-stat-pill resolved">
            <span className="stat-label">Resolved in Compare</span>
            <span className="stat-num">+{resolvedCount}</span>
          </div>
        )}
      </div>

      {/* Severity Filter Pills */}
      <div className="findings-filter-row" role="tablist" aria-label="Filter findings by severity">
        <button
          type="button"
          className={`filter-pill ${activeFilter === "ALL" ? "active" : ""}`}
          onClick={() => setActiveFilter("ALL")}
        >
          All ({counts.ALL})
        </button>
        {SEVERITIES.map((sev) => {
          if (!counts[sev]) return null;
          return (
            <button
              key={sev}
              type="button"
              className={`filter-pill sev-filter-${sev} ${activeFilter === sev ? "active" : ""}`}
              onClick={() => setActiveFilter(sev)}
            >
              {sev} ({counts[sev]})
            </button>
          );
        })}
      </div>

      {/* Findings Cards List */}
      <div className="findings-list">
        {filteredFindings.map((f) => {
          const isSelected = f.key === selected;
          const evCount = f.evidence?.items?.length || 0;
          const packetsList = f.evidence?.items?.map((i) => `#${i.packet}`).join(", ");

          return (
            <div
              key={f.key}
              className={`card finding-item-card sev-border-${f.severity} ${isSelected ? "is-selected" : ""}`}
              onClick={() => onSelect(f.key)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => e.key === "Enter" && onSelect(f.key)}
            >
              <div className="finding-card-head">
                <span className={`finding-sev-badge sev-${f.severity}`}>
                  {f.severity}
                </span>
                <span className="finding-rule-id">{f.finding_id}</span>
                {f.scope === "offered" && (
                  <span className="scope-tag">Offered Proposal Only</span>
                )}
              </div>

              <h4 className="finding-item-title">{f.title}</h4>

              <div className="finding-observed-row">
                <span className="observed-lbl">Observed value:</span>
                <code className="observed-val">{value(f.evidence?.observed)}</code>
              </div>

              <p className="finding-short-desc">
                {f.evidence?.expected ? `Expected: ${f.evidence.expected}` : f.why_it_matters.slice(0, 110) + "..."}
              </p>

              <div className="finding-card-footer">
                <div className="finding-evidence-pill">
                  {evCount > 0 ? (
                    <span>Evidence in Packet {packetsList}</span>
                  ) : (
                    <span>Session observation</span>
                  )}
                </div>
                <span className="view-detail-link">
                  <span>View Evidence Chain</span>
                  <ArrowRightIcon size={14} />
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
