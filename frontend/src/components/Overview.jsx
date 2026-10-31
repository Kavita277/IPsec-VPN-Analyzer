import React from "react";
import ScoreGauge from "./ScoreGauge.jsx";
import {
  ShieldIcon,
  LockIcon,
  KeyIcon,
  AlertTriangleIcon,
  CheckCircleIcon,
  ArrowRightIcon,
  FileTextIcon,
  NetworkIcon,
  GitCompareIcon,
  SparklesIcon,
  InfoIcon,
} from "./Icons.jsx";
import RiskBasis from "./RiskBasis.jsx";

export default function Overview({ doc, explanation, onNavigateTab, onSelectFinding, methodology }) {
  if (!doc) return null;

  const p = doc.posture || {};
  const neg = doc.negotiation || {};
  const secParams = doc.security_parameters || {};
  const findings = doc.findings || [];

  const counts = p.counts || {};
  const highCount = (counts.Critical || 0) + (counts.High || 0);
  const medLowCount = (counts.Medium || 0) + (counts.Low || 0);
  const infoCount = counts.Informational || 0;
  const totalFindings = findings.length;

  // Determine parameter status from findings
  const getParamStatus = (paramName) => {
    const relevant = findings.filter((f) => f.evidence?.parameter === paramName);
    if (!relevant.length) {
      const val = secParams[paramName];
      if (!val) return { state: "neutral", label: neg.status === "failed" ? "None agreed" : "Not observed", findingKey: null };
      return { state: "pass", label: "Approved by policy", findingKey: null };
    }
    const worst = relevant[0];
    if (worst.severity === "Critical" || worst.severity === "High") {
      return { state: "fail", label: `Violates policy (${worst.severity})`, findingKey: worst.key };
    }
    if (worst.severity === "Medium" || worst.severity === "Low") {
      return { state: "warning", label: `Deprecated/Flagged (${worst.severity})`, findingKey: worst.key };
    }
    return { state: "info", label: "Informational note", findingKey: worst.key };
  };

  const encStatus = getParamStatus("encryption");
  const intStatus = getParamStatus("integrity");
  const dhStatus = getParamStatus("dh_group");

  const summaryText = explanation?.summary?.text || (
    totalFindings === 0
      ? `Session satisfies all criteria under ${doc.assessment?.policy?.name || "the selected policy"} with no detected violations.`
      : `Session evaluated under ${doc.assessment?.policy?.name || "the selected policy"}. Detected ${totalFindings} finding(s) impacting cryptographic posture.`
  );

  const handleParamClick = (statusObj) => {
    if (statusObj.findingKey) {
      onSelectFinding(statusObj.findingKey);
      onNavigateTab("findings");
    } else {
      onNavigateTab("findings");
    }
  };

  return (
    <div className="overview-container">
      {/* Top Banner Row: Status & Score */}
      <div className="overview-hero-grid">
        {/* Card A: Security Status Card */}
        <div className="card hero-status-card">
          <div className="card-header-clean">
            <div className="status-indicator-badge">
              {p.highest_severity === "Critical" || p.highest_severity === "High" ? (
                <div className="status-icon-wrap status-high">
                  <AlertTriangleIcon size={24} />
                </div>
              ) : p.highest_severity === "Medium" || p.highest_severity === "Low" ? (
                <div className="status-icon-wrap status-med">
                  <AlertTriangleIcon size={24} />
                </div>
              ) : (
                <div className="status-icon-wrap status-pass">
                  <CheckCircleIcon size={24} />
                </div>
              )}
              <div>
                <span className="card-kicker">Assessment Status</span>
                <h2 className="hero-status-title">
                  {p.rating === "Compliant" ? "Session Compliant" : p.rating || "Evaluated"}
                </h2>
              </div>
            </div>

            <div className="policy-badge-pill">
              <span>Policy:</span> <strong>{doc.assessment?.policy?.name || "NIST Baseline"}</strong>
            </div>
          </div>

          <div className="hero-status-body">
            <p className="hero-status-summary">{summaryText}</p>

            <div className="hero-status-meta">
              <div className="status-meta-pill">
                <span className="meta-label">Negotiation:</span>
                <span className={`meta-val ${neg.status === "failed" ? "meta-fail" : "meta-ok"}`}>
                  {neg.status === "failed" ? "Failed (NO_PROPOSAL_CHOSEN)" : "Successful Handshake"}
                </span>
              </div>
              <div className="status-meta-pill">
                <span className="meta-label">Basis:</span>
                <span className="meta-val">{p.basis === "negotiated" ? "Negotiated Tunnel" : "Offered Proposals"}</span>
              </div>
              {explanation?.summary?.source && (
                <div className="status-meta-pill">
                  <SparklesIcon size={14} className="sparkle-icon" />
                  <span className="meta-label">Wording:</span>
                  <span className="meta-val">{explanation.summary.source}</span>
                </div>
              )}
            </div>
          </div>

          <div className="hero-actions-row">
            <button type="button" className="action-pill primary" onClick={() => onNavigateTab("findings")}>
              <span>Explore Findings ({totalFindings})</span>
              <ArrowRightIcon size={16} />
            </button>
            <button type="button" className="action-pill secondary" onClick={() => onNavigateTab("handshake")}>
              <NetworkIcon size={16} />
              <span>View Handshake</span>
            </button>
            <button type="button" className="action-pill secondary" onClick={() => onNavigateTab("compare")}>
              <GitCompareIcon size={16} />
              <span>Compare Sessions</span>
            </button>
            <button type="button" className="action-pill secondary" onClick={() => onNavigateTab("report")}>
              <FileTextIcon size={16} />
              <span>Open Report</span>
            </button>
          </div>
        </div>

        {/* Card B: Security Score Card */}
        <div className="card hero-score-card">
          <div className="card-header-clean">
            <span className="card-kicker">Security Posture</span>
            <span className="score-category-tag">Deterministic Score</span>
          </div>

          <ScoreGauge
            score={p.score}
            rating={p.rating}
            highestSeverity={p.highest_severity}
          />
        </div>
      </div>

      {/* Row 2: Findings Summary Metric Cards */}
      <div className="overview-metrics-grid">
        <div className="metric-card metric-card-high" onClick={() => onNavigateTab("findings")}>
          <div className="metric-card-top">
            <div className="metric-icon-badge bg-high">
              <AlertTriangleIcon size={20} />
            </div>
            <span className="metric-card-count">{highCount}</span>
          </div>
          <div className="metric-card-bottom">
            <h4 className="metric-card-title">High Risk Issues</h4>
            <p className="metric-card-desc">Critical & High severity policy breaches</p>
          </div>
        </div>

        <div className="metric-card metric-card-med" onClick={() => onNavigateTab("findings")}>
          <div className="metric-card-top">
            <div className="metric-icon-badge bg-med">
              <InfoIcon size={20} />
            </div>
            <span className="metric-card-count">{medLowCount}</span>
          </div>
          <div className="metric-card-bottom">
            <h4 className="metric-card-title">Warnings / Deprecated</h4>
            <p className="metric-card-desc">Medium & Low severity configuration issues</p>
          </div>
        </div>

        <div className="metric-card metric-card-total" onClick={() => onNavigateTab("findings")}>
          <div className="metric-card-top">
            <div className="metric-icon-badge bg-total">
              <CheckCircleIcon size={20} />
            </div>
            <span className="metric-card-count">{totalFindings}</span>
          </div>
          <div className="metric-card-bottom">
            <h4 className="metric-card-title">Total Rules Evaluated</h4>
            <p className="metric-card-desc">
              {infoCount > 0 ? `${totalFindings - infoCount} violations, ${infoCount} informational` : "Against versioned 19-rule catalog"}
            </p>
          </div>
        </div>
      </div>

      {/* Row 3: Negotiated Security Parameters */}
      <div className="overview-section-header">
        <div>
          <h3 className="section-title">Negotiated Cryptographic Suite</h3>
          <p className="section-subtitle">Extracted parameters established during IKEv2 key exchange</p>
        </div>
        <button type="button" className="btn-link" onClick={() => onNavigateTab("handshake")}>
          <span>See exchange packets</span>
          <ArrowRightIcon size={14} />
        </button>
      </div>

      <div className="params-cards-grid">
        {/* Encryption Card */}
        <div
          className={`card param-card ${encStatus.state}`}
          onClick={() => handleParamClick(encStatus)}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => e.key === "Enter" && handleParamClick(encStatus)}
        >
          <div className="param-card-top">
            <div className="param-icon-box">
              <LockIcon size={22} />
            </div>
            <span className={`param-status-chip ${encStatus.state}`}>
              {encStatus.label}
            </span>
          </div>
          <div className="param-card-body">
            <span className="param-type-label">ENCRYPTION ALGORITHM</span>
            <code className="param-value-code">{secParams.encryption || "Not agreed"}</code>
          </div>
          <div className="param-card-foot">
            <span>Click to inspect finding & evidence</span>
            <ArrowRightIcon size={14} />
          </div>
        </div>

        {/* Integrity Card */}
        <div
          className={`card param-card ${intStatus.state}`}
          onClick={() => handleParamClick(intStatus)}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => e.key === "Enter" && handleParamClick(intStatus)}
        >
          <div className="param-card-top">
            <div className="param-icon-box">
              <ShieldIcon size={22} />
            </div>
            <span className={`param-status-chip ${intStatus.state}`}>
              {intStatus.label}
            </span>
          </div>
          <div className="param-card-body">
            <span className="param-type-label">INTEGRITY ALGORITHM</span>
            <code className="param-value-code">{secParams.integrity || "Not agreed"}</code>
          </div>
          <div className="param-card-foot">
            <span>Click to inspect finding & evidence</span>
            <ArrowRightIcon size={14} />
          </div>
        </div>

        {/* Key Exchange Card */}
        <div
          className={`card param-card ${dhStatus.state}`}
          onClick={() => handleParamClick(dhStatus)}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => e.key === "Enter" && handleParamClick(dhStatus)}
        >
          <div className="param-card-top">
            <div className="param-icon-box">
              <KeyIcon size={22} />
            </div>
            <span className={`param-status-chip ${dhStatus.state}`}>
              {dhStatus.label}
            </span>
          </div>
          <div className="param-card-body">
            <span className="param-type-label">KEY EXCHANGE GROUP (DH)</span>
            <code className="param-value-code">{secParams.dh_group || "Not agreed"}</code>
          </div>
          <div className="param-card-foot">
            <span>Click to inspect finding & evidence</span>
            <ArrowRightIcon size={14} />
          </div>
        </div>
      </div>

      {/* Collapsible Methodology & Audit Transparency */}
      <div className="overview-methodology-wrap">
        <details className="card methodology-accordion">
          <summary className="methodology-summary-trigger">
            <div className="methodology-trigger-content">
              <div className="methodology-icon-badge">
                <InfoIcon size={20} />
              </div>
              <div>
                <h4 className="methodology-trigger-title">How this verdict is reached</h4>
                <p className="methodology-trigger-desc">Transparent scoring arithmetic, rule catalogue, and per-parameter checks</p>
              </div>
            </div>
            <span className="accordion-chevron">▼</span>
          </summary>
          <div className="methodology-content-inner">
            <RiskBasis doc={doc} methodology={methodology} />
          </div>
        </details>
      </div>
    </div>
  );
}
