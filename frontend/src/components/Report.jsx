import React, { useEffect, useState } from "react";
import { api } from "../api.js";
import { DownloadIcon, FileTextIcon, InfoIcon, XIcon, CheckCircleIcon } from "./Icons.jsx";

function save(text, name, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export default function Report({ doc, explanation, comparison, onClearComparison, onError }) {
  const [html, setHtml] = useState("");
  const [busy, setBusy] = useState(false);
  const cmp = comparison?.diff || null;
  const sid = (doc?.session?.session_id || "report").replace(/[^A-Za-z0-9_-]/g, "");

  useEffect(() => {
    if (!explanation || !doc) return;
    let live = true;
    setBusy(true);
    api.report(doc, explanation, cmp, "html")
      .then((t) => live && setHtml(t))
      .catch((e) => live && onError(e.message))
      .finally(() => live && setBusy(false));
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [doc, explanation, cmp]);

  const download = async (format) => {
    try {
      const text = await api.report(doc, explanation, cmp, format);
      save(text, `ipsec-assessment-${sid}.${format === "md" ? "md" : "html"}`, format === "md" ? "text/markdown" : "text/html");
    } catch (e) {
      onError(e.message);
    }
  };

  const handlePrint = () => {
    if (!html) return;
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    window.open(url, "_blank");
  };

  const p = doc?.posture || {};
  const findingsCount = doc?.findings?.length || 0;

  return (
    <div className="report-view-container">
      {/* Report Header Card */}
      <div className="card report-meta-card">
        <div className="report-meta-main">
          <div className="report-badge-icon">
            <FileTextIcon size={24} />
          </div>
          <div>
            <span className="card-kicker">Audit Report Preview</span>
            <h3 className="report-session-title">Session: {doc?.session?.session_id || "VPN Audit"}</h3>
            <div className="report-meta-tags">
              <span className="tag-item">Policy: <strong>{doc?.assessment?.policy?.name || "NIST Baseline"}</strong></span>
              <span className="tag-item">Score: <strong>{p.score !== null ? `${p.score}/100` : "N/A"}</strong></span>
              <span className="tag-item">Rating: <strong className={`sev-color-${p.highest_severity || "none"}`}>{p.rating}</strong></span>
              <span className="tag-item">Findings: <strong>{findingsCount}</strong></span>
            </div>
          </div>
        </div>

        {/* Action Export Buttons */}
        <div className="report-actions-group">
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => download("html")}
            disabled={!explanation || busy}
          >
            <DownloadIcon size={16} />
            <span>Download HTML</span>
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => download("md")}
            disabled={!explanation || busy}
          >
            <DownloadIcon size={16} />
            <span>Download Markdown</span>
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={handlePrint}
            disabled={!html || busy}
          >
            <span>Print or PDF</span>
          </button>
        </div>
      </div>

      {/* Comparison Included Notice */}
      {comparison && (
        <div className="card report-comparison-alert">
          <div className="alert-content">
            <CheckCircleIcon size={18} />
            <span>Before & After comparison included: <strong>{comparison.label}</strong></span>
          </div>
          <button type="button" className="btn-link" onClick={onClearComparison}>
            <XIcon size={14} />
            <span>Exclude from report</span>
          </button>
        </div>
      )}

      {/* Preview Frame */}
      <div className="card report-preview-card">
        <div className="preview-top-bar">
          <div className="preview-indicator-dots">
            <span className="dot dot-red" />
            <span className="dot dot-yellow" />
            <span className="dot dot-green" />
          </div>
          <span className="preview-url-label">Self-contained HTML Report • Evidence, Ruleset v{doc?.assessment?.ruleset_version || "1.0.0"}</span>
        </div>

        {busy ? (
          <div className="preview-loading-box">
            <div className="spinner" />
            <p>Rendering report preview...</p>
          </div>
        ) : (
          <iframe
            title="Report preview"
            className="preview-iframe"
            sandbox="allow-same-origin"
            srcDoc={html}
          />
        )}
      </div>
    </div>
  );
}
