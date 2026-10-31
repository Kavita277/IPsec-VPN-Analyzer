import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, stripAssessment } from "./api.js";
import Overview from "./components/Overview.jsx";
import Ladder from "./components/Ladder.jsx";
import Findings from "./components/Findings.jsx";
import Detail from "./components/Detail.jsx";
import Compare from "./components/Compare.jsx";
import Report from "./components/Report.jsx";
import SessionHelp from "./components/SessionHelp.jsx";
import UploadModal from "./components/UploadModal.jsx";
import { ShieldIcon, UploadIcon, HelpCircleIcon, AlertTriangleIcon, LayersIcon } from "./components/Icons.jsx";

const TABS = [
  ["overview", "Overview"],
  ["handshake", "Handshake"],
  ["findings", "Findings"],
  ["compare", "Before & After"],
  ["report", "Report"],
];

export default function App() {
  const [health, setHealth] = useState(null);
  const [policies, setPolicies] = useState([]);
  const [samples, setSamples] = useState([]);
  const [policy, setPolicy] = useState("nist-baseline");
  const [source, setSource] = useState({ type: "sample", name: "weak_01" });
  const [uploads, setUploads] = useState([]); // analysis documents from the last upload
  const [results, setResults] = useState([]);
  const [idx, setIdx] = useState(0);
  const [explanation, setExplanation] = useState(null);
  const [selKey, setSelKey] = useState(null);
  const [comparison, setComparison] = useState(null);
  const [tab, setTab] = useState("overview");
  const [methodology, setMethodology] = useState(null);
  const [showSession, setShowSession] = useState(false);
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([api.health(), api.policies(), api.samples()])
      .then(([h, p, s]) => {
        setHealth(h);
        setPolicies(p);
        setSamples(s);
      })
      .catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    let live = true;
    api.methodology(policy)
      .then((m) => live && setMethodology(m))
      .catch((e) => live && setError(e.message));
    return () => {
      live = false;
    };
  }, [policy]);

  // Load or re-assess whenever the source or policy changes.
  useEffect(() => {
    let live = true;
    setLoading(true);
    const run = source.type === "sample"
      ? api.sample(source.name, policy).then((r) => r.results)
      : Promise.all(source.docs.map((d) => api.assess(d, policy).then((r) => r.results[0])));
    run
      .then((r) => {
        if (live) {
          setResults(r);
          setIdx(0);
          setError("");
        }
      })
      .catch((e) => live && setError(e.message))
      .finally(() => live && setLoading(false));
    return () => {
      live = false;
    };
  }, [source, policy]);

  const doc = results[idx] || null;

  useEffect(() => {
    if (!doc) return;
    let live = true;
    setExplanation(null);
    setSelKey(doc.findings[0]?.key ?? null);
    api.explain(doc)
      .then((e) => live && setExplanation(e))
      .catch((e) => live && setError(e.message));
    return () => {
      live = false;
    };
  }, [doc]);

  const finding = doc?.findings.find((f) => f.key === selKey) || null;
  const hot = useMemo(() => new Set(finding ? finding.evidence.items.map((i) => i.packet) : []), [finding]);

  const handleUploadFile = async (file) => {
    setLoading(true);
    try {
      const r = await api.upload(file, policy);
      const docs = r.results.map(stripAssessment);
      setUploads(docs);
      setSource({ type: "upload", docs, label: file.name });
      setComparison(null);
    } catch (e) {
      setError(e.message);
      throw e;
    } finally {
      setLoading(false);
    }
  };

  const options = useMemo(() => [
    ...samples.map((s) => ({
      id: `sample:${s.name}`,
      label: s.name,
      load: (pol) => api.sample(s.name, pol).then((r) => r.results[0]),
    })),
    ...uploads.map((d, i) => ({
      id: `upload:${i}`,
      label: `${d.metadata?.capture_file ?? "upload"} (${d.session.session_id ?? "no session"})`,
      load: (pol) => api.assess(d, pol).then((r) => r.results[0]),
    })),
  ], [samples, uploads]);

  const onCompare = useCallback((c) => setComparison(c), []);
  const sourceValue = source.type === "sample" ? `sample:${source.name}` : "upload";

  return (
    <div className="crextio-app-wrapper">
      {/* Top Application Header */}
      <header className="app-top-header">
        <div className="brand-group">
          <div className="brand-logo-badge">
            <ShieldIcon size={22} />
          </div>
          <div className="brand-text">
            <h1 className="brand-title">IPsec Analyzer</h1>
            <p className="brand-subtitle">VPN security insights</p>
          </div>
        </div>

        <div className="header-controls-group">
          {/* Session Selector */}
          <div className="header-field">
            <span className="field-label-text">
              <span>Session</span>
              <button
                type="button"
                className="help-circle-btn"
                onClick={() => setShowSession(true)}
                title="What is an IPsec session?"
                aria-label="What is an IPsec session?"
              >
                <HelpCircleIcon size={14} />
              </button>
            </span>
            <div className="select-wrapper">
              <select
                className="header-select"
                value={sourceValue}
                onChange={(e) => e.target.value.startsWith("sample:") && setSource({ type: "sample", name: e.target.value.slice(7) })}
              >
                {samples.map((s) => (
                  <option key={s.name} value={`sample:${s.name}`}>
                    {s.name} {s.negotiation_status === "failed" ? "(failed handshake)" : ""}
                  </option>
                ))}
                {source.type === "upload" && <option value="upload">{source.label}</option>}
              </select>
            </div>
          </div>

          {/* Policy Selector */}
          <div className="header-field">
            <span className="field-label-text">Policy</span>
            <div className="select-wrapper">
              <select
                className="header-select"
                value={policy}
                onChange={(e) => setPolicy(e.target.value)}
              >
                {policies.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </div>
          </div>

          {/* Upload Button */}
          <button
            type="button"
            className="btn btn-primary upload-trigger-btn"
            onClick={() => setIsUploadOpen(true)}
          >
            <UploadIcon size={16} />
            <span>Upload capture or JSON</span>
          </button>
        </div>
      </header>

      {/* Pill-Style Navigation Bar */}
      <nav className="nav-pill-bar" role="tablist" aria-label="Dashboard sections">
        <div className="nav-pill-container">
          {TABS.map(([id, label]) => {
            const isActive = tab === id;
            return (
              <button
                key={id}
                type="button"
                role="tab"
                id={`tab-${id}`}
                aria-selected={isActive}
                aria-controls={`panel-${id}`}
                className={`nav-pill-item ${isActive ? "active" : ""}`}
                onClick={() => setTab(id)}
              >
                {label}
                {id === "findings" && doc?.findings?.length > 0 && (
                  <span className="nav-pill-counter">{doc.findings.length}</span>
                )}
              </button>
            );
          })}
        </div>
      </nav>

      {/* Multi-Session Selector (if upload has multiple sessions) */}
      {results.length > 1 && (
        <div className="multi-session-bar card">
          <span className="multi-session-label">
            This capture contains <strong>{results.length}</strong> separate IPsec sessions. Showing:
          </span>
          <select
            className="header-select compact-select"
            value={idx}
            onChange={(e) => setIdx(Number(e.target.value))}
          >
            {results.map((r, i) => (
              <option key={i} value={i}>{r.session.session_id}</option>
            ))}
          </select>
        </div>
      )}

      {/* Error Banner */}
      {error && (
        <div className="alert-banner error" role="alert">
          <AlertTriangleIcon size={18} />
          <div className="alert-text-body">
            <span>{error}</span>
            <button type="button" className="btn-link" onClick={() => setError("")}>Dismiss</button>
          </div>
        </div>
      )}

      {/* Main Tab Panels */}
      <main id={`panel-${tab}`} role="tabpanel" aria-labelledby={`tab-${tab}`} aria-busy={loading} className="main-content-area">
        {loading && !doc ? (
          <div className="card loading-card">
            <div className="spinner" />
            <p>Analyzing IPsec capture...</p>
          </div>
        ) : (
          <>
            {/* 1. OVERVIEW TAB */}
            {tab === "overview" && (
              <Overview
                doc={doc}
                explanation={explanation}
                onNavigateTab={setTab}
                onSelectFinding={setSelKey}
                methodology={methodology}
              />
            )}

            {/* 2. HANDSHAKE TAB */}
            {tab === "handshake" && (
              <div className="tab-section-wrap">
                <div className="tab-section-header">
                  <div>
                    <h2 className="tab-title">IKEv2 Handshake Flow</h2>
                    <p className="tab-desc">Step-by-step exchange between Initiator and Responder with inspected packets</p>
                  </div>
                </div>
                <Ladder doc={doc} hot={hot} />
              </div>
            )}

            {/* 3. FINDINGS TAB */}
            {tab === "findings" && (
              <div className="tab-section-wrap">
                <div className="tab-section-header">
                  <div>
                    <h2 className="tab-title">Security Assessment Findings</h2>
                    <p className="tab-desc">Deterministic policy violations linked to packet-level evidence chains</p>
                  </div>
                </div>

                <div className="findings-detail-split-grid">
                  <div className="findings-col">
                    <Findings
                      findings={doc?.findings || []}
                      selected={selKey}
                      onSelect={setSelKey}
                      comparison={comparison}
                    />
                  </div>
                  <div className="detail-col">
                    <Detail
                      finding={finding}
                      text={finding && explanation?.findings?.[finding.key]}
                    />
                  </div>
                </div>
              </div>
            )}

            {/* 4. BEFORE & AFTER TAB */}
            {tab === "compare" && (
              <div className="tab-section-wrap">
                <Compare
                  options={options}
                  policy={policy}
                  comparison={comparison}
                  onResult={onCompare}
                  onError={setError}
                />
              </div>
            )}

            {/* 5. REPORT TAB */}
            {tab === "report" && (
              <div className="tab-section-wrap">
                <Report
                  doc={doc}
                  explanation={explanation}
                  comparison={comparison}
                  onClearComparison={() => setComparison(null)}
                  onError={setError}
                />
              </div>
            )}
          </>
        )}
      </main>

      {/* Floating Modals */}
      <UploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onUpload={handleUploadFile}
        policy={policy}
        health={health}
      />

      {showSession && (
        <SessionHelp
          doc={doc}
          sessionCount={results.length}
          id="session-help-modal"
          onClose={() => setShowSession(false)}
        />
      )}

      {/* Application Footer */}
      <footer className="app-footer">
        <div className="footer-content">
          <span>Ruleset v{doc?.assessment?.ruleset_version ?? "1.0.0"} • Deterministic Rule Engine</span>
          <span className="footer-dot">•</span>
          <span>Sponsored by NTRO (SIH26160)</span>
          <span className="footer-dot">•</span>
          <span>Zero AI Hallucinations in Verdicts</span>
        </div>
      </footer>
    </div>
  );
}
