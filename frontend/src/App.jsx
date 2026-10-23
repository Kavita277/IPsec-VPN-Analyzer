import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, stripAssessment } from "./api.js";
import Ladder from "./components/Ladder.jsx";
import Parameters from "./components/Parameters.jsx";
import Posture from "./components/Posture.jsx";
import Findings from "./components/Findings.jsx";
import Detail from "./components/Detail.jsx";
import Compare from "./components/Compare.jsx";
import Report from "./components/Report.jsx";
import RiskBasis from "./components/RiskBasis.jsx";
import SessionHelp from "./components/SessionHelp.jsx";

const TABS = [["assessment", "Assessment"], ["compare", "Before and after"], ["report", "Report"]];

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
  const [tab, setTab] = useState("assessment");
  const [methodology, setMethodology] = useState(null);
  const [showSession, setShowSession] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const fileInput = useRef(null);

  useEffect(() => {
    Promise.all([api.health(), api.policies(), api.samples()])
      .then(([h, p, s]) => { setHealth(h); setPolicies(p); setSamples(s); })
      .catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    let live = true;
    api.methodology(policy).then((m) => live && setMethodology(m)).catch((e) => live && setError(e.message));
    return () => { live = false; };
  }, [policy]);

  // Load or re-assess whenever the source or policy changes.
  useEffect(() => {
    let live = true;
    setLoading(true);
    const run = source.type === "sample"
      ? api.sample(source.name, policy).then((r) => r.results)
      : Promise.all(source.docs.map((d) => api.assess(d, policy).then((r) => r.results[0])));
    run
      .then((r) => { if (live) { setResults(r); setIdx(0); setError(""); } })
      .catch((e) => live && setError(e.message))
      .finally(() => live && setLoading(false));
    return () => { live = false; };
  }, [source, policy]);

  const doc = results[idx] || null;

  useEffect(() => {
    if (!doc) return;
    let live = true;
    setExplanation(null);
    setSelKey(doc.findings[0]?.key ?? null);
    api.explain(doc).then((e) => live && setExplanation(e)).catch((e) => live && setError(e.message));
    return () => { live = false; };
  }, [doc]);

  const finding = doc?.findings.find((f) => f.key === selKey) || null;
  const hot = useMemo(() => new Set(finding ? finding.evidence.items.map((i) => i.packet) : []), [finding]);

  const onFile = async (event) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    setLoading(true);
    try {
      const r = await api.upload(file, policy);
      const docs = r.results.map(stripAssessment);
      setUploads(docs);
      setSource({ type: "upload", docs, label: file.name });
      setComparison(null);
    } catch (e) { setError(e.message); setLoading(false); }
  };

  const options = useMemo(() => [
    ...samples.map((s) => ({ id: `sample:${s.name}`, label: s.name, load: (pol) => api.sample(s.name, pol).then((r) => r.results[0]) })),
    ...uploads.map((d, i) => ({ id: `upload:${i}`, label: `${d.metadata?.capture_file ?? "upload"} (${d.session.session_id ?? "no session"})`, load: (pol) => api.assess(d, pol).then((r) => r.results[0]) })),
  ], [samples, uploads]);

  const onCompare = useCallback((c) => setComparison(c), []);
  const sourceValue = source.type === "sample" ? `sample:${source.name}` : "upload";

  return (
    <div className="app">
      <header className="top">
        <div>
          <h1>IPsec session review</h1>
          <p className="muted">Every finding traces back to a packet.</p>
        </div>
        <div className="controls">
          <label className="field">
            <span>Session <button type="button" className="help" aria-expanded={showSession} aria-controls="session-help" onClick={() => setShowSession((v) => !v)} title="What is a session?">?<span className="sr-only"> What is a session?</span></button></span>
            <select value={sourceValue} onChange={(e) => e.target.value.startsWith("sample:") && setSource({ type: "sample", name: e.target.value.slice(7) })}>
              {samples.map((s) => <option key={s.name} value={`sample:${s.name}`}>{s.name}{s.negotiation_status === "failed" ? " (failed handshake)" : ""}</option>)}
              {source.type === "upload" && <option value="upload">{source.label}</option>}
            </select>
          </label>
          <label className="field">
            <span>Policy</span>
            <select value={policy} onChange={(e) => setPolicy(e.target.value)}>
              {policies.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
          </label>
          <input ref={fileInput} type="file" accept=".pcap,.pcapng,.cap,.json" hidden onChange={onFile} />
          <button type="button" className="btn" onClick={() => fileInput.current?.click()}>Upload capture or JSON</button>
        </div>
      </header>

      {health && !health.pcap_upload && (
        <p className="note">PCAP upload is off because tshark is not installed on the server. Analysis JSON files and the sample sessions still work.</p>
      )}
      {showSession && <SessionHelp id="session-help" doc={doc} sessionCount={results.length} />}
      {error && <p className="alert" role="alert">{error} <button type="button" className="link" onClick={() => setError("")}>Dismiss</button></p>}

      <nav className="tabs" role="tablist" aria-label="Views">
        {TABS.map(([id, label]) => (
          <button key={id} type="button" role="tab" id={`tab-${id}`} aria-selected={tab === id} aria-controls={`panel-${id}`} onClick={() => setTab(id)}>{label}</button>
        ))}
      </nav>

      {results.length > 1 && (
        <label className="field inline">
          <span>This upload has {results.length} sessions. Showing</span>
          <select value={idx} onChange={(e) => setIdx(Number(e.target.value))}>
            {results.map((r, i) => <option key={i} value={i}>{r.session.session_id}</option>)}
          </select>
        </label>
      )}

      <main id={`panel-${tab}`} role="tabpanel" aria-labelledby={`tab-${tab}`} aria-busy={loading}>
        {tab === "assessment" && (doc ? (
          <>
            <Posture doc={doc} explanation={explanation} />
            <div className="grid">
              <div className="col">
                <h2>Handshake</h2>
                <Ladder doc={doc} hot={hot} />
                <h2>Parameters</h2>
                <Parameters doc={doc} onPick={setSelKey} />
              </div>
              <div className="col">
                <h2>Findings</h2>
                <Findings findings={doc.findings} selected={selKey} onSelect={setSelKey} />
                <h2>Evidence chain</h2>
                <Detail finding={finding} text={finding && explanation?.findings?.[finding.key]} />
              </div>
            </div>
            <RiskBasis doc={doc} methodology={methodology} />
          </>
        ) : <p className="empty">{loading ? "Loading session…" : "Choose a sample session or upload a capture to begin."}</p>)}

        {tab === "compare" && (
          <Compare options={options} policy={policy} comparison={comparison} onResult={onCompare} onError={setError} />
        )}

        {tab === "report" && (doc ? (
          <Report doc={doc} explanation={explanation} comparison={comparison} onClearComparison={() => setComparison(null)} onError={setError} />
        ) : <p className="empty">Load a session first.</p>)}
      </main>

      <footer className="foot muted small">
        Ruleset {doc?.assessment.ruleset_version ?? "…"}. Severity, score and findings come from a deterministic rule engine; the AI only explains them.
      </footer>
    </div>
  );
}
