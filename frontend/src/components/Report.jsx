import React, { useEffect, useState } from "react";
import { api } from "../api.js";

function save(text, name, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export default function Report({ doc, explanation, comparison, onClearComparison, onError }) {
  const [html, setHtml] = useState("");
  const [busy, setBusy] = useState(false);
  const cmp = comparison?.diff || null;
  const sid = (doc.session.session_id || "report").replace(/[^A-Za-z0-9_-]/g, "");

  useEffect(() => {
    if (!explanation) return;
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
    } catch (e) { onError(e.message); }
  };

  return (
    <section className="report">
      <div className="report-bar">
        <button type="button" className="btn primary" onClick={() => download("html")} disabled={!explanation}>Download HTML report</button>
        <button type="button" className="btn" onClick={() => download("md")} disabled={!explanation}>Download Markdown</button>
        <button type="button" className="btn" onClick={() => html && window.open(URL.createObjectURL(new Blob([html], { type: "text/html" })))} disabled={!html}>
          Open to print or save as PDF
        </button>
      </div>
      {comparison && (
        <p className="note">
          Before and after comparison included: {comparison.label}.{" "}
          <button type="button" className="link" onClick={onClearComparison}>Remove it</button>
        </p>
      )}
      <p className="muted small">The report covers the session loaded on the Assessment tab and lists its evidence, rule versions and limits.</p>
      <iframe title="Report preview" className="preview" sandbox="" srcDoc={html} aria-busy={busy} />
    </section>
  );
}
