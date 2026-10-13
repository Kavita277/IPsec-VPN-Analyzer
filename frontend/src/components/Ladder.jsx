import React from "react";
import { FIELD_SUFFIX } from "../severity.js";

const W = 400, LEFT = 70, RIGHT = 330, TOP = 58, ROW = 78;

function describe(doc, packet) {
  const ev = doc.evidence.filter((e) => e.packet === packet);
  const pick = (suffix) => ev.find((e) => String(e.field).endsWith(suffix))?.value;
  const notify = ev.find((e) => String(e.field).includes("notify"))?.value;
  const outbound = packet % 2 === 1; // IKE alternates request and reply, so direction is inferred
  if (notify) return { kind: "error reply", detail: String(notify) };
  const parts = Object.values(FIELD_SUFFIX).map(pick).filter(Boolean);
  if (parts.length) return { kind: outbound ? "offers proposal" : "selects proposal", detail: parts.join(" / ") };
  return { kind: "no parameters extracted", detail: "" };
}

export default function Ladder({ doc, hot }) {
  const fromSa = (doc.security_associations || []).map((s) => s.packet);
  const packets = [...new Set([...fromSa, ...doc.evidence.map((e) => e.packet)])].sort((a, b) => a - b);
  if (!packets.length) return <p className="muted">No IKE packets were found in this input.</p>;

  const height = TOP + packets.length * ROW;
  const summary = `Handshake with ${packets.length} packets between initiator and responder`;

  return (
    <figure className="ladder">
      <svg viewBox={`0 0 ${W} ${height}`} role="img" aria-label={summary}>
        <defs>
          <marker id="head" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0 0 L10 5 L0 10 z" className="head-fill" />
          </marker>
          <marker id="head-hot" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M0 0 L10 5 L0 10 z" className="head-fill hot" />
          </marker>
        </defs>
        {[["Initiator", LEFT], ["Responder", RIGHT]].map(([name, x]) => (
          <g key={name}>
            <text x={x} y="22" textAnchor="middle" className="ladder-head">{name}</text>
            <line x1={x} y1="34" x2={x} y2={height - 6} className="lifeline" />
          </g>
        ))}
        {packets.map((p, i) => {
          const y = TOP + i * ROW + 38;
          const isHot = hot.has(p);
          const out = p % 2 === 1;
          const info = describe(doc, p);
          return (
            <g key={p} className={isHot ? "hop hot" : "hop"} data-packet={p}>
              {isHot && <rect x="6" y={y - 40} width={W - 12} height={ROW - 4} rx="6" className="halo" />}
              <text x={W / 2} y={y - 22} textAnchor="middle" className="hop-kind">{`#${p}  ${info.kind}`}</text>
              {info.detail && <text x={W / 2} y={y - 8} textAnchor="middle" className="hop-detail">{info.detail}</text>}
              <line
                x1={out ? LEFT + 4 : RIGHT - 4} x2={out ? RIGHT - 4 : LEFT + 4} y1={y + 4} y2={y + 4}
                className="arrow" markerEnd={isHot ? "url(#head-hot)" : "url(#head)"}
              />
            </g>
          );
        })}
      </svg>
      <figcaption className="muted small">
        Direction is inferred from packet order. Only values the analyzer extracted are shown.
        {hot.size > 0 && " Highlighted packets are the evidence for the selected finding."}
      </figcaption>
    </figure>
  );
}
