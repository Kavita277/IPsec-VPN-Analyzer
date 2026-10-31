import React, { useState } from "react";
import { FIELD_SUFFIX, value } from "../severity.js";
import { LaptopIcon, ServerIcon, ArrowRightIcon, AlertTriangleIcon, CheckCircleIcon, InfoIcon } from "./Icons.jsx";

function getPacketDetails(doc, packet) {
  const ev = doc.evidence.filter((e) => e.packet === packet);
  const pick = (suffix) => ev.find((e) => String(e.field).endsWith(suffix))?.value;
  const notify = ev.find((e) => String(e.field).includes("notify"))?.value;
  const outbound = packet % 2 === 1;

  if (notify) {
    return {
      kind: "Error Reply (Negotiation Failed)",
      detail: String(notify),
      status: "Extracted",
      isError: true,
      transforms: [],
      items: ev,
    };
  }

  const transforms = [];
  const enc = pick(FIELD_SUFFIX.encryption);
  const integ = pick(FIELD_SUFFIX.integrity);
  const dh = pick(FIELD_SUFFIX.dh_group);

  if (enc) transforms.push({ label: "Encryption", val: enc });
  if (integ) transforms.push({ label: "Integrity", val: integ });
  if (dh) transforms.push({ label: "DH Group", val: dh });

  if (transforms.length) {
    return {
      kind: outbound ? "Offers Proposal (IKE_SA_INIT)" : "Selects Proposal (IKE_SA_INIT)",
      detail: transforms.map((t) => t.val).join(" • "),
      status: "Extracted",
      isError: false,
      transforms,
      items: ev,
    };
  }

  return {
    kind: outbound ? "IKE Exchange Request" : "IKE Exchange Response",
    detail: "No parameters extracted from this message.",
    status: "No parameters extracted",
    isError: false,
    transforms: [],
    items: ev,
  };
}

export default function Ladder({ doc, hot }) {
  const [selectedPacket, setSelectedPacket] = useState(null);

  const fromSa = (doc.security_associations || []).map((s) => s.packet);
  const packets = [...new Set([...fromSa, ...doc.evidence.map((e) => e.packet)])].sort((a, b) => a - b);

  if (!packets.length) {
    return (
      <div className="card empty-card">
        <InfoIcon size={24} />
        <p>No IKE packets were found in this input capture.</p>
      </div>
    );
  }

  const sas = doc.security_associations || [];
  const initSpi = sas.find((s) => s.initiator_spi)?.initiator_spi;
  const respSpi = sas.find((s) => s.responder_spi)?.responder_spi;

  const togglePacket = (p) => {
    setSelectedPacket((prev) => (prev === p ? null : p));
  };

  return (
    <div className="handshake-view">
      {/* Handshake Endpoints Bar */}
      <div className="handshake-endpoints-bar">
        <div className="endpoint-box initiator">
          <div className="endpoint-icon-wrap">
            <LaptopIcon size={22} />
          </div>
          <div className="endpoint-info">
            <span className="endpoint-role">INITIATOR</span>
            <span className="endpoint-label">Gateway A (Client)</span>
            <span className="endpoint-sub">SPI: <code>{initSpi ? initSpi.slice(0, 10) + "..." : "Auto-generated"}</code></span>
          </div>
        </div>

        <div className="handshake-exchange-label">
          <span className="exchange-badge">IKEv2 Protocol Handshake</span>
          <span className="exchange-sub">UDP Port 500 / 4500</span>
        </div>

        <div className="endpoint-box responder">
          <div className="endpoint-info text-right">
            <span className="endpoint-role">RESPONDER</span>
            <span className="endpoint-label">Gateway B (Server)</span>
            <span className="endpoint-sub">SPI: <code>{respSpi ? respSpi.slice(0, 10) + "..." : "Response SPI"}</code></span>
          </div>
          <div className="endpoint-icon-wrap">
            <ServerIcon size={22} />
          </div>
        </div>
      </div>

      {/* Message Sequence Timeline */}
      <div className="handshake-timeline">
        {packets.map((p) => {
          const isHot = hot && hot.has(p);
          const outbound = p % 2 === 1;
          const info = getPacketDetails(doc, p);
          const isExpanded = selectedPacket === p;

          return (
            <div
              key={p}
              className={`timeline-message-row ${outbound ? "dir-out" : "dir-in"} ${isHot ? "is-hot" : ""} ${isExpanded ? "is-expanded" : ""}`}
            >
              {/* Message Packet Card */}
              <div
                className={`card message-packet-card ${isHot ? "packet-hot" : ""} ${info.isError ? "packet-error" : ""}`}
                onClick={() => togglePacket(p)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => e.key === "Enter" && togglePacket(p)}
              >
                <div className="message-packet-header">
                  <div className="packet-number-pill">
                    <span>Packet #{p}</span>
                  </div>
                  <div className="message-direction-pill">
                    {outbound ? (
                      <>
                        <span>Initiator</span>
                        <ArrowRightIcon size={12} />
                        <span>Responder</span>
                      </>
                    ) : (
                      <>
                        <span>Responder</span>
                        <ArrowRightIcon size={12} />
                        <span>Initiator</span>
                      </>
                    )}
                  </div>
                  <span className={`extraction-badge ${info.isError ? "badge-err" : info.status === "Extracted" ? "badge-ok" : "badge-neutral"}`}>
                    {info.status}
                  </span>
                  {isHot && (
                    <span className="hot-evidence-pill">
                      ★ Active Evidence
                    </span>
                  )}
                </div>

                <div className="message-packet-title-row">
                  <h4 className="message-kind-title">{info.kind}</h4>
                  <span className="message-toggle-hint">{isExpanded ? "Hide Evidence" : "Inspect Packet"}</span>
                </div>

                {info.detail && (
                  <p className="message-detail-summary">{info.detail}</p>
                )}

                {/* Individual extracted transform chips */}
                {info.transforms.length > 0 && (
                  <div className="message-transforms-list">
                    {info.transforms.map((t) => (
                      <div key={t.label} className="transform-mini-chip">
                        <span className="t-label">{t.label}:</span>
                        <code className="t-val">{t.val}</code>
                      </div>
                    ))}
                  </div>
                )}

                {/* Expanded Packet Evidence Drawer */}
                {isExpanded && (
                  <div className="packet-evidence-drawer" onClick={(e) => e.stopPropagation()}>
                    <h5 className="drawer-title">Extracted TShark Fields for Packet #{p}</h5>
                    {info.items.length ? (
                      <table className="evidence-mini-table">
                        <thead>
                          <tr>
                            <th>Field Path</th>
                            <th>Extracted Value</th>
                          </tr>
                        </thead>
                        <tbody>
                          {info.items.map((it, idx) => (
                            <tr key={idx}>
                              <td><code>{it.field}</code></td>
                              <td><code>{value(it.value)}</code></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    ) : (
                      <p className="muted small">No specific field mappings recorded for this packet index.</p>
                    )}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Legend Footer */}
      <div className="handshake-legend-card card">
        <h5 className="legend-title">Exchange Flow Legend</h5>
        <div className="legend-items-wrap">
          <div className="legend-item">
            <span className="legend-dot initiator-dot" />
            <span>Initiator (Client / Outgoing Request)</span>
          </div>
          <div className="legend-item">
            <span className="legend-dot responder-dot" />
            <span>Responder (Gateway / Incoming Response)</span>
          </div>
          <div className="legend-item">
            <span className="legend-dot hot-dot" />
            <span>Highlighted Evidence for Selected Finding</span>
          </div>
          <div className="legend-item">
            <span className="legend-dot error-dot" />
            <span>Protocol Failure / NO_PROPOSAL_CHOSEN</span>
          </div>
        </div>
        <p className="legend-note muted small">
          Message direction is chronologically ordered from capture timestamps. Only parameters visibly exchanged in cleartext <code>IKE_SA_INIT</code> frames are parsed.
        </p>
      </div>
    </div>
  );
}
