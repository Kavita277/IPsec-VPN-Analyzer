import React from "react";
import { XIcon, HelpCircleIcon, InfoIcon } from "./Icons.jsx";

export default function SessionHelp({ doc, sessionCount, id, onClose }) {
  const sas = doc?.security_associations || [];
  const spi = sas.find((s) => s.initiator_spi)?.initiator_spi;
  const rspi = sas.find((s) => s.responder_spi)?.responder_spi;
  const packets = [...new Set(sas.map((s) => s.packet).filter((p) => p != null))];

  return (
    <div className="modal-backdrop" onClick={onClose} role="dialog" aria-modal="true" aria-labelledby="session-help-title">
      <div className="modal-card session-help-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title-wrap">
            <div className="modal-icon-badge">
              <HelpCircleIcon size={20} />
            </div>
            <div>
              <h3 id="session-help-title" className="modal-title">What is an IPsec Session?</h3>
              <p className="modal-subtitle">Understanding VPN tunnels, SPI identifiers, and capture grouping</p>
            </div>
          </div>
          <button type="button" className="btn-icon" onClick={onClose} aria-label="Close session guide">
            <XIcon size={18} />
          </button>
        </div>

        <div className="modal-body">
          <div className="session-help-prose">
            <p>
              A <strong>session</strong> represents one IPsec VPN tunnel being negotiated between two peers: a single <strong>IKE Security Association (SA)</strong>.
              It begins when the initiator transmits an <code>IKE_SA_INIT</code> request and covers the cryptographic handshake that follows.
            </p>
            <p>
              Every session is tagged with an <strong>initiator SPI</strong> (Security Parameter Index), a unique 8-byte hex identifier.
              The analyzer groups all packets carrying this identifier and assigns a standardized session ID: <code>vpn_&lt;initiator SPI&gt;</code>.
            </p>
          </div>

          <div className="session-help-controls-info">
            <h4>Available Datasets</h4>
            <ul className="help-bullets">
              <li><strong>secure_01:</strong> Compliant StrongSwan tunnel with AES-256, SHA2-256, and MODP-2048.</li>
              <li><strong>weak_01:</strong> Vulnerable tunnel connecting with broken MODP-1024 and deprecated HMAC-SHA1.</li>
              <li><strong>misconfigured_01:</strong> Failed negotiation returning <code>NO_PROPOSAL_CHOSEN</code>.</li>
            </ul>
          </div>

          {doc && (
            <div className="session-active-summary">
              <h4>Active Session Metadata</h4>
              <dl className="help-kv-grid">
                <dt>Session ID</dt>
                <dd><code>{doc.session?.session_id ?? "none found"}</code></dd>
                <dt>Source File</dt>
                <dd>{doc.metadata?.capture_file ? <code>{doc.metadata.capture_file}</code> : "Analysis JSON"}</dd>
                <dt>Initiator SPI</dt>
                <dd>{spi ? <code>{spi}</code> : "Not recorded"}</dd>
                <dt>Responder SPI</dt>
                <dd>{rspi ? <code>{rspi}</code> : "None (Responder rejected)"}</dd>
                <dt>Observed Packets</dt>
                <dd>{packets.length ? packets.map((p) => `#${p}`).join(", ") : "None recorded"}</dd>
                <dt>Negotiation Status</dt>
                <dd className={doc.negotiation?.status === "failed" ? "text-fail" : "text-ok"}>
                  {doc.negotiation?.status ?? "unknown"}
                </dd>
                {sessionCount > 1 && (
                  <>
                    <dt>Sessions in Upload</dt>
                    <dd>{sessionCount} total sessions parsed</dd>
                  </>
                )}
              </dl>
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button type="button" className="btn btn-primary" onClick={onClose}>
            Got it
          </button>
        </div>
      </div>
    </div>
  );
}
