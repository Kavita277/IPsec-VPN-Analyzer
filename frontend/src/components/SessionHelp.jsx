import React from "react";

// Explains what the Session control means, using the session that is open right now.
export default function SessionHelp({ doc, sessionCount, id }) {
  const sas = doc?.security_associations || [];
  const spi = sas.find((s) => s.initiator_spi)?.initiator_spi;
  const rspi = sas.find((s) => s.responder_spi)?.responder_spi;
  const packets = [...new Set(sas.map((s) => s.packet).filter((p) => p != null))];

  return (
    <aside id={id} className="sessionhelp" aria-label="What a session is">
      <h2>What is a session?</h2>
      <p>
        A <strong>session</strong> is one VPN tunnel being set up between two peers: a single IKE security association (SA).
        It starts when one side sends an <code>IKE_SA_INIT</code> request and covers the handshake that follows, in which the peers
        agree which encryption, integrity and Diffie-Hellman group to use. This tool judges that agreement.
      </p>
      <p>
        Every session has an <strong>initiator SPI</strong>, an 8-byte number the first peer picks. Every packet of that tunnel carries it,
        so the analyzer groups packets by it and names the session <code>vpn_&lt;initiator SPI&gt;</code>. One capture file can hold
        several tunnels, and each becomes its own session with its own score.
      </p>
      <h3>What the controls do</h3>
      <ul>
        <li><strong>Session</strong> (top of the page) chooses which session you are looking at. The bundled choices are three example captures: <code>secure_01</code> (strong settings), <code>weak_01</code> (weak settings that still connect) and <code>misconfigured_01</code> (the peers never agreed). After an upload, your file appears there too.</li>
        <li>If an upload holds more than one session, a second selector appears above the results so you can switch between them. The Policy selector re-judges the same session against a different standard.</li>
      </ul>
      {doc && (
        <>
          <h3>The session open now</h3>
          <dl className="kv">
            <dt>Session ID</dt><dd><code>{doc.session.session_id ?? "none found"}</code></dd>
            <dt>Source file</dt><dd>{doc.metadata?.capture_file ? <code>{doc.metadata.capture_file}</code> : "analysis JSON (no capture)"}</dd>
            <dt>Initiator SPI</dt><dd>{spi ? <code>{spi}</code> : "not recorded"}</dd>
            <dt>Responder SPI</dt><dd>{rspi ? <code>{rspi}</code> : "none: the responder never answered with an SPI"}</dd>
            <dt>Handshake packets</dt><dd>{packets.length ? packets.join(", ") : "none recorded"}</dd>
            <dt>Outcome</dt><dd>{doc.negotiation?.status ?? "unknown"}</dd>
            {sessionCount > 1 && <><dt>In this upload</dt><dd>{sessionCount} sessions</dd></>}
          </dl>
        </>
      )}
    </aside>
  );
}
