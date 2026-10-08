# Person 1 Handoff Documentation

## 1. What Person 1 Implemented

Person 1's module implements the telemetry and protocol extraction foundation of the **AI-Powered IPsec VPN Protocol Analyzer (SIH26160)**.

The responsibility of this module is strictly bounded:
```
PCAP → TShark → IPsec/IKEv2 Parsing → Session Grouping → Evidence Mapping → Normalized JSON
```

Person 1 **does not** implement:
- Security assessment rules
- Risk or severity scoring
- Posture generation
- AI analysis or recommendations
- Frontend or API layers

These analytical responsibilities belong to **Person 2**.

---

## 2. Input Format

- **Format**: Standard PCAP or PCAPNG packet capture file (`.pcap`, `.pcapng`).
- **Protocols Supported**: IKEv2 (dissected via Wireshark/TShark ISAKMP protocol dissector, UDP port 500 / port 4500).

---

## 3. Analyzer Command for Person 2

To analyze any capture file, run:
```bash
python analyze.py <path/to/capture.pcap>
```
Optional custom output directory:
```bash
python analyze.py <path/to/capture.pcap> --output <output_dir>
```

Example commands:
```bash
python analyze.py samples/secure/secure_01.pcap
python analyze.py samples/weak/weak_01.pcap
python analyze.py samples/misconfigured/misconfigured_01.pcap
```

The tool outputs the normalized JSON file(s) into the `analysis/` directory (e.g. `analysis/secure_01.json`).

---

## 4. Frozen Schema Location

The single source of truth for the data contract is:
- **`docs/schema/v1.json`**

Do **not** alter field names, nesting structure, or data types.

---

## 5. Output Format & Data Contract

Each analyzed session produces a JSON document matching `docs/schema/v1.json`:
```json
{
  "schema_version": "1.0",
  "session": {
    "session_id": "vpn_<initiator_spi>"
  },
  "protocol": {
    "ike_version": "IKEv2"
  },
  "negotiation": {
    "status": "successful | failed | null",
    "offered_proposals": [
      {
        "encryption": "...",
        "integrity": "...",
        "dh_group": "..."
      }
    ],
    "negotiated_proposal": {
      "encryption": "...",
      "integrity": "...",
      "dh_group": "..."
    }
  },
  "security_parameters": {
    "encryption": "...",
    "integrity": "...",
    "dh_group": "..."
  },
  "security_associations": [
    {
      "initiator_spi": "...",
      "responder_spi": "...",
      "packet": 1
    }
  ],
  "evidence": [
    {
      "packet": 1,
      "field": "isakmp.tf.id.encr",
      "value": "AES-256-CBC",
      "session_id": "vpn_..."
    }
  ],
  "metadata": {
    "source": "tshark",
    "capture_file": "..."
  }
}
```

---

## 6. Evidence Format

Every observation extracted from the wire contains a 4-tuple:
- `packet`: Integer frame number where the attribute was observed.
- `field`: Exact TShark/Wireshark field path where the value was dissected.
- `value`: Raw observed value on the wire.
- `session_id`: Deterministic session identifier (`vpn_<initiator_spi>`).

Person 2 should cite this evidence directly in rule violations or audit reports.

---

## 7. Real Test Scenarios

All capture files were generated using genuine Linux endpoints (**Debian 13** / kernel 6.12.107) running **StrongSwan 6.0.1** on an isolated internal network (`10.10.10.1` <-> `10.10.10.2`).

### Scenario 1 — Secure
- **Traffic**: Valid IKEv2 SA_INIT and IKE_AUTH negotiation.
- **Parameters**: `AES-256-CBC`, `HMAC-SHA2-256`, `MODP-2048`.
- **Status**: `"successful"`
- **PCAP Location**: `samples/secure/secure_01.pcap`
- **JSON Output**: `analysis/secure_01.json`

### Scenario 2 — Weak
- **Traffic**: Valid IKEv2 negotiation with legacy/weaker cryptographic suites.
- **Parameters**: `AES-128-CBC`, `HMAC-SHA1`, `MODP-1024`.
- **Status**: `"successful"`
- **PCAP Location**: `samples/weak/weak_01.pcap`
- **JSON Output**: `analysis/weak_01.json`

### Scenario 3 — Misconfigured
- **Traffic**: Initiator offers `AES-128-CBC / HMAC-SHA1 / MODP-1024`, Responder rejects proposal with notify error `14` (`NO_PROPOSAL_CHOSEN`).
- **Status**: `"failed"`
- **Negotiated proposal**: `null`
- **Security parameters**: `null`
- **PCAP Location**: `samples/misconfigured/misconfigured_01.pcap`
- **JSON Output**: `analysis/misconfigured_01.json`

---

## 8. What Person 2 Should Consume

Person 2 should ingest the JSON files produced in `analysis/*.json` and:
1. Read `security_parameters` and `negotiation.offered_proposals` to evaluate against compliance policies (e.g. NIST SP 800-77, CNSA, RFC 8247).
2. Flag weak algorithms (e.g., `MODP-1024` < 2048 bits, `HMAC-SHA1`, `AES-128` vs `AES-256`).
3. Check `negotiation.status` (`"failed"` triggers negotiation failure findings).
4. Attach items from `evidence[]` to explain why a specific finding was raised.

---

## 9. Intentionally Not Inferred Information

- **Missing Fields**: If an attribute is not present on the wire (e.g. no response observed, or transform omitted), the value is strictly `null`.
- **No Guesses**: Never assume 256-bit key length if only algorithm ID 12 without key attribute is sent.
- **ESP Payloads**: ESP encrypted payload contents are not decrypted. Only observable IKE handshake parameters are parsed.

---

## 10. Known Limitations & Scope

- **IKEv1**: Excluded from current MVP (IKEv1 support is planned for future work).
- **Fragmentation**: Large IKEv2 fragmented messages require reassembly in TShark before transform extraction.
