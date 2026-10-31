# Presentation Guide & Complete Slide Deck Content
## AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

- **Project ID:** SIH26160
- **Project Title:** AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework
- **Sponsoring Organisation:** NTRO (National Technical Research Organisation)
- **Current Repository Commit:** `aec2176ac0c5d6e9841ed2b436b589497b138888`
- **Synchronisation Status:** 100% Up-to-date with GitHub `origin/main`

---

## Slide 1: Title Slide

### Slide Visuals / Header
- **Title:** AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework
- **Subtitle:** Automated Cryptographic Auditing, Packet-Level Evidence Chains, and Guarded AI Explanations
- **Problem Statement ID:** SIH26160
- **Sponsoring Agency:** National Technical Research Organisation (NTRO)

### Team Roles & Modular Ownership
- **Person 1 (Network & Protocol Analysis):** Traffic capture, TShark dissection, IKEv2 parsing, and normalized JSON extraction.
- **Person 2 (Security Assessment Engine):** Cryptographic policies, 19-rule evaluation engine, posture scoring, and before/after diffing.
- **Person 3 (Integration, UI & AI):** FastAPI REST backend, React dashboard, handshake ladder diagram, and guarded AI explainability.

> **Speaker Notes:**  
> "Good morning, respected evaluators and professors. Today we present our mini-project SIH26160, sponsored by NTRO: an automated, evidence-backed security analyzer for IPsec VPN connections. Our framework eliminates human error in cryptographic auditing by coupling deterministic rule evaluation with strict packet-level evidence and guarded AI explanations."

---

## Slide 2: Executive Summary & Project Motivation

### Bullet Points
- **Critical Infrastructure Backbone:** IPsec is the foundational tunneling protocol securing inter-data center, governmental, and defense communications across the globe.
- **The Cryptographic Drift Problem:** Real-world VPN gateways frequently harbor obsolete ciphers (e.g., 3DES, DES, MD5, 1024-bit DH groups) due to legacy backward-compatibility or human misconfigurations.
- **The Manual Audit Bottleneck:** Network security engineers spend hours inspecting raw Wireshark packet dumps to determine whether an active session violates organizational security baselines.
- **Our Solution:** An end-to-end automated platform that extracts IKEv2 handshake negotiations directly from packet captures (`.pcap`), measures them against NIST and CNSA policies, computes reproducible security posture scores, highlights exact packets on an interactive ladder, and produces audit-ready compliance reports.

---

## Slide 3: The Problem Statement & Industry Gaps

### Challenges in Current Security Auditing
1. **Opaque Handshakes:** Network engineers must manually expand Wireshark's nested IKEv2 transform structures (Encryption, PRF, Integrity, Diffie-Hellman) across multiple packets.
2. **Subjective Scoring:** Different auditors interpret security severity differently; there is no standardized, automated scoring arithmetic tied to concrete RFC standards.
3. **Black-Box AI Hallucinations:** Using raw generative AI directly on network traffic leads to hallucinated CVEs, invented algorithm weaknesses, and unreliable security verdicts.
4. **Negotiated vs. Offered Ambiguity:** Security tools often fail to distinguish between what ciphers were merely *offered* by an initiator versus what was actually *negotiated* and active.

---

## Slide 4: Proposed Solution & Core Innovation

### Key Design Pillars
- **Strict Separation of Verdict vs. Explanation:**
  - **Verdict (100% Deterministic):** Cryptographic rules, severity ratings, and posture scores are calculated entirely by versioned Python code. Zero AI involvement.
  - **Explanation (Guarded AI):** LLM integration is restricted to converting verified facts into clear, plain-language remediation steps for network administrators.
- **Immutable 4-Tuple Evidence Chains:** Every finding links directly back to: `(packet_number, field_path, observed_value, session_id)`.
- **Zero-Guessing Contract:** Fields not present in the capture are strictly stored as `null`. Missing parameters are reported as observability limits rather than false compliance.
- **Dual Policy Support:** Pre-configured with **NIST Baseline** (SP 800-77 Rev.1) and **NSA CNSA 1.0 Strict** compliance profiles.

---

## Slide 5: Complete System Architecture (Block Diagram)

```
+---------------------------------------------------------------------------------------------------------+
|                                  END-TO-END SYSTEM ARCHITECTURE PIPELINE                                |
+---------------------------------------------------------------------------------------------------------+

 [StrongSwan IPsec Gateways]
            │
            ▼ (Live UDP 500 / 4500 Traffic)
   [.pcap / .pcapng Traces]
            │
 ═══════════╪══════════════════════════════════════════════════════════════════════════════════════════════
  STAGE 1   │ PERSON 1: PROTOCOL EXTRACTION PIPELINE
 ═══════════╪══════════════════════════════════════════════════════════════════════════════════════════════
            ▼
   [TShark CLI Dissector] ─────────────> Raw Wireshark JSON Stream
            │
            ▼
   [IKEv2 Parser] ─────────────────────> Extracts SPIs, Exchanges, Transform Types 1-4, Notifies
            │
            ▼
   [Evidence Mapper] ──────────────────> Records 4-Tuple Provenance (Packet, Field, Value, Session)
            │
            ▼
   [JSON Normalizer] ──────────────────> Generates docs/schema/v1.json (analysis/*.json)
            │
 ═══════════╪══════════════════════════════════════════════════════════════════════════════════════════════
  STAGE 2   │ PERSON 2: DETERMINISTIC ASSESSMENT ENGINE
 ═══════════╪══════════════════════════════════════════════════════════════════════════════════════════════
            │   ┌────────────────────────────────────────┐
            ├──>│ Policy Store (nist-baseline, cnsa-strict) │
            │   └────────────────────────────────────────┘
            ▼
   [19-Rule Catalog] ──────────────────> Evaluates Algorithms, Protocol, Negotiation & Observability
            │
            ▼
   [Scoring & Posture Engine] ─────────> Deducts weights: max(0, 100 - sum(weights)); derives Rating
            │
            ▼
   [Baseline Comparator] ──────────────> Compares Before vs After Remediation (Resolved / Introduced)
            │
            ▼
   docs/schema/assessment_v1.json (assessments/*.assessed.json)
            │
 ═══════════╪══════════════════════════════════════════════════════════════════════════════════════════════
  STAGE 3   │ PERSON 3: BACKEND, AI EXPLANATION & DASHBOARD
 ═══════════╪══════════════════════════════════════════════════════════════════════════════════════════════
            ▼
   [FastAPI REST API] ─────────────────> Exposes /api/upload, /api/assess, /api/compare, /api/report
            │
            ├──────────────────────────────────────────┬──────────────────────────────────────────┐
            ▼                                          ▼                                          ▼
   [AI Facts & Guard Layer]                  [Report Generator]                         [React SPA Dashboard]
   - ai/facts.py (isolated facts)            - Standalone HTML (Print to PDF)           - Handshake Ladder
   - ai/explain.py (guardrail validation)    - GitHub Markdown                          - Risk Basis Methodology
   - Template / Claude Sonnet fallback                                                  - Packet Evidence Inspector
```

---

## Slide 6: Person 1 Module — Protocol Analysis & Data Normalization

### Responsibilities
- Automated environment discovery of `tshark` on Linux and Windows systems.
- Execution of dissection filter: `tshark -r <capture> -T json --no-duplicate-keys -n -Y isakmp`.
- Parsing `IKE_SA_INIT` packets to extract:
  - Version (IKEv1 vs IKEv2)
  - Security Parameter Indexes: Initiator SPI ($SPI_i$) and Responder SPI ($SPI_r$)
  - Exchange Type and Flags (Initiator bit, Response bit)
  - Offered Proposals (Initiator Proposal Substructures)
  - Negotiated Proposal (Responder Selected Transforms)
  - Negotiation Status (Detects Responder Notify Type 14: `NO_PROPOSAL_CHOSEN`)
- **CLI Command:** `python analyze.py samples/weak/weak_01.pcap`
- **Output:** Normalized JSON adhering to frozen schema `docs/schema/v1.json`.

---

## Slide 7: IKEv2 Protocol Handshake Deep Dive

```
Initiator (Client / Gateway A)                      Responder (Gateway B)
      │                                                   │
      │ ──── Packet 1: IKE_SA_INIT Request (UDP 500) ────>│
      │      - Initiator SPI: 0xc0a15c9a873db101          │
      │      - Security Association (SA) Payload:         │
      │        * Proposal 1: ENCR: AES-256-CBC,           │
      │                      INTEG: HMAC-SHA2-256,        │
      │                      DH: MODP-2048, PRF: SHA2-256 │
      │      - Key Exchange (KE) Payload (Public DH Key)  │
      │      - Nonce Payload (Ni)                         │
      │                                                   │
      │ <─── Packet 2: IKE_SA_INIT Response (UDP 500) ────│
      │      - Responder SPI: 0x8a92f03d12bc4e77          │
      │      - Selected Proposal: Exactly 1 Chosen Suite  │
      │        (or Notify: NO_PROPOSAL_CHOSEN on mismatch)│
      │      - Key Exchange (KE) Payload (Public DH Key)  │
      │      - Nonce Payload (Nr)                         │
      │                                                   │
================ Session Keys (SKEYSEED) Derived Locally ================
      │                                                   │
      │ ──── Packet 3: IKE_AUTH Request (UDP 4500) ──────>│ (Encrypted)
      │ <─── Packet 4: IKE_AUTH Response (UDP 4500) ─────│ (Encrypted)
      │                                                   │
```

---

## Slide 8: The Data Contracts & Evidence Mapping

### 1. Frozen Data Contract (`docs/schema/v1.json`)
Guarantees clean architectural decoupling between Person 1 and Person 2:
- `metadata`: capture file, timestamp, SHA-256 packet hash.
- `protocol`: `ike_version`, `transport_protocol`, `port`.
- `session`: `session_id`, `initiator_spi`, `responder_spi`.
- `negotiation`: `status` (`successful`, `failed`, `unknown`), `offered_proposals`, `negotiated_proposal`.
- `security_parameters`: `encryption`, `integrity`, `dh_group`, `key_length`.
- `evidence`: Array of verifiable 4-tuples.

### 2. Evidence 4-Tuple Structure
```json
{
  "packet": 2,
  "field": "security_parameters.dh_group",
  "value": "MODP-1024",
  "session_id": "vpn_c0a15c9a873db101"
}
```

---

## Slide 9: Person 2 Module — Security Assessment Engine

### Responsibilities
- Receives the normalized JSON from Person 1.
- Loads security baseline policy definitions (`assessment/policies/*.json`).
- Classifies every cryptographic parameter into 4 tiers:
  1. **Approved:** Cryptographically sound, compliant with standard.
  2. **Deprecated:** Legacy algorithm with known weaknesses (e.g., 3DES, HMAC-SHA1).
  3. **Forbidden:** Obsolete or broken cipher with practical attacks (e.g., DES, MD5, MODP $\le 1536$).
  4. **Unapproved:** Valid cipher, but not allowed by the chosen strict profile.
- Executes the **19 Deterministic Rules**.
- Computes numerical posture score ($0 - 100$) and qualitative posture rating.
- CLI Entrypoint: `python assess.py analysis/weak_01.json -p nist-baseline`

---

## Slide 10: Policy Frameworks: NIST Baseline vs. CNSA Strict

| Cryptographic Primitive | NIST Baseline (`nist-baseline.json`) | NSA CNSA Strict (`cnsa-strict.json`) |
| :--- | :--- | :--- |
| **IKE Versions** | IKEv2 only (IKEv1 forbidden) | IKEv2 only |
| **Encryption Algorithms** | Approved: AES-128-CBC, AES-256-CBC, AES-GCM<br>Deprecated: 3DES-CBC<br>Forbidden: DES, RC5, IDEA, NULL | Approved: AES-256-CBC, AES-256-GCM only<br>Forbidden: AES-128, 3DES, DES |
| **Integrity Algorithms** | Approved: HMAC-SHA2-256/384/512<br>Deprecated: HMAC-SHA1<br>Forbidden: MD5, DES-MAC | Approved: HMAC-SHA2-384, HMAC-SHA2-512 only<br>Forbidden: HMAC-SHA1, HMAC-SHA2-256, MD5 |
| **Diffie-Hellman Groups** | Approved: MODP $\ge 2048$ (Group 14+), ECP-256/384<br>Forbidden: MODP-768, MODP-1024, MODP-1536 | Approved: MODP $\ge 3072$, ECP-384, ECP-521<br>Forbidden: MODP-2048, ECP-256, MODP-1024 |

---

## Slide 11: The 19 Deterministic Rules (Ruleset v1.0.0)

```
┌────────────────────────────────────────────────────────────────────────┐
│                        19 VERSIONED ASSESSMENT RULES                   │
├───────────────────┬────────────────────────────────────────────────────┤
│ Category          │ Rules & IDs                                        │
├───────────────────┼────────────────────────────────────────────────────┤
│ Encryption        │ IPSEC-ALG-001: Forbidden cipher (High)             │
│ (Algorithms)      │ IPSEC-ALG-002: Deprecated cipher (Medium)          │
│                   │ IPSEC-ALG-003: Unapproved cipher (Medium)          │
│                   │ IPSEC-ALG-004: NULL encryption (Critical)          │
│                   │ IPSEC-ALG-005: Unobserved key length (Info)        │
├───────────────────┼────────────────────────────────────────────────────┤
│ Integrity         │ IPSEC-INT-001: Forbidden MAC (High)                │
│ (Algorithms)      │ IPSEC-INT-002: Deprecated MAC (Low)                │
│                   │ IPSEC-INT-003: Unapproved MAC (Medium)             │
│                   │ IPSEC-INT-004: Missing MAC on non-AEAD (Info)      │
├───────────────────┼────────────────────────────────────────────────────┤
│ Key Exchange      │ IPSEC-DH-001: Forbidden DH group (High)            │
│ (Diffie-Hellman)  │ IPSEC-DH-002: Unapproved DH group (Medium)         │
│                   │ IPSEC-DH-003: Missing DH group (Info)              │
├───────────────────┼────────────────────────────────────────────────────┤
│ Protocol &        │ IPSEC-PROTO-001: Disallowed IKE version (High)     │
│ Negotiation       │ IPSEC-NEG-001: Negotiation failed (Medium)         │
│                   │ IPSEC-NEG-002: Weak options offered (Low)          │
│                   │ IPSEC-NEG-003: Outcome unobservable (Info)         │
│                   │ IPSEC-NEG-004: Selected proposal not offered (Med) │
├───────────────────┼────────────────────────────────────────────────────┤
│ Observability     │ IPSEC-OBS-001: No IKE session in capture (Info)    │
│ Gaps              │ IPSEC-OBS-002: No algorithm parameters (Info)      │
└───────────────────┴────────────────────────────────────────────────────┘
```

---

## Slide 12: Posture Scoring Mathematics & Rating Matrix

### Mathematical Deduction Formula
$$\text{Score} = \max\left(0, 100 - \sum_{i=1}^{N} \text{Weight}(\text{Severity}_i)\right)$$

### Severity Weights & Deductions
- **Critical:** $-40$ points (Immediate breach risk, e.g., NULL encryption)
- **High:** $-25$ points (Practically breakable, e.g., 1024-bit DH, DES, MD5)
- **Medium:** $-10$ points (Deprecated/unapproved, e.g., 3DES, failed handshake)
- **Low:** $-3$ points (Suboptimal configuration, e.g., HMAC-SHA1)
- **Informational:** $0$ points (Audit note or unobserved field)

### Posture Rating Assignment
The overall rating is strictly derived from the **highest single severity present**:
- Any Critical $\rightarrow$ **Critical**
- Any High $\rightarrow$ **High risk**
- Any Medium $\rightarrow$ **Moderate risk**
- Any Low $\rightarrow$ **Low risk**
- Informational only / No findings $\rightarrow$ **Compliant**
- Unextractable / Empty session $\rightarrow$ **Not assessable** (Score: `null`)

---

## Slide 13: Offered vs. Negotiated Proposals & Severity Demotion

### The Problem
If Gateway A offers weak ciphers (e.g., MODP-1024), but Gateway B rejects the proposal (`NO_PROPOSAL_CHOSEN`), was any live user payload encrypted with a weak cipher?
**No. Zero packets were exposed.**

### Our Technical Solution: One-Level Severity Demotion
- When a handshake succeeds (`scope = "negotiated"`), rules judge the agreed suite at **full default severity**.
- When a handshake fails (`scope = "offered"`), rules judge the offered proposals with **severity demoted by exactly one tier**:
  - High $\rightarrow$ Medium (e.g., MODP-1024 offered becomes $-10$ pts instead of $-25$ pts)
  - Low $\rightarrow$ Informational (e.g., HMAC-SHA1 offered becomes $0$ pts instead of $-3$ pts)
- **Result:** Reflects poor configuration hygiene without falsely claiming that data in transit was compromised.

---

## Slide 14: Person 3 Module — Backend, Reporting & Architecture

### Backend Stack ([backend/app.py](file:///c:/Users/Kavita/Desktop/IPsec-VPN-Analyzer/backend/app.py))
- **FastAPI + Uvicorn:** Fully asynchronous, lightweight, stateless microframework.
- **Stateless Design:** No backend database required. Sessions are maintained in the client browser, allowing infinite scalability and easy Docker deployment.
- **Max Upload Protection:** 25 MB payload limit with strict sanitization of filenames.

### Core API Endpoints
- `GET /api/health`: Health status, TShark availability, ruleset version.
- `GET /api/methodology`: Audit transparency documentation explaining scoring rules.
- `POST /api/upload`: Multipart upload for `.pcap`, `.pcapng`, or analysis `.json`.
- `POST /api/assess`: Re-evaluates analysis JSON against any chosen policy.
- `POST /api/compare`: Diffs two assessed sessions to compute before/after posture change.
- `POST /api/explain`: Invokes guarded AI explanation service.
- `POST /api/report`: Exports self-contained HTML (printable directly to PDF) or Markdown.

---

## Slide 15: AI Explainability Layer & Anti-Hallucination Guard

```
               [Assessed JSON Document]
                          │
                          ▼
               [ai/facts.py: build_facts()]
                          │  (Strips raw packets; extracts verified findings only)
                          ▼
                  {Verified Facts JSON}
                          │
         ┌────────────────┴────────────────┐
         ▼                                 ▼
[TemplateProvider]                [AnthropicProvider]
(Deterministic Offline)           (Claude 3.5 Sonnet)
         │                                 │
         │                                 ▼ (Raw LLM Response)
         │                     [ai/explain.py: guard()]
         │                     - Checks for valid JSON object
         │                     - Validates finding keys
         │                     - Rejects unverified IPSEC-* IDs
         │                     - Discards unverified claims
         │                                 │
         │                     ┌───────────┴───────────┐
         │                     ▼ (Passed)              ▼ (Violated)
         │               [Keep LLM Text]       [Discard & Fallback to Template]
         │                     │                       │
         └─────────────────────┼───────────────────────┘
                               ▼
                   {Guarded Explanations}
             (Every finding labelled: template / AI)
```

---

## Slide 16: Interactive React Dashboard (UI Features)

### 1. Handshake Ladder Diagram
- Visualizes packet transmission flow between Initiator and Responder.
- Highlights direction, packet index, UDP ports, and IKEv2 message types.
- **Interactive Provenance:** Clicking any security finding immediately highlights the exact packet responsible in the ladder.

### 2. Risk Basis & Methodology Panel
- Explicitly informs the security auditor of what the tool does and does *not* judge.
- Discloses the mathematical deduction breakdown for total audit transparency.

### 3. Session Inspector (`?` Help Modal)
- Breaks down Session Identifiers: Initiator SPI, Responder SPI, and frame count.

---

## Slide 17: Before & After Remediation Comparison

### Automated Verification of Remediation
Auditors can upload a "Before" capture and an "After" capture to prove vulnerability remediation:

```
+-------------------------------------------------------------------------+
|                  BEFORE & AFTER REMEDIATION COMPARISON                  |
+-------------------------------------------------------------------------+
  Session Before: weak_01 (Score: 72/100, Rating: High risk)
  Session After:  secure_01 (Score: 100/100, Rating: Compliant)
  Verdict:        IMPROVED (+28 points)

  [Resolved Findings (2)]
  ✓ [High]   IPSEC-DH-001: Forbidden Diffie-Hellman group (MODP-1024 -> MODP-2048)
  ✓ [Low]    IPSEC-INT-002: Deprecated integrity algorithm (HMAC-SHA1 -> HMAC-SHA2-256)

  [Introduced Findings (0)]
  (None - No security regressions introduced)
```

---

## Slide 18: Empirical Test Results: Real StrongSwan Scenarios

All test captures were captured from real StrongSwan IPsec endpoints running on isolated Debian virtual machines:

| Test Scenario | Capture File | Negotiated Parameters | Negotiation Status | Score & Rating | Triggered Findings |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Secure Tunnel** | `samples/secure/secure_01.pcap` | AES-256-CBC, HMAC-SHA2-256, MODP-2048 | Successful | **100 / 100**<br>(Compliant) | None |
| **2. Weak Tunnel** | `samples/weak/weak_01.pcap` | AES-128-CBC, HMAC-SHA1, MODP-1024 | Successful | **72 / 100**<br>(High risk) | - IPSEC-DH-001 (High: $-25$)<br>- IPSEC-INT-002 (Low: $-3$) |
| **3. Misconfigured** | `samples/misconfigured/misconfigured_01.pcap` | Offered: AES-128, SHA1, MODP-1024<br>Responder: Rejected | Failed (`NO_PROPOSAL_CHOSEN`) | **80 / 100**<br>(Moderate risk) | - IPSEC-DH-001 (Med: $-10$)<br>- IPSEC-NEG-001 (Med: $-10$)<br>- IPSEC-INT-002 (Info: $-0$) |
| **4. Synthetic Weak** | `testfiles/weak_test.pcap` | 3DES-CBC, HMAC-MD5, MODP-1024 | Successful | **40 / 100**<br>(High risk) | - IPSEC-ALG-002 (Med: $-10$)<br>- IPSEC-INT-001 (High: $-25$)<br>- IPSEC-DH-001 (High: $-25$) |
| **5. Synthetic Secure**| `testfiles/secure_test.pcap` | AES-256-CBC, HMAC-SHA2-384, ECP-384 | Successful | **100 / 100**<br>(Compliant) | None |

---

## Slide 19: Technology Stack & Architectural Justifications

```
┌─────────────────┬───────────────────┬────────────────────────────────────────────────────────┐
│ Layer           │ Technology        │ Technical Justification                                │
├─────────────────┼───────────────────┼────────────────────────────────────────────────────────┤
│ Extraction      │ TShark / Wireshark│ Industry-standard deep packet dissector; avoids        │
│                 │ (v4.x)            │ implementing custom C network packet parsers.          │
├─────────────────┼───────────────────┼────────────────────────────────────────────────────────┤
│ Backend Logic   │ Python 3.10+      │ Rich standard library, robust JSON handling,           │
│                 │ (tested 3.13)     │ rapid cryptographic prototyping.                       │
├─────────────────┼───────────────────┼────────────────────────────────────────────────────────┤
│ REST Framework  │ FastAPI           │ Async ASGI performance, native OpenAPI documentation,   │
│                 │ + Pydantic v2     │ strict schema typing for requests.                     │
├─────────────────┼───────────────────┼────────────────────────────────────────────────────────┤
│ Web Server      │ Uvicorn           │ Production-grade, low-latency async ASGI server.       │
├─────────────────┼───────────────────┼────────────────────────────────────────────────────────┤
│ Frontend SPA    │ React 18 + Vite   │ Component modularity, reactive state management,       │
│                 │                   │ sub-second Hot Module Reload (HMR).                    │
├─────────────────┼───────────────────┼────────────────────────────────────────────────────────┤
│ Styling & Print │ Vanilla CSS       │ Zero runtime overhead; custom print media queries      │
│                 │                   │ enabling native "Print to PDF" without Chromium headless│
├─────────────────┼───────────────────┼────────────────────────────────────────────────────────┤
│ Test Harness    │ Pytest (v9.1+)    │ 150 automated test cases across analyzer, assessment,  │
│                 │                   │ AI guard, and REST endpoints.                          │
└─────────────────┴───────────────────┴────────────────────────────────────────────────────────┘
```

---

## Slide 20: Limitations, Ethical Boundaries & Future Work

### Current System Boundaries (Ethical Transparency)
- **Visible Handshake Only:** Only unencrypted IKEv2 negotiations are inspected. The tool does not attempt to decrypt ESP inner packets (RFC 4303).
- **No Private Key Ingestion:** Protects privacy by avoiding the storage or extraction of private cryptographic certificates or pre-shared keys.
- **Unobserved Inner Attributes:** Parameters negotiated inside encrypted `IKE_AUTH` payloads (e.g., EAP credentials, Child SA lifetimes) are marked `null`, not guessed.

### Future Roadmap
1. **IKEv1 Deprecation Scanner:** Add extended backward-compatibility parsers for legacy IKEv1 aggressive mode captures.
2. **Post-Quantum Cryptography (PQC) Policies:** Implement CNSA 2.0 rules checking for Post-Quantum algorithms (e.g., ML-KEM / Kyber, Dilithium).
3. **Automated Gateway Config Remediation:** Generate downloadable StrongSwan `/etc/ipsec.conf` or `swanctl.conf` correction snippets automatically.

---

## Slide 21: Conclusion & Key Takeaways

1. **Automated Audit Pipeline:** Replaced hours of manual Wireshark inspection with instant, single-click PCAP assessment.
2. **100% Deterministic Security Verdicts:** Cryptographic findings and scores are provably reproducible and standards-backed.
3. **Audit-Grade Traceability:** Every vulnerability is permanently linked to its exact packet index and byte-level field value.
4. **Trustworthy AI:** The AI explainability layer is strictly guarded against hallucination and cannot alter verdicts.
5. **Completely Verified:** Validated across real StrongSwan hardware captures and backed by 150 automated unit and integration tests.

---

## Slide 22+: Viva Voce Cheat-Sheet & Rapid-Fire Questions

### Q1: What is the exact difference between IKEv2 and ESP?
**Answer:** IKEv2 (Internet Key Exchange version 2, UDP 500/4500) is the control-plane protocol used to mutually authenticate peers, establish Security Associations (SAs), and negotiate cryptographic keys. ESP (Encapsulating Security Payload, IP protocol 50) is the data-plane protocol that uses the negotiated symmetric keys to encrypt and authenticate actual user data packets.

### Q2: Why is Diffie-Hellman Group 2 (MODP-1024) insecure?
**Answer:** 1024-bit discrete logarithm groups provide only ~80 bits of symmetric security. As demonstrated in the Logjam vulnerability, well-resourced adversaries can precompute discrete logarithm tables for common 1024-bit primes, allowing passive decryption of VPN session keys. Both NIST SP 800-77 and RFC 8247 explicitly forbid it.

### Q3: Why does your project use deterministic rules instead of an ML model for security scoring?
**Answer:** Security assessment requires 100% determinism, legal auditability, and zero false-confidence hallucinations. Machine learning models can give varying ratings for identical inputs and can hallucinate nonexistent vulnerabilities. Our deterministic rule engine guarantees reproducibility, while AI is strictly quarantined to plain-language explanation.

### Q4: How does your AI guard work?
**Answer:** The AI explanation module receives only verified facts from `ai/facts.py`. The output from the LLM is passed through `guard()`, which regex-validates that no unauthorized `IPSEC-*` IDs are introduced, verifies that finding keys exist, and checks for malformed text. If any violation is detected, that finding's explanation is discarded and replaced with deterministic template text.

### Q5: How does your framework handle failed handshakes?
**Answer:** In a failed handshake (e.g., responder sends `NO_PROPOSAL_CHOSEN`), no live user traffic was actually protected by the offered ciphers. Therefore, our engine applies a one-level severity demotion to offered proposals (e.g., High becomes Medium), preventing an unestablished tunnel from being rated as a catastrophic breach.
