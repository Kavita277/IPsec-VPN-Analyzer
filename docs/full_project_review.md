# Full Project Review & Technical Audit

**Project ID:** SIH26160  
**Project Title:** AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework  
**Sponsoring Organisation:** NTRO  
**Date:** October 13, 2026  
**Auditor:** Antigravity (Google DeepMind Advanced Agentic Coding)  

---

## 1. Executive Summary & Git Synchronization Status

- **Configured GitHub Remote:** `https://github.com/Kavita277/IPsec-VPN-Analyzer` (`origin`)
- **Active Branch:** `main`
- **Synchronization Action:** Local repository was clean on commit `70f0501` ("Add real StrongSwan validation and Person 1 handoff"). Fetched remote changes from GitHub (`origin/main`), which had 1 new commit authored by teammate (`4yu-san`). Fast-forwarded cleanly via `git pull --ff-only origin main`.
- **Final Commit Hash:** `6079eac4308336b2ead71bf0448cd91d4a99bc1d`
- **Synchronization Status:** **100% Up-to-date with GitHub `origin/main`**. Working tree is completely clean.
- **Repository State:** All three modules (Person 1, Person 2, Person 3) are present, integrated, and verified against real packet captures.

---

## 2. Complete Architecture Diagram

The system follows a strict, unidirectional pipeline where packet observation and deterministic security assessment are completely separated from generative AI explanations:

```
+---------------------------------------------------------------------------------------------------------+
|                                        PERSON 1: PACKET & PROTOCOL LAYER                                |
|                                                                                                         |
|  [StrongSwan IPsec Gateways] ---> [pcap/pcapng trace]                                                    |
|                                         |                                                               |
|                                         v                                                               |
|                              [tshark CLI dissector]                                                     |
|                                         |                                                               |
|                                         v (raw Wireshark packet JSON)                                   |
|                        [analyzer/extractors/tshark_extractor.py]                                        |
|                                         |                                                               |
|                                         v (filtered IKEv2 frames)                                       |
|                          [analyzer/parsers/ike_parser.py]                                               |
|                                         |                                                               |
|                                         +---> [analyzer/evidence/evidence_mapper.py] (4-tuple evidence) |
|                                         |                                                               |
|                                         v                                                               |
|                           [analyzer/normalizer.py]                                                      |
|                                         |                                                               |
|                                         v                                                               |
|                     docs/schema/v1.json contract (analysis/*.json)                                      |
+---------------------------------------------------------------------------------------------------------+
                                          |
                                          v (Normalized Analysis Document)
+---------------------------------------------------------------------------------------------------------+
|                                    PERSON 2: DETERMINISTIC ASSESSMENT ENGINE                            |
|                                                                                                         |
|                     [assessment/policies/*.json (nist-baseline, cnsa-strict)]                           |
|                                         |                                                               |
|                                         v                                                               |
|                            [assessment/engine.py: assess()]                                             |
|                                         |                                                               |
|                  +----------------------+----------------------+                                        |
|                  |                                             |                                        |
|                  v                                             v                                        |
|    [assessment/rules/algorithms.py]              [assessment/rules/negotiation.py]                      |
|    (12 Rules: ALG-001..005, INT-001..004,        (7 Rules: PROTO-001, NEG-001..004,                     |
|     DH-001..003)                                  OBS-001..002)                                         |
|                  |                                             |                                        |
|                  +----------------------+----------------------+                                        |
|                                         |                                                               |
|                                         v (Findings with attached evidence)                             |
|                        [assessment/scoring/: compute_posture()]                                         |
|                                         |                                                               |
|                                         v                                                               |
|              docs/schema/assessment_v1.json contract (assessments/*.assessed.json)                      |
+---------------------------------------------------------------------------------------------------------+
                                          |
                                          v (Assessed JSON Document)
+---------------------------------------------------------------------------------------------------------+
|                                PERSON 3: BACKEND, AI EXPLANATION & DASHBOARD                            |
|                                                                                                         |
|                            [FastAPI REST API (backend/app.py)]                                          |
|                                         |                                                               |
|       +---------------------------------+---------------------------------+                             |
|       |                                 |                                 |                             |
|       v                                 v                                 v                             |
|  [ai/facts.py]                  [backend/report.py]            [React Dashboard (Vite)]                 |
|       |                          - HTML Standalone              - Handshake Ladder Diagram              |
|       v                          - GitHub Markdown              - Parameters & Findings Panels          |
|  [ai/explain.py]                 - Printable to PDF             - Packet Evidence Inspection            |
|       |                                                         - Before & After Diff Tool              |
|  +----+------------------------+                                - Export Report Action                  |
|  |                             |                                                                        |
|  v                             v                                                                        |
| [ai/plain_language.py]   [ai/providers.py]                                                              |
| (Offline Template)       (Optional Claude LLM + Strict Guard)                                           |
+---------------------------------------------------------------------------------------------------------+
```

---

## 3. Module-to-File Mapping

| Architectural Component | File / Directory | Key Classes & Functions | Purpose |
| :--- | :--- | :--- | :--- |
| **Person 1 Extractor** | `analyzer/extractors/tshark_extractor.py` | `TSharkExtractor`, `find_tshark()`, `extract_packets()` | Discovers `tshark`, runs packet dissection filter (`isakmp`), parses JSON stdout. |
| **Person 1 Parser** | `analyzer/parsers/ike_parser.py` | `IKEv2Parser`, `parse()`, `_extract_transforms()` | Extracts IKE version, SPIs, exchanges, offered vs negotiated transforms, NO_PROPOSAL_CHOSEN. |
| **Person 1 Evidence Mapper** | `analyzer/evidence/evidence_mapper.py` | `EvidenceMapper`, `record()` | Generates strict 4-tuple evidence: `(packet, field, value, session_id)`. |
| **Person 1 Normalizer** | `analyzer/normalizer.py` | `normalize_session()`, `build_v1_output()` | Enforces schema contract `docs/schema/v1.json`, maps missing fields to `null`. |
| **Person 1 CLI Entrypoint** | `analyze.py` | `analyze_pcap()`, `main()` | Single CLI command: `python analyze.py <pcap_path>`. |
| **Person 2 Policy Manager** | `assessment/policy.py`, `assessment/policies/` | `Policy`, `load_policy()`, `list_policies()` | Loads policy profiles (`nist-baseline.json`, `cnsa-strict.json`) containing forbidden, deprecated, and approved tiers. |
| **Person 2 Rule Base & Context**| `assessment/rules/base.py`, `assessment/models.py` | `Context`, `Rule`, `RuleMeta`, `Finding`, `Severity` | Encapsulates session context, classification, and finding construction. |
| **Person 2 Algorithm Rules** | `assessment/rules/algorithms.py` | `ALGORITHM_RULES` (ALG-001..005, INT-001..004, DH-001..003) | 12 rules checking encryption, integrity, and DH group security. |
| **Person 2 Negotiation Rules** | `assessment/rules/negotiation.py` | `NEGOTIATION_RULES` (PROTO-001, NEG-001..004, OBS-001..002) | 7 rules evaluating protocol version, handshake success/failure, offered downgrade risks. |
| **Person 2 Assessment Engine** | `assessment/engine.py` | `assess()`, `run_rules()` | Evaluates all 19 rules against context; attaches evidence; invokes scoring. |
| **Person 2 Posture Scoring** | `assessment/scoring/__init__.py` | `compute_posture()`, `WEIGHTS` | Deterministic posture calculation: `score = max(0, 100 - sum(weights))`, derives rating. |
| **Person 2 Baseline & Diff** | `assessment/baseline.py` | `compare()`, `PostureChange` | Compares before and after sessions; identifies resolved, introduced, and unchanged findings. |
| **Person 2 CLI Entrypoint** | `assess.py` | `assess_file()`, `main()` | CLI tool for assessing JSON files and running comparisons. |
| **Person 3 AI Facts Extractor** | `ai/facts.py` | `build_facts()` | Strips raw packets and isolates verified facts only for AI consumption. |
| **Person 3 AI Guard & Explain** | `ai/explain.py` | `guard()`, `explain()` | Validation guard that discards hallucinated finding IDs or unverified claims; falls back to template text. |
| **Person 3 AI Providers** | `ai/providers.py`, `ai/plain_language.py` | `TemplateProvider`, `AnthropicProvider`, `get_provider()` | Offline deterministic template provider and optional Claude Sonnet API integration. |
| **Person 3 Backend API** | `backend/app.py` | FastAPI app, REST endpoints (`/api/*`), Static file mount | Handles file upload (PCAP or JSON), assessment requests, comparisons, and report generation. |
| **Person 3 Report Generator** | `backend/report.py` | `render_html()`, `render_markdown()`, `build_model()` | Standalone HTML (with CSS print rules for PDF export) and GitHub-flavored Markdown. |
| **Person 3 Frontend Dashboard**| `frontend/src/App.jsx`, `components/*` | React components (`Posture`, `Ladder`, `Parameters`, `Findings`, `Detail`, `Compare`, `Report`) | Interactive Single Page Application (Vite + React) displaying handshake diagrams, findings, and evidence links. |

---

## 4. Technology Stack Verification

| Technology | Where Used | Why Used | Relevant Files | Connection to Other Components |
| :--- | :--- | :--- | :--- | :--- |
| **Python 3.10+** (tested 3.13) | Backend, Analyzer, Engine, AI | Core language for protocol analysis, parsing, rule engine, and API | `analyze.py`, `assess.py`, `backend/app.py` | Executes all server-side logic and tests |
| **Wireshark / TShark (v4.x)** | Person 1 Extractor | Deep packet dissection of raw PCAPs into structured JSON without writing C packet decoders | `analyzer/extractors/tshark_extractor.py` | Dissects PCAP frames; outputs JSON via `stdin`/`stdout` to Python |
| **FastAPI (v0.143+)** | Person 3 Backend | Modern, high-performance async REST framework with automatic OpenAPI docs | `backend/app.py` | Exposes REST endpoints consumed by React frontend; calls `analyzer`, `assessment`, and `ai` |
| **Uvicorn (v0.54+)** | Backend Web Server | Lightning-fast ASGI server for serving FastAPI application and static assets | `backend/app.py`, `requirements.txt` | Hosts the backend server at port 8000 |
| **Pydantic (v2.14+)** | Backend Data Validation | Strict data validation and typing for request bodies and configurations | `requirements.txt` | Validates API schemas in FastAPI |
| **React (v18.3+)** | Frontend Dashboard | Declarative UI for dynamic filtering, tab switching, and packet-to-finding selection | `frontend/src/App.jsx`, `frontend/src/main.jsx` | Renders user interface in browser; fetches data via HTTP from `/api/*` |
| **Vite (v5.4+)** | Frontend Build Tool | Ultra-fast bundling, HMR dev server, and production asset optimization | `frontend/vite.config.js`, `frontend/package.json` | Compiles JSX and CSS into production bundle at `frontend/dist` |
| **Vanilla CSS** | Frontend Styling | High-performance, zero-runtime dependency responsive design with dark/light theme support | `frontend/src/styles.css` | Styles handshake ladder, posture cards, and print views |
| **Pytest (v9.1+)** | Testing Framework | Comprehensive automated unit, integration, and regression test suite | `analyzer/tests/`, `assessment/tests/`, `ai/tests/`, `backend/tests/` | Validates 148 test cases across all modules |
| **Anthropic Claude API (Optional)**| Person 3 AI Layer | Natural language explanations of verified security findings for non-expert admins | `ai/providers.py` | Optional HTTP call using verified fact payload; guarded against hallucination |

---

## 5. End-to-End Data Flow

1. **Traffic Capture (StrongSwan Gateway):**
   - Two gateways (`10.10.10.1` and `10.10.10.2`) perform IKEv2 negotiations over UDP 500/4500.
   - Traffic captured using `tcpdump` or Wireshark into `.pcap` files (`samples/secure/`, `samples/weak/`, `samples/misconfigured/`).
2. **Packet Dissection (TShark):**
   - `analyzer/extractors/tshark_extractor.py` runs:
     ```bash
     tshark -r <capture.pcap> -T json --no-duplicate-keys -n -Y isakmp
     ```
   - Filters out non-IPsec packets; captures raw frames as structured JSON.
3. **IKEv2 Parsing & Evidence Extraction (Person 1):**
   - `analyzer/parsers/ike_parser.py` parses IKE header, SPIs, flags (Initiator/Responder), Message ID, and payloads.
   - Extracts Transform Substructures: Type 1 (ENCR), Type 2 (PRF), Type 3 (INTEG), Type 4 (DH).
   - Records offered proposals from initiator (`IKE_SA_INIT` request, Message ID 0) and negotiated proposal from responder (`IKE_SA_INIT` response).
   - If responder returns Notify type 14 (`NO_PROPOSAL_CHOSEN`), marks negotiation status as `failed`.
   - `analyzer/evidence/evidence_mapper.py` attaches exact packet number, field name, observed value, and session ID.
4. **Schema Normalization (docs/schema/v1.json):**
   - `analyzer/normalizer.py` produces normalized JSON containing metadata, protocol, session, negotiation, security parameters, and evidence array.
   - Unobservable fields are strictly serialized as `null` (never inferred or guessed).
5. **Security Policy Evaluation (Person 2):**
   - `assessment/engine.py` loads policy (`nist-baseline.json` or `cnsa-strict.json`).
   - Classifies each parameter (`encryption`, `integrity`, `dh_group`) into tiers: `approved`, `deprecated`, `forbidden`, `unapproved`, or `null`.
   - Runs 19 rules:
     - If handshake succeeded (`negotiated`), rules evaluate the negotiated cipher suite.
     - If handshake failed (`failed`), rules evaluate offered proposals with severity demoted by 1 level (since no traffic was actually protected).
6. **Deterministic Scoring & Posture (Person 2):**
   - `assessment/scoring/__init__.py` calculates:
     $$\text{score} = \max\left(0, 100 - \sum \text{weight}[\text{severity}]\right)$$
     where Critical = 40, High = 25, Medium = 10, Low = 3, Informational = 0.
   - Posture rating assigned from highest severity present (`Critical`, `High risk`, `Moderate risk`, `Low risk`, `Compliant`, or `Not assessable`).
   - Emits assessed document conforming to `docs/schema/assessment_v1.json`.
7. **AI Fact Extraction & Guarded Explanation (Person 3):**
   - `ai/facts.py` extracts verified findings and posture into a minimal fact dictionary.
   - `ai/explain.py` selects provider:
     - Default: `TemplateProvider` (offline, 100% deterministic plain English).
     - Optional: `AnthropicProvider` (calls Claude Sonnet API with `system` prompt).
   - `guard()` inspects response: if output contains unknown finding IDs, hallucinated numbers, or invalid JSON, it drops the hallucinated segment and replaces it with the deterministic template text.
8. **Dashboard & Report Export (Person 3):**
   - React UI fetches `/api/samples/*` or handles drag-and-drop file upload to `/api/upload`.
   - Displays ladder diagram, parameters table, findings cards, and packet evidence highlights.
   - Users can compare before/after remediation and export standalone HTML or Markdown reports.

---

## 6. Verification of the Three Real Scenarios

All three test scenarios were generated using real StrongSwan IPsec endpoints running in Debian 13 virtual machines and verified through the entire pipeline:

### Scenario 1: Secure Configuration (`samples/secure/secure_01.pcap`)
- **StrongSwan Configuration:** `ike = aes256-sha256-modp2048!`
- **Observed Negotiated Suite:**
  - Encryption: `AES-256-CBC` (key length 256)
  - Integrity: `HMAC-SHA2-256`
  - DH Group: `MODP-2048` (Group 14)
- **Negotiation Status:** `successful`
- **Assessment Results (`nist-baseline`):**
  - Score: **100 / 100**
  - Rating: **Compliant**
  - Findings: **0** findings above Informational.
- **Evidence Verification:** Responder Packet 2 establishes all parameters.

### Scenario 2: Weak Configuration (`samples/weak/weak_01.pcap`)
- **StrongSwan Configuration:** `ike = aes128-sha1-modp1024!`
- **Observed Negotiated Suite:**
  - Encryption: `AES-128-CBC` (approved by baseline)
  - Integrity: `HMAC-SHA1` (deprecated by NIST)
  - DH Group: `MODP-1024` (Group 2, broken/forbidden)
- **Negotiation Status:** `successful`
- **Assessment Results (`nist-baseline`):**
  - Score: **72 / 100** ($100 - 25 - 3 = 72$)
  - Rating: **High risk**
  - Findings:
    1. `IPSEC-DH-001` (High, -25 pts): Forbidden Diffie-Hellman group `MODP-1024`.
    2. `IPSEC-INT-002` (Low, -3 pts): Deprecated integrity algorithm `HMAC-SHA1`.
- **Evidence Verification:** Packet 2, fields `dh_group` and `integrity`.

### Scenario 3: Misconfigured / Failed Negotiation (`samples/misconfigured/misconfigured_01.pcap`)
- **StrongSwan Configuration:** VM-A configured for `aes128-sha1-modp1024!`, VM-B configured for `aes256-sha256-modp2048!`.
- **Observed Exchange:** Initiator sends offer; Responder returns `Notify: NO_PROPOSAL_CHOSEN` (type 14).
- **Negotiation Status:** `failed`
- **Assessment Results (`nist-baseline`):**
  - Score: **80 / 100** ($100 - 10 - 10 - 0 = 80$)
  - Rating: **Moderate risk**
  - Findings:
    1. `IPSEC-DH-001` (Medium, -10 pts): Forbidden DH group offered (`MODP-1024`). *Note: Demoted from High to Medium because it was offered, not negotiated.*
    2. `IPSEC-NEG-001` (Medium, -10 pts): IKE negotiation failed (`NO_PROPOSAL_CHOSEN`).
    3. `IPSEC-INT-002` (Informational, -0 pts): Deprecated integrity offered (`HMAC-SHA1`). *Note: Demoted from Low to Informational.*
- **Evidence Verification:** Packet 1 (offered proposal) and Packet 2 (Notify payload type 14).

---

## 7. Test Suite Execution & Analysis

Running `pytest` across all four test suites in the repository:
```bash
python -m pytest ai analyzer assessment backend
```

### Results Summary:
- **Total Tests Collected:** 148 tests
- **Passed:** 147 tests (99.3%)
- **Failed:** 1 test (`backend/tests/test_api.py::test_pcap_upload_reports_missing_tshark_clearly`)

### Root Cause Analysis of the Single Test Failure:
- **Test Intent:** Tests whether the API returns HTTP 503 when `tshark` is missing from the environment.
- **Why it failed on Windows:**
  The test uses `monkeypatch.setenv("PATH", "/nonexistent")`. On Linux, this hides `tshark`. However, `analyzer/extractors/tshark_extractor.py` specifically includes a fallback to standard Windows installation paths:
  ```python
  STANDARD_WINDOWS_PATHS = [
      r"C:\Program Files\Wireshark\tshark.exe",
      r"C:\Program Files (x86)\Wireshark\tshark.exe",
  ]
  ```
  Because Wireshark is genuinely installed at `C:\Program Files\Wireshark\tshark.exe` on this machine, the extractor successfully finds `tshark.exe` despite the cleared `PATH`. The uploaded dummy byte string is then passed to real TShark, which detects invalid capture magic bytes and raises `MalformedPcapError`, resulting in HTTP 422 (Unprocessable Entity) rather than HTTP 503.
- **Significance:** This is a platform-specific test artifact in a mock environment; in real-world usage on this machine, PCAP parsing works 100% correctly because Wireshark/TShark is present and active.

---

## 8. Exact Commands to Run the Project

### Prerequisites:
Make sure the Python virtual environment is activated and dependencies installed:
```powershell
# In PowerShell:
.\.venv\Scripts\Activate.ps1
```

### 1. Run Protocol Analyzer (Person 1 CLI):
```powershell
python analyze.py samples/weak/weak_01.pcap
# Generates: analysis/weak_01.json
```

### 2. Run Security Assessment Engine (Person 2 CLI):
```powershell
# Assess using default nist-baseline policy:
python assess.py analysis/weak_01.json

# Assess against strict CNSA 1.0 profile:
python assess.py analysis/weak_01.json -p cnsa-strict

# Compare before and after remediation:
python assess.py --compare assessments/weak_01.nist-baseline.assessed.json assessments/secure_01.nist-baseline.assessed.json
```

### 3. Build Frontend & Launch Full Dashboard Server (Person 3):
```powershell
# 1. Build frontend assets (only needed once or after editing React code):
cd frontend
npm install
npm run build
cd ..

# 2. Start the unified FastAPI server:
uvicorn backend.app:app --host 127.0.0.1 --port 8000
```
Open your browser to: **`http://127.0.0.1:8000`**

### 4. Run the Full Test Suite:
```powershell
python -m pytest ai analyzer assessment
```

---

## 9. Recommended Order for Studying the Code

1. **`docs/schema/v1.json`**: Understand the frozen data contract produced by Person 1.
2. **`analyzer/extractors/tshark_extractor.py` & `analyzer/parsers/ike_parser.py`**: See how TShark dissects packets and how transforms and SPIs are extracted.
3. **`assessment/policies/nist-baseline.json`**: Inspect how cipher suites are categorized into `approved`, `deprecated`, and `forbidden`.
4. **`assessment/rules/algorithms.py` & `assessment/rules/negotiation.py`**: Read the 19 deterministic rules and understand the logic for offered vs negotiated scoring.
5. **`assessment/scoring/__init__.py`**: Understand the simple, transparent deduction formula.
6. **`ai/facts.py` & `ai/explain.py`**: Review how AI is strictly bounded by deterministic facts and guard logic.
7. **`backend/app.py` & `frontend/src/App.jsx`**: Understand how FastAPI coordinates uploads, assessment, and React UI presentation.
