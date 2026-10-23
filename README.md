# AI-Powered IPsec VPN Protocol Analyzer

Upload an IPsec capture, see which negotiated parameters break a security policy, follow each finding back to the exact packet, and export a report. Severity and score come from a deterministic, versioned rule engine. The AI only explains findings it is given.

```
PCAP -> tshark -> analyzer/ -> analysis/*.json -> assessment/ -> findings + posture -> backend/ + ai/ -> frontend/ + report
        Person 1                                  Person 2                            Person 3
```

| Folder | What it does | Docs |
| --- | --- | --- |
| `analyzer/`, `analyze.py` | PCAP to normalized JSON with packet-level evidence | `docs/person1_handoff.md` |
| `assessment/`, `assess.py` | Policies, 19 rules, scoring, before/after comparison | `docs/assessment.md` |
| `ai/` | Plain-language explanations from verified facts, with a guard | below |
| `backend/` | FastAPI: upload, assess, explain, compare, report export | below |
| `frontend/` | React dashboard: handshake diagram, findings, evidence chain | below |
| `samples/`, `analysis/`, `assessments/` | Three StrongSwan scenarios (secure, weak, failed) and their outputs | |

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
sudo apt install tshark            # or install Wireshark; only needed to analyze .pcap files

# command line
python analyze.py samples/weak/weak_01.pcap           # -> analysis/weak_01.json
python assess.py analysis/weak_01.json -p cnsa-strict # -> assessments/

# dashboard (one server serves API and UI)
cd frontend && npm install && npm run build && cd ..
uvicorn backend.app:app                               # open http://127.0.0.1:8000
```

For dashboard development with hot reload, run `uvicorn backend.app:app --reload` and, in `frontend/`, `npm run dev` (port 5173, proxies `/api`).

Without `tshark` the dashboard still works with the sample sessions and with analysis `.json` uploads. PCAP upload is switched off and the UI says so.

## Tests

```bash
python -m pytest assessment ai backend     # 130 tests
python -m pytest analyzer                  # Person 1's tests (need tshark and scapy)
```

## The dashboard

- **Assessment:** rating and score, a handshake ladder, negotiated and offered parameters, and findings grouped by severity. Selecting a finding highlights the packets that are its evidence and shows the chain: observed, policy, rule, evidence, meaning, fix.
- **How this verdict is reached** (bottom of the Assessment tab): states that the tool audits the negotiated configuration and does not detect attacks or malware, what happens to an uploaded PCAP or JSON, each parameter checked against the policy for the open session, the score arithmetic, and which of the 19 rules fired. Backed by `GET /api/methodology`.
- **Session help:** the `?` beside the Session selector explains that a session is one IKE security association (one tunnel negotiation, named from its initiator SPI) and shows the SPIs and packets of the session that is open.
- **Before and after:** compare two sessions under the same policy. Shows resolved, introduced and unchanged findings.
- **Report:** HTML (prints cleanly to PDF) and Markdown, with evidence, rule versions and limits.

## AI explanations

`ai/` receives only the rule engine's output (`ai/facts.py`). It cannot add, remove or re-rate findings.

- **Default:** deterministic template text (`ai/plain_language.py`). Works offline, no key needed.
- **LLM wording (optional):** set `ANTHROPIC_API_KEY`. `IPSEC_AI_MODEL` picks the model (default `claude-sonnet-5-5`), and `IPSEC_AI_PROVIDER=template` forces templates. The browser cannot select a paid provider.
- **Guard:** model output is dropped, per finding, if it is malformed, names an unknown finding, or mentions an `IPSEC-...` ID that is not in the facts. Template text fills the gap, and the UI and report label each piece as template or AI.
- The LLM path is covered by tests with a fake transport. It has not been run against the live API in this repository.

## API

| Endpoint | Purpose |
| --- | --- |
| `GET /api/health`, `/api/policies`, `/api/samples` | Status, bundled policies, sample sessions |
| `GET /api/methodology?policy=` | Policy lists, severity weights, rating scale and rule catalogue behind the verdict |
| `GET /api/samples/{name}?policy=` | Assess a sample |
| `POST /api/upload?policy=` | Multipart `.pcap`, `.pcapng` or analysis `.json` (max 25 MB) |
| `POST /api/assess?policy=` | Assess an analysis JSON body |
| `POST /api/compare` | `{before, after}` assessed documents |
| `POST /api/explain` | `{assessed}` returns explanations |
| `POST /api/report?format=html\|md` | `{assessed, explanation?, comparison?}` returns a report |

The API is stateless: the browser holds the session and nothing is stored on the server. Interactive docs are at `/docs` while the server runs.

## Limits

- Only IKEv2 handshake parameters visible in the capture are judged. ESP payloads are not decrypted, and SA lifetimes, PRF, authentication method and ESP transforms are not in the analyzer output yet.
- Handshake direction in the diagram is inferred from packet order.
- Policies are readings of the cited standards, not an official compliance test. Review the lists in `assessment/policies/` for your own requirements.
