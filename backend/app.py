"""HTTP API tying the analyzer, assessment engine, AI layer and report export together.

The API is stateless: every call that needs an assessment receives it in the
request, so the browser holds the session and nothing is stored on the server.

Run from the repository root:
    uvicorn backend.app:app --reload
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Body, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ai import explain as ai_explain  # noqa: E402
from ai import guard  # noqa: E402
from ai.facts import build_facts  # noqa: E402
from assessment import InvalidAnalysisError, PolicyError, assess, compare, list_policies, load_policy  # noqa: E402
from assessment.rules import RULESET_VERSION  # noqa: E402
from backend.report import build_model, render_html, render_markdown  # noqa: E402

SAMPLES_DIR = ROOT / "analysis"
FRONTEND_DIST = ROOT / "frontend" / "dist"
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}
CLIENT_PROVIDERS = {None, "auto", "template"}  # the browser may not pick a paid provider

app = FastAPI(title="IPsec VPN Analyzer API", version=RULESET_VERSION)


# --- helpers -----------------------------------------------------------

def _policy(policy: Optional[str]):
    try:
        return load_policy(policy)
    except PolicyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None


def _assess(doc: Any, policy: Optional[str]) -> Dict[str, Any]:
    pol = _policy(policy)
    try:
        return assess(doc, pol)
    except InvalidAnalysisError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


def _samples() -> Dict[str, Path]:
    return {p.stem: p for p in sorted(SAMPLES_DIR.glob("*.json"))} if SAMPLES_DIR.is_dir() else {}


def _safe_name(name: Optional[str]) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", Path(name or "upload").name)[:80] or "upload"
    return stem


def _run_pcap_analysis(data: bytes, filename: str) -> List[Dict[str, Any]]:
    """Run Person 1's pipeline on uploaded capture bytes. Needs tshark on the server."""
    try:
        from analyze import analyze_pcap
        from analyzer.extractors.tshark_extractor import (
            MalformedPcapError,
            TSharkExecutionError,
            TSharkNotFoundError,
        )
    except ImportError as exc:
        raise HTTPException(status_code=503, detail=f"The PCAP analyzer is not available on this server ({exc.name}).") from None

    safe = _safe_name(filename)
    with tempfile.TemporaryDirectory(prefix="ipsec-upload-") as tmp:
        pcap = Path(tmp) / safe
        pcap.write_bytes(data)
        try:
            outputs = analyze_pcap(pcap, output_dir=Path(tmp) / "out")
        except TSharkNotFoundError:
            raise HTTPException(
                status_code=503,
                detail="tshark is not installed on the server, so PCAP files cannot be analyzed. "
                       "Install Wireshark/tshark, or upload an analysis JSON instead.",
            ) from None
        except MalformedPcapError as exc:
            raise HTTPException(status_code=422, detail=f"Malformed capture file: {exc}") from None
        except TSharkExecutionError as exc:
            raise HTTPException(status_code=422, detail=f"tshark could not read this file: {exc}") from None
        if len(outputs) > 1:  # analyze.py also writes a duplicate of the first session as <stem>.json
            outputs = [o for o in outputs if o.name != f"{pcap.stem}.json"]
        return [json.loads(o.read_text(encoding="utf-8")) for o in outputs]


# --- routes ------------------------------------------------------------

@app.get("/api/health")
def health() -> Dict[str, Any]:
    import os
    import shutil

    return {
        "status": "ok",
        "ruleset_version": RULESET_VERSION,
        "pcap_upload": shutil.which("tshark") is not None or bool(os.environ.get("TSHARK_PATH")),
        "ai_provider": "anthropic" if os.environ.get("ANTHROPIC_API_KEY") and os.environ.get("IPSEC_AI_PROVIDER", "auto") != "template" else "template",
    }


@app.get("/api/policies")
def policies() -> List[Dict[str, Any]]:
    out = []
    for pid in list_policies():
        pol = load_policy(pid)
        out.append({**pol.summary(), "description": pol.data.get("description", ""), "references": pol.references,
                    "recommended": pol.recommended})
    return out


@app.get("/api/samples")
def samples() -> List[Dict[str, Any]]:
    out = []
    for name, path in _samples().items():
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        out.append({
            "name": name,
            "capture_file": (doc.get("metadata") or {}).get("capture_file"),
            "session_id": (doc.get("session") or {}).get("session_id"),
            "negotiation_status": (doc.get("negotiation") or {}).get("status"),
        })
    return out


@app.get("/api/samples/{name}")
def sample(name: str, policy: Optional[str] = None) -> Dict[str, Any]:
    path = _samples().get(name)
    if path is None:
        raise HTTPException(status_code=404, detail=f"No sample named {name!r}")
    return {"results": [_assess(json.loads(path.read_text(encoding="utf-8")), policy)], "source": "sample"}


@app.post("/api/assess")
def assess_json(doc: Any = Body(...), policy: Optional[str] = None) -> Dict[str, Any]:
    return {"results": [_assess(doc, policy)], "source": "json"}


@app.post("/api/upload")
async def upload(file: UploadFile = File(...), policy: Optional[str] = None) -> Dict[str, Any]:
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"File is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
    if not data:
        raise HTTPException(status_code=422, detail="The uploaded file is empty")
    _policy(policy)  # fail fast on a bad policy before doing any work
    suffix = Path(file.filename or "").suffix.lower()

    if suffix == ".json":
        try:
            doc = json.loads(data)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise HTTPException(status_code=422, detail="The file is not valid JSON") from None
        return {"results": [_assess(doc, policy)], "source": "json"}
    if suffix in PCAP_SUFFIXES:
        docs = _run_pcap_analysis(data, file.filename or "capture.pcap")
        return {"results": [_assess(d, policy) for d in docs], "source": "pcap"}
    raise HTTPException(status_code=415, detail="Upload a .pcap/.pcapng capture or an analysis .json file")


@app.post("/api/compare")
def compare_endpoint(body: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    try:
        return compare(body.get("before") or {}, body.get("after") or {})
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=f"Both 'before' and 'after' must be assessed documents ({exc})") from None


def _check_assessed(doc: Any) -> Dict[str, Any]:
    if not isinstance(doc, dict) or "findings" not in doc or "posture" not in doc:
        raise HTTPException(status_code=422, detail="'assessed' must be an assessed document (output of /api/assess)")
    return doc


@app.post("/api/explain")
def explain_endpoint(body: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    assessed = _check_assessed(body.get("assessed"))
    provider = body.get("provider")
    if provider not in CLIENT_PROVIDERS:
        raise HTTPException(status_code=400, detail="provider must be 'auto' or 'template'")
    return ai_explain(assessed, provider=provider)


def _reusable_explanation(assessed: Dict[str, Any], given: Any) -> Optional[Dict[str, Any]]:
    """Reuse an explanation the user already saw, but only if it passes the same guard."""
    if not isinstance(given, dict):
        return None
    try:
        raw = {
            "summary": given["summary"]["text"],
            "findings": {
                k: {x: v[x] for x in ("explanation", "impact", "remediation_steps")}
                for k, v in given["findings"].items()
            },
        }
    except (KeyError, TypeError, AttributeError):
        return None
    facts = build_facts(assessed)
    checked = guard(raw, facts)
    if checked["rejected"] or checked["summary"] is None or set(checked["findings"]) != {f["key"] for f in facts["findings"]}:
        return None
    # Keep the source labels but never trust them beyond known values.
    allowed = {"template", "anthropic"}
    return {
        "summary": {"text": checked["summary"], "source": given["summary"].get("source") if given["summary"].get("source") in allowed else "template"},
        "findings": {k: {**v, "source": given["findings"][k].get("source") if given["findings"][k].get("source") in allowed else "template"}
                     for k, v in checked["findings"].items()},
        "ai": {"provider": "reused", "model": None, "warnings": []},
    }


@app.post("/api/report")
def report(body: Dict[str, Any] = Body(...), format: str = Query("html", pattern="^(html|md)$")) -> Response:
    assessed = _check_assessed(body.get("assessed"))
    explanation = _reusable_explanation(assessed, body.get("explanation")) or ai_explain(assessed, provider=None)
    comparison = body.get("comparison")
    if comparison is not None and not (isinstance(comparison, dict) and "posture_change" in comparison):
        raise HTTPException(status_code=422, detail="'comparison' must be the output of /api/compare")
    model = build_model(assessed, explanation, comparison)
    sid = re.sub(r"[^A-Za-z0-9_-]", "", str(model["session_id"] or "report"))
    if format == "md":
        return Response(render_markdown(model), media_type="text/markdown; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="ipsec-assessment-{sid}.md"'})
    return Response(render_html(model), media_type="text/html; charset=utf-8",
                    headers={"Content-Disposition": f'inline; filename="ipsec-assessment-{sid}.html"'})


# The built dashboard is served last so it never shadows /api routes.
if FRONTEND_DIST.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="frontend")
