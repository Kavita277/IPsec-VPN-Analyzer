"""Normalizer module.

Transforms parsed IKE sessions and associated evidence into the frozen v1.json schema contract.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from analyzer.evidence.evidence_mapper import EvidenceMapper
from analyzer.parsers.ike_parser import IKESession


def build_normalized_v1(
    session: Optional[IKESession],
    evidence_list: List[Dict[str, Any]],
    capture_file: Optional[str] = None,
    source: str = "tshark",
) -> Dict[str, Any]:
    """Produce a normalized document strictly complying with docs/schema/v1.json.
    
    Args:
        session: Extracted IKESession instance (or None if no session found).
        evidence_list: List of evidence items for this session.
        capture_file: Original PCAP file name/path.
        source: Extraction source identifier (default: "tshark").

    Returns:
        Dictionary conforming precisely to the frozen v1.json contract.
    """
    capture_filename = Path(capture_file).name if capture_file else None

    if session is None:
        return {
            "schema_version": "1.0",
            "session": {
                "session_id": None,
            },
            "protocol": {
                "ike_version": None,
            },
            "negotiation": {
                "status": None,
                "offered_proposals": [],
                "negotiated_proposal": None,
            },
            "security_parameters": {
                "encryption": None,
                "integrity": None,
                "dh_group": None,
            },
            "security_associations": [],
            "evidence": [],
            "metadata": {
                "source": source,
                "capture_file": capture_filename,
            },
        }

    return {
        "schema_version": "1.0",
        "session": {
            "session_id": session.session_id,
        },
        "protocol": {
            "ike_version": session.ike_version,
        },
        "negotiation": {
            "status": session.status,
            "offered_proposals": session.offered_proposals,
            "negotiated_proposal": session.negotiated_proposal,
        },
        "security_parameters": {
            "encryption": session.security_parameters.get("encryption"),
            "integrity": session.security_parameters.get("integrity"),
            "dh_group": session.security_parameters.get("dh_group"),
        },
        "security_associations": session.security_associations,
        "evidence": evidence_list,
        "metadata": {
            "source": source,
            "capture_file": capture_filename,
        },
    }
