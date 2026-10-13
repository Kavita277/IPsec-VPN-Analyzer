"""Builders for synthetic analysis documents shaped like Person 1's output."""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional

SID = "vpn_0123456789abcdef"
ISPI = "01:23:45:67:89:ab:cd:ef"
RSPI = "fe:dc:ba:98:76:54:32:10"

_UNSET = object()


def make_doc(
    enc: Optional[str] = "AES-256-CBC",
    integ: Optional[str] = "HMAC-SHA2-256",
    dh: Optional[str] = "MODP-2048",
    status: Optional[str] = "successful",
    ike: Optional[str] = "IKEv2",
    offered: Any = _UNSET,
    negotiated: Any = _UNSET,
    evidence: bool = True,
    session: bool = True,
) -> Dict[str, Any]:
    """A completed handshake by default. Pass status='failed' with enc/integ/dh=None for a failed one."""
    proposal = {"encryption": enc, "integrity": integ, "dh_group": dh}
    if offered is _UNSET:
        offered = [dict(proposal)]
    if negotiated is _UNSET:
        negotiated = dict(proposal) if status == "successful" else None

    sid = SID if session else None
    ev: List[Dict[str, Any]] = []
    sas: List[Dict[str, Any]] = []
    if session:
        sas = [
            {"initiator_spi": ISPI, "responder_spi": None, "packet": 1},
            {"initiator_spi": ISPI, "responder_spi": RSPI if status == "successful" else None, "packet": 2},
        ]
        if evidence:
            fields = (("encryption", "isakmp.tf.id.encr"), ("integrity", "isakmp.tf.id.integ"), ("dh_group", "isakmp.tf.id.dh"))
            for proposal_item in offered:
                for key, field in fields:
                    if proposal_item.get(key):
                        ev.append({"packet": 1, "field": field, "value": proposal_item[key], "session_id": sid})
            if negotiated:
                for key, field in fields:
                    if negotiated.get(key):
                        ev.append({"packet": 2, "field": field, "value": negotiated[key], "session_id": sid})
            if ike:
                ev.append({"packet": 1, "field": "isakmp.version", "value": ike, "session_id": sid})
            if status == "failed":
                ev.append({"packet": 2, "field": "isakmp.typepayload_tree.isakmp.notify.msgtype",
                           "value": "NO_PROPOSAL_CHOSEN", "session_id": sid})

    return {
        "schema_version": "1.0",
        "session": {"session_id": sid},
        "protocol": {"ike_version": ike if session else None},
        "negotiation": {"status": status if session else None, "offered_proposals": offered if session else [],
                        "negotiated_proposal": negotiated if session else None},
        "security_parameters": {"encryption": enc if negotiated else None,
                                "integrity": integ if negotiated else None,
                                "dh_group": dh if negotiated else None},
        "security_associations": sas,
        "evidence": ev,
        "metadata": {"source": "tshark", "capture_file": "synthetic.pcap"},
    }


def failed_doc(**kw) -> Dict[str, Any]:
    """Failed handshake: the initiator offered the given values, nothing was negotiated."""
    enc = kw.pop("enc", "AES-256-CBC")
    integ = kw.pop("integ", "HMAC-SHA2-256")
    dh = kw.pop("dh", "MODP-2048")
    return make_doc(enc=enc, integ=integ, dh=dh, status="failed", **kw)


def ids(result: Dict[str, Any]) -> List[str]:
    return [f["finding_id"] for f in result["findings"]]


def find(result: Dict[str, Any], finding_id: str) -> Dict[str, Any]:
    matches = [f for f in result["findings"] if f["finding_id"] == finding_id]
    assert matches, f"{finding_id} not in {ids(result)}"
    return matches[0]


def clone(doc: Dict[str, Any]) -> Dict[str, Any]:
    return copy.deepcopy(doc)
