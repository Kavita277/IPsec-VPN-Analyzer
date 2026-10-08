"""Integration and Schema Contract Tests."""

import json
import subprocess
import sys
from pathlib import Path

from analyze import analyze_pcap
from analyzer.normalizer import build_normalized_v1
from analyzer.parsers.ike_parser import IKESession


FROZEN_SCHEMA_CONTRACT = {
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
        "source": None,
        "capture_file": None,
    },
}


def test_schema_keys_conformity() -> None:
    """Verify that normalized output strictly matches the keys and structure of docs/schema/v1.json."""
    schema_path = Path("docs/schema/v1.json")
    assert schema_path.exists(), "docs/schema/v1.json must exist"

    if schema_path.stat().st_size > 0:
        with open(schema_path, "r", encoding="utf-8") as f:
            schema_contract = json.load(f)
    else:
        schema_contract = FROZEN_SCHEMA_CONTRACT

    # 1. Test null-filled session output
    null_doc = build_normalized_v1(None, [], capture_file="test.pcap")
    assert set(null_doc.keys()) == set(schema_contract.keys())
    assert set(null_doc["session"].keys()) == set(schema_contract["session"].keys())
    assert set(null_doc["protocol"].keys()) == set(schema_contract["protocol"].keys())
    assert set(null_doc["negotiation"].keys()) == set(schema_contract["negotiation"].keys())
    assert set(null_doc["security_parameters"].keys()) == set(schema_contract["security_parameters"].keys())
    assert set(null_doc["metadata"].keys()) == set(schema_contract["metadata"].keys())

    # 2. Test populated session output
    session = IKESession("vpn_1234567890abcdef")
    session.ike_version = "IKEv2"
    session.status = "successful"
    session.offered_proposals = [
        {"encryption": "AES-256-CBC", "integrity": "HMAC-SHA2-256", "dh_group": "MODP-2048"}
    ]
    session.negotiated_proposal = {
        "encryption": "AES-256-CBC",
        "integrity": "HMAC-SHA2-256",
        "dh_group": "MODP-2048",
    }
    session.security_parameters = {
        "encryption": "AES-256-CBC",
        "integrity": "HMAC-SHA2-256",
        "dh_group": "MODP-2048",
    }
    evidence = [
        {
            "packet": 1,
            "field": "ikev2.transform.encryption",
            "value": "AES-256-CBC",
            "session_id": "vpn_1234567890abcdef",
        }
    ]

    populated_doc = build_normalized_v1(session, evidence, capture_file="secure.pcap")
    assert set(populated_doc.keys()) == set(schema_contract.keys())
    assert set(populated_doc["session"].keys()) == set(schema_contract["session"].keys())
    assert set(populated_doc["protocol"].keys()) == set(schema_contract["protocol"].keys())
    assert set(populated_doc["negotiation"].keys()) == set(schema_contract["negotiation"].keys())
    assert set(populated_doc["security_parameters"].keys()) == set(schema_contract["security_parameters"].keys())
    assert set(populated_doc["metadata"].keys()) == set(schema_contract["metadata"].keys())

    assert populated_doc["schema_version"] == "1.0"
    assert populated_doc["session"]["session_id"] == "vpn_1234567890abcdef"
    assert populated_doc["protocol"]["ike_version"] == "IKEv2"
    assert populated_doc["negotiation"]["status"] == "successful"
    assert len(populated_doc["evidence"]) == 1


def test_cli_execution_with_scapy_pcap(tmp_path: Path) -> None:
    """Generate a real IKEv2 PCAP, run analyze.py CLI, and verify analysis/ output."""
    from scapy.all import Ether, IP, Raw, UDP, wrpcap

    # Transform 1: ENCR AES-CBC (12) + Key length 256
    t1 = bytes.fromhex("0300000c0100000c800e0100")
    # Transform 2: PRF HMAC-SHA2-256 (5)
    t2 = bytes.fromhex("0300000802000005")
    # Transform 3: INTEG HMAC-SHA2-256 (12)
    t3 = bytes.fromhex("030000080300000c")
    # Transform 4: DH Group 14 (MODP-2048)
    t4 = bytes.fromhex("000000080400000e")

    # Proposal 1: Length 44 (8 header + 12 + 8 + 8 + 8)
    prop = bytes.fromhex("0000002c01010004") + t1 + t2 + t3 + t4

    # SA Payload: Length 48 (4 header + 44)
    sa = bytes.fromhex("00000030") + prop

    # IKE Header: Init SPI: aabbccddeeff0011, Resp SPI: 0, Next: 33 (SA), Version: 0x20, Exch: 34 (IKE_SA_INIT), Flags: 0x08, MsgID: 0
    ike_hdr = bytes.fromhex("aabbccddeeff00110000000000000000212022080000000000000000")
    total_len = 28 + len(sa)
    ike_hdr = ike_hdr[:24] + total_len.to_bytes(4, "big")

    payload = ike_hdr + sa

    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=500, dport=500) / Raw(load=payload)

    pcap_file = tmp_path / "test_secure_01.pcap"
    wrpcap(str(pcap_file), [pkt])

    out_dir = tmp_path / "analysis_out"

    # Run analyze_pcap function
    output_files = analyze_pcap(pcap_file, output_dir=out_dir)
    assert len(output_files) >= 1

    primary_out = out_dir / "test_secure_01.json"
    assert primary_out.is_file()

    with open(primary_out, "r", encoding="utf-8") as f:
        doc = json.load(f)

    assert doc["schema_version"] == "1.0"
    assert doc["session"]["session_id"] == "vpn_aabbccddeeff0011"
    assert doc["protocol"]["ike_version"] == "IKEv2"
    assert len(doc["negotiation"]["offered_proposals"]) >= 1
    assert doc["negotiation"]["offered_proposals"][0]["encryption"] == "AES-256-CBC"
    assert doc["negotiation"]["offered_proposals"][0]["dh_group"] == "MODP-2048"
    assert len(doc["evidence"]) >= 1


def test_cli_subprocess_invocation(tmp_path: Path) -> None:
    """Test invoking python analyze.py via subprocess CLI."""
    non_existent = tmp_path / "missing.pcap"

    res = subprocess.run(
        [sys.executable, "analyze.py", str(non_existent)],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 1
    assert "File not found" in res.stderr
