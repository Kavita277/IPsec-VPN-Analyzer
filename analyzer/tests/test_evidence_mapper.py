"""Unit tests for EvidenceMapper."""

from analyzer.evidence.evidence_mapper import EvidenceItem, EvidenceMapper


def test_evidence_structure() -> None:
    """Verify that evidence items conform to packet, field, value, session_id."""
    mapper = EvidenceMapper()
    item = mapper.record(
        packet=42,
        field="ikev2.proposal.encryption",
        value="AES-256-CBC",
        session_id="vpn_secure_001",
    )

    assert isinstance(item, EvidenceItem)
    d = item.to_dict()
    assert d == {
        "packet": 42,
        "field": "ikev2.proposal.encryption",
        "value": "AES-256-CBC",
        "session_id": "vpn_secure_001",
    }


def test_evidence_by_session() -> None:
    """Verify evidence segregation by session ID."""
    mapper = EvidenceMapper()
    mapper.record(1, "field.a", "val_a", session_id="session_1")
    mapper.record(2, "field.b", "val_b", session_id="session_2")
    mapper.record(3, "field.c", "val_c", session_id="session_1")

    s1_ev = mapper.get_evidence("session_1")
    s2_ev = mapper.get_evidence("session_2")
    all_ev = mapper.get_evidence()

    assert len(s1_ev) == 2
    assert len(s2_ev) == 1
    assert len(all_ev) == 3

    assert s1_ev[0]["packet"] == 1
    assert s1_ev[1]["packet"] == 3
    assert s2_ev[0]["packet"] == 2


def test_unassociated_evidence() -> None:
    """Verify evidence without session_id is preserved."""
    mapper = EvidenceMapper()
    mapper.record(1, "frame.protocols", "eth:ip:udp:isakmp", session_id=None)

    all_ev = mapper.get_evidence()
    assert len(all_ev) == 1
    assert all_ev[0]["session_id"] is None
    assert all_ev[0]["value"] == "eth:ip:udp:isakmp"


def test_evidence_clear() -> None:
    """Verify clear empties the evidence mapper."""
    mapper = EvidenceMapper()
    mapper.record(1, "field.a", "val_a", session_id="session_1")
    assert len(mapper.get_evidence()) == 1
    mapper.clear()
    assert len(mapper.get_evidence()) == 0
