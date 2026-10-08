"""Unit tests for IKEv2 Parser."""

from analyzer.evidence.evidence_mapper import EvidenceMapper
from analyzer.parsers.ike_parser import IKEv2Parser


def test_detect_ikev2_and_session_id() -> None:
    """Verify IKEv2 version detection and session grouping from SPI."""
    mapper = EvidenceMapper()
    parser = IKEv2Parser(evidence_mapper=mapper)

    packet = {
        "_source": {
            "layers": {
                "frame": {"frame.number": "1"},
                "isakmp": {
                    "isakmp.ispi": "11:22:33:44:55:66:77:88",
                    "isakmp.rspi": "00:00:00:00:00:00:00:00",
                    "isakmp.version": "0x20",
                    "isakmp.exchangetype": "34",
                    "isakmp.flags_tree": {"isakmp.flag_r": "0"},
                },
            }
        }
    }

    session = parser.parse_packet(packet)
    assert session is not None
    assert session.session_id == "vpn_1122334455667788"
    assert session.ike_version == "IKEv2"

    evidence = mapper.get_evidence("vpn_1122334455667788")
    assert any(e["field"] == "isakmp.version" and e["value"] == "IKEv2" for e in evidence)
    assert any(e["field"] == "isakmp.ispi" and e["value"] == "11:22:33:44:55:66:77:88" for e in evidence)


def test_ignore_non_ikev2() -> None:
    """Verify that non-IKEv2 packets (e.g. IKEv1 version 0x10) are ignored."""
    mapper = EvidenceMapper()
    parser = IKEv2Parser(evidence_mapper=mapper)

    packet_v1 = {
        "_source": {
            "layers": {
                "frame": {"frame.number": "1"},
                "isakmp": {
                    "isakmp.ispi": "aabbccddeeff0011",
                    "isakmp.version": "0x10",  # IKEv1
                },
            }
        }
    }

    session = parser.parse_packet(packet_v1)
    assert session is None
    assert len(parser.sessions) == 0


def test_offered_vs_negotiated_proposals() -> None:
    """Verify that initiator proposals go to offered_proposals and responder proposal goes to negotiated."""
    mapper = EvidenceMapper()
    parser = IKEv2Parser(evidence_mapper=mapper)

    # Packet 1: Request with offered proposals
    req_packet = {
        "_source": {
            "layers": {
                "frame": {"frame.number": "10"},
                "isakmp": {
                    "isakmp.ispi": "aabb112233445566",
                    "isakmp.rspi": "00:00:00:00:00:00:00:00",
                    "isakmp.version": "0x20",
                    "isakmp.exchangetype": "34",
                    "isakmp.flags_tree": {"isakmp.flag_r": "0"},
                    "isakmp.prop.number": "1",
                    "isakmp.tf.type": "1",
                    "isakmp.tf.id.encr": "12",
                    "isakmp.ike2.attr": {"isakmp.ike2.attr.key_length": "256"},
                    "isakmp.tf.id.integ": "12",
                    "isakmp.tf.id.dh": "14",
                },
            }
        }
    }

    # Packet 2: Response with chosen/negotiated proposal
    resp_packet = {
        "_source": {
            "layers": {
                "frame": {"frame.number": "11"},
                "isakmp": {
                    "isakmp.ispi": "aabb112233445566",
                    "isakmp.rspi": "9988776655443322",
                    "isakmp.version": "0x20",
                    "isakmp.exchangetype": "34",
                    "isakmp.flags_tree": {"isakmp.flag_r": "1"},
                    "isakmp.prop.number": "1",
                    "isakmp.tf.type": "1",
                    "isakmp.tf.id.encr": "12",
                    "isakmp.ike2.attr": {"isakmp.ike2.attr.key_length": "256"},
                    "isakmp.tf.id.integ": "12",
                    "isakmp.tf.id.dh": "14",
                },
            }
        }
    }

    parser.parse_packet(req_packet)
    parser.parse_packet(resp_packet)

    session = parser.sessions["vpn_aabb112233445566"]
    assert len(session.offered_proposals) == 1
    assert session.offered_proposals[0]["encryption"] == "AES-256-CBC"
    assert session.offered_proposals[0]["integrity"] == "HMAC-SHA2-256"
    assert session.offered_proposals[0]["dh_group"] == "MODP-2048"

    assert session.negotiated_proposal is not None
    assert session.negotiated_proposal["encryption"] == "AES-256-CBC"
    assert session.negotiated_proposal["integrity"] == "HMAC-SHA2-256"
    assert session.negotiated_proposal["dh_group"] == "MODP-2048"

    assert session.status == "successful"
    assert session.security_parameters["encryption"] == "AES-256-CBC"
    assert session.security_parameters["integrity"] == "HMAC-SHA2-256"
    assert session.security_parameters["dh_group"] == "MODP-2048"


def test_missing_fields_return_null() -> None:
    """Verify that unobservable fields remain None/null and are never invented."""
    mapper = EvidenceMapper()
    parser = IKEv2Parser(evidence_mapper=mapper)

    # Incomplete proposal with only encryption, no integrity or DH group
    partial_packet = {
        "_source": {
            "layers": {
                "frame": {"frame.number": "5"},
                "isakmp": {
                    "isakmp.ispi": "deadbeef12345678",
                    "isakmp.version": "0x20",
                    "isakmp.flags_tree": {"isakmp.flag_r": "0"},
                    "isakmp.prop.number": "1",
                    "isakmp.tf.type": "1",
                    "isakmp.tf.id.encr": "3",  # 3DES-CBC
                },
            }
        }
    }

    parser.parse_packet(partial_packet)
    session = parser.sessions["vpn_deadbeef12345678"]

    assert len(session.offered_proposals) == 1
    prop = session.offered_proposals[0]
    assert prop["encryption"] == "3DES-CBC"
    assert prop["integrity"] is None
    assert prop["dh_group"] is None

    # Negotiated proposal must be None because no response was observed
    assert session.negotiated_proposal is None
    assert session.security_parameters["encryption"] is None
    assert session.security_parameters["integrity"] is None
    assert session.security_parameters["dh_group"] is None


def test_session_grouping_multiple_packets() -> None:
    """Verify that multiple packets with the same initiator SPI are grouped together."""
    mapper = EvidenceMapper()
    parser = IKEv2Parser(evidence_mapper=mapper)

    p1 = {
        "_source": {
            "layers": {
                "frame": {"frame.number": "1"},
                "isakmp": {
                    "isakmp.ispi": "cafebeef00112233",
                    "isakmp.version": "0x20",
                    "isakmp.flags_tree": {"isakmp.flag_r": "0"},
                },
            }
        }
    }

    p2 = {
        "_source": {
            "layers": {
                "frame": {"frame.number": "2"},
                "isakmp": {
                    "isakmp.ispi": "cafebeef00112233",
                    "isakmp.version": "0x20",
                    "isakmp.flags_tree": {"isakmp.flag_r": "1"},
                },
            }
        }
    }

    p3 = {
        "_source": {
            "layers": {
                "frame": {"frame.number": "3"},
                "isakmp": {
                    "isakmp.ispi": "different99887766",
                    "isakmp.version": "0x20",
                    "isakmp.flags_tree": {"isakmp.flag_r": "0"},
                },
            }
        }
    }

    parser.parse_packet(p1)
    parser.parse_packet(p2)
    parser.parse_packet(p3)

    assert len(parser.sessions) == 2
    assert "vpn_cafebeef00112233" in parser.sessions
    assert "vpn_different99887766" in parser.sessions


def test_notify_error_failed_status() -> None:
    """Verify that notify payload error sets status to failed."""
    mapper = EvidenceMapper()
    parser = IKEv2Parser(evidence_mapper=mapper)

    err_packet = {
        "_source": {
            "layers": {
                "frame": {"frame.number": "20"},
                "isakmp": {
                    "isakmp.ispi": "feedface00112233",
                    "isakmp.rspi": "1122334455667788",
                    "isakmp.version": "0x20",
                    "isakmp.flags_tree": {"isakmp.flag_r": "1"},
                    "isakmp.notify.type": "14",  # NO_PROPOSAL_CHOSEN
                },
            }
        }
    }

    parser.parse_packet(err_packet)
    session = parser.sessions["vpn_feedface00112233"]

    assert session.status == "failed"
    assert session.negotiated_proposal is None
