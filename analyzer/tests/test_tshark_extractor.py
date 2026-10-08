"""Unit tests for TShark Extractor."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from analyzer.extractors.tshark_extractor import (
    MalformedPcapError,
    PcapFileNotFoundError,
    TSharkExecutionError,
    TSharkExtractor,
    TSharkNotFoundError,
)


def test_missing_tshark(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that TSharkNotFoundError is raised when tshark is not on PATH or standard locations."""
    monkeypatch.setattr("shutil.which", lambda cmd: None)
    monkeypatch.setattr("os.path.isfile", lambda path: False)
    monkeypatch.delenv("TSHARK_PATH", raising=False)

    with pytest.raises(TSharkNotFoundError) as exc_info:
        TSharkExtractor.find_tshark()
    assert "tshark executable not found" in str(exc_info.value)


def test_missing_pcap(tmp_path: Path) -> None:
    """Verify that PcapFileNotFoundError is raised when file does not exist."""
    extractor = TSharkExtractor.__new__(TSharkExtractor)
    extractor.tshark_path = "mock_tshark"

    non_existent = tmp_path / "does_not_exist.pcap"
    with pytest.raises(PcapFileNotFoundError):
        extractor.extract_packets(non_existent)


def test_malformed_pcap(tmp_path: Path) -> None:
    """Verify that MalformedPcapError is raised when tshark reports a corrupted file."""
    extractor = TSharkExtractor.__new__(TSharkExtractor)
    extractor.tshark_path = "mock_tshark"

    corrupt_file = tmp_path / "corrupt.pcap"
    corrupt_file.write_bytes(b"garbage-not-a-valid-pcap-header")

    # Mock subprocess run returning tshark error
    mock_res = MagicMock()
    mock_res.returncode = 1
    mock_res.stdout = ""
    mock_res.stderr = "tshark: The capture file appears to be damaged or corrupt."

    with patch("subprocess.run", return_value=mock_res):
        with pytest.raises(MalformedPcapError):
            extractor.extract_packets(corrupt_file)


def test_tshark_execution_error(tmp_path: Path) -> None:
    """Verify generic execution failure handling."""
    extractor = TSharkExtractor.__new__(TSharkExtractor)
    extractor.tshark_path = "mock_tshark"

    valid_file = tmp_path / "test.pcap"
    valid_file.write_bytes(b"some content")

    mock_res = MagicMock()
    mock_res.returncode = 2
    mock_res.stdout = ""
    mock_res.stderr = "Unknown internal crash"

    with patch("subprocess.run", return_value=mock_res):
        with pytest.raises(TSharkExecutionError):
            extractor.extract_packets(valid_file)


def test_valid_json_extraction(tmp_path: Path) -> None:
    """Verify successful parsing of structured tshark JSON output."""
    extractor = TSharkExtractor.__new__(TSharkExtractor)
    extractor.tshark_path = "mock_tshark"

    dummy_pcap = tmp_path / "sample.pcap"
    dummy_pcap.write_bytes(b"sample bytes")

    mock_packet = [
        {
            "_source": {
                "layers": {
                    "frame": {"frame.number": "1"},
                    "ikev2": {"ikev2.version": "0x20"},
                }
            }
        }
    ]

    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = json.dumps(mock_packet)
    mock_res.stderr = ""

    with patch("subprocess.run", return_value=mock_res):
        packets = extractor.extract_packets(dummy_pcap)
        assert len(packets) == 1
        assert packets[0]["_source"]["layers"]["frame"]["frame.number"] == "1"


def test_empty_packet_output(tmp_path: Path) -> None:
    """Verify that empty tshark output returns empty list."""
    extractor = TSharkExtractor.__new__(TSharkExtractor)
    extractor.tshark_path = "mock_tshark"

    dummy_pcap = tmp_path / "empty.pcap"
    dummy_pcap.write_bytes(b"sample")

    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = "   \n"
    mock_res.stderr = ""

    with patch("subprocess.run", return_value=mock_res):
        packets = extractor.extract_packets(dummy_pcap)
        assert packets == []
