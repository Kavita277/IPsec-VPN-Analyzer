"""TShark Extractor module.

Responsible for verifying tshark availability, executing tshark against
a PCAP file, handling extraction errors, and returning structured packet JSON.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, List, Optional


class TSharkExtractorError(Exception):
    """Base exception for TShark extractor."""
    pass


class TSharkNotFoundError(TSharkExtractorError):
    """Raised when tshark executable cannot be found."""
    pass


class PcapFileNotFoundError(TSharkExtractorError):
    """Raised when the specified PCAP file does not exist."""
    pass


class MalformedPcapError(TSharkExtractorError):
    """Raised when tshark encounters a corrupted or invalid PCAP file."""
    pass


class TSharkExecutionError(TSharkExtractorError):
    """Raised when tshark execution fails unexpectedly."""
    pass


class TSharkExtractor:
    """Manages tshark discovery and raw packet extraction from PCAP files."""

    STANDARD_WINDOWS_PATHS = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]

    def __init__(self, tshark_path: Optional[str] = None) -> None:
        """Initialize TSharkExtractor.
        
        Args:
            tshark_path: Explicit path to tshark executable (optional).
        """
        self.tshark_path = self.find_tshark(tshark_path)

    @classmethod
    def find_tshark(cls, custom_path: Optional[str] = None) -> str:
        """Find the tshark executable on the system.
        
        Args:
            custom_path: User-provided path or override.

        Returns:
            Resolved absolute path to tshark executable.

        Raises:
            TSharkNotFoundError: If tshark is not installed or found.
        """
        # 1. User supplied or environment variable override
        candidate = custom_path or os.environ.get("TSHARK_PATH")
        if candidate:
            resolved = shutil.which(candidate) or candidate
            if os.path.isfile(resolved) and os.access(resolved, os.X_OK):
                return os.path.abspath(resolved)
            if os.path.isfile(resolved):
                return os.path.abspath(resolved)

        # 2. Check PATH
        path_which = shutil.which("tshark")
        if path_which:
            return os.path.abspath(path_which)

        # 3. Check well-known Windows locations
        if os.name == "nt":
            for win_path in cls.STANDARD_WINDOWS_PATHS:
                if os.path.isfile(win_path):
                    return win_path

        raise TSharkNotFoundError(
            "tshark executable not found. Please ensure Wireshark/tshark is installed "
            "and added to PATH, or set TSHARK_PATH environment variable."
        )

    def extract_packets(
        self,
        pcap_path: str | Path,
        display_filter: str = "isakmp",
    ) -> List[dict[str, Any]]:
        """Run tshark against a PCAP file and return raw parsed packet JSON.

        Args:
            pcap_path: Path to the PCAP file.
            display_filter: Wireshark display filter to apply.

        Returns:
            List of packet dictionaries extracted from tshark.

        Raises:
            PcapFileNotFoundError: If PCAP file does not exist.
            MalformedPcapError: If PCAP file is damaged, invalid, or truncated.
            TSharkExecutionError: If tshark exits with an unexpected error.
        """
        pcap_file = Path(pcap_path).resolve()
        if not pcap_file.is_file():
            raise PcapFileNotFoundError(f"PCAP file not found: {pcap_file}")

        cmd = [
            self.tshark_path,
            "-r",
            str(pcap_file),
            "-T",
            "json",
            "--no-duplicate-keys",
            "-n",
        ]

        if display_filter:
            cmd.extend(["-Y", display_filter])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
        except OSError as exc:
            raise TSharkExecutionError(f"Failed to execute tshark: {exc}") from exc

        stderr_lower = result.stderr.lower()

        # Check for malformed / truncated / invalid capture file errors
        malformed_indicators = [
            "the capture file appears to be damaged or corrupt",
            "the file isn't a capture file",
            "appear to be a valid capture file",
            "less than the minimum header length",
            "cut short in the middle of a packet",
            "unrecognized libpcap format",
            "bad record length",
        ]

        if result.returncode != 0:
            if any(indicator in stderr_lower for indicator in malformed_indicators):
                raise MalformedPcapError(
                    f"PCAP file is malformed or corrupted: {result.stderr.strip()}"
                )
            raise TSharkExecutionError(
                f"tshark failed with exit code {result.returncode}: {result.stderr.strip()}"
            )

        # Even with returncode == 0, check if tshark printed fatal corrupt warnings
        if any(indicator in stderr_lower for indicator in malformed_indicators):
            raise MalformedPcapError(
                f"PCAP file is damaged or corrupted: {result.stderr.strip()}"
            )

        stdout = result.stdout.strip()
        if not stdout:
            return []

        try:
            parsed = json.loads(stdout)
            if isinstance(parsed, list):
                return parsed
            elif isinstance(parsed, dict):
                return [parsed]
            return []
        except json.JSONDecodeError as exc:
            raise MalformedPcapError(
                f"Failed to parse tshark JSON output: {exc}. Stderr: {result.stderr.strip()}"
            ) from exc
