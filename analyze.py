#!/usr/bin/env python3
"""CLI Entrypoint for AI-Powered IPsec VPN Protocol Analyzer (Person 1 Module).

Usage:
    python analyze.py samples/secure/secure_01.pcap
    python analyze.py path/to/capture.pcap --output analysis/
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List

from analyzer.evidence.evidence_mapper import EvidenceMapper
from analyzer.extractors.tshark_extractor import (
    MalformedPcapError,
    PcapFileNotFoundError,
    TSharkExecutionError,
    TSharkExtractor,
    TSharkNotFoundError,
)
from analyzer.normalizer import build_normalized_v1
from analyzer.parsers.ike_parser import IKEv2Parser


def analyze_pcap(
    pcap_path: str | Path,
    output_dir: str | Path = "analysis",
) -> List[Path]:
    """Run full analysis pipeline on a PCAP file and write normalized output.
    
    Args:
        pcap_path: Path to the PCAP file.
        output_dir: Directory where analysis JSON should be written.

    Returns:
        List of generated JSON file paths.
    """
    pcap_file = Path(pcap_path).resolve()
    out_dir = Path(output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Initialize extractor and check tshark
    extractor = TSharkExtractor()

    # 2. Extract structured packets from tshark
    packets = extractor.extract_packets(pcap_file)

    # 3. Parse IKEv2 packets and map evidence
    evidence_mapper = EvidenceMapper()
    parser = IKEv2Parser(evidence_mapper=evidence_mapper)
    sessions = parser.parse_packet_list(packets)

    output_files: List[Path] = []
    base_stem = pcap_file.stem

    if not sessions:
        # No IKE sessions detected; write null-filled template as per schema contract
        normalized = build_normalized_v1(
            session=None,
            evidence_list=[],
            capture_file=pcap_file.name,
            source="tshark",
        )
        out_file = out_dir / f"{base_stem}.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(normalized, f, indent=2)
        output_files.append(out_file)
        return output_files

    if len(sessions) == 1:
        # Single session: write <base_stem>.json
        session = next(iter(sessions.values()))
        evidence = evidence_mapper.get_evidence(session.session_id)
        normalized = build_normalized_v1(
            session=session,
            evidence_list=evidence,
            capture_file=pcap_file.name,
            source="tshark",
        )
        out_file = out_dir / f"{base_stem}.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(normalized, f, indent=2)
        output_files.append(out_file)
    else:
        # Multiple sessions: write primary <base_stem>.json and per-session files
        first = True
        for s_id, session in sessions.items():
            evidence = evidence_mapper.get_evidence(s_id)
            normalized = build_normalized_v1(
                session=session,
                evidence_list=evidence,
                capture_file=pcap_file.name,
                source="tshark",
            )
            # Write per-session file
            out_file = out_dir / f"{base_stem}_{s_id}.json"
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(normalized, f, indent=2)
            output_files.append(out_file)

            if first:
                # Also save primary session as <base_stem>.json
                primary_file = out_dir / f"{base_stem}.json"
                with open(primary_file, "w", encoding="utf-8") as f:
                    json.dump(normalized, f, indent=2)
                output_files.append(primary_file)
                first = False

    return output_files


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract and normalize IPsec/IKEv2 sessions from PCAP using tshark."
    )
    parser.add_argument("pcap", help="Path to input PCAP file")
    parser.add_argument(
        "-o",
        "--output",
        default="analysis",
        help="Output directory for normalized JSON (default: analysis)",
    )

    args = parser.parse_args()

    try:
        written_files = analyze_pcap(args.pcap, output_dir=args.output)
        print(f"[SUCCESS] Analysis completed successfully.")
        for out_path in written_files:
            print(f"  -> Generated: {out_path}")
        return 0

    except TSharkNotFoundError as err:
        print(f"[ERROR] TShark not found: {err}", file=sys.stderr)
        return 1
    except PcapFileNotFoundError as err:
        print(f"[ERROR] File not found: {err}", file=sys.stderr)
        return 1
    except MalformedPcapError as err:
        print(f"[ERROR] Malformed PCAP: {err}", file=sys.stderr)
        return 1
    except TSharkExecutionError as err:
        print(f"[ERROR] TShark error: {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"[ERROR] Unexpected error: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
