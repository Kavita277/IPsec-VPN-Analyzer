#!/usr/bin/env python3
"""Generate small synthetic IKEv2 captures for testing the analyzer and dashboard.

Standard library only. The output is deterministic, so rerunning this script
reproduces the committed files byte for byte:

    python testfiles/generate_testfiles.py

Each capture holds one IKEv2 session: IKE_SA_INIT request and response on UDP
500 (these carry the proposals the analyzer reads), then IKE_AUTH request and
response on UDP 4500 (encrypted, so the contents are random bytes, as on a real
wire). The SA payload layout follows the real StrongSwan captures in samples/.
Key exchange values, nonces and ciphertext are random filler, not a real
key exchange, so these files are for parsing and assessment tests only.
"""

from __future__ import annotations

import random
import struct
from pathlib import Path

OUT = Path(__file__).resolve().parent

# IANA IKEv2 transform types
ENCR, PRF, INTEG, DH = 1, 2, 3, 4
# Key-exchange sizes in bytes, by DH group id
KE_BYTES = {2: 128, 14: 256, 15: 384, 20: 96}


def transform(kind: int, ident: int, key_bits: int | None = None, last: bool = False) -> bytes:
    attr = struct.pack("!HH", 0x800E, key_bits) if key_bits else b""
    return struct.pack("!BBHBBH", 0 if last else 3, 0, 8 + len(attr), kind, 0, ident) + attr


def sa_payload(next_payload: int, encr: int, key_bits: int | None, prf: int, integ: int, dh: int) -> bytes:
    transforms = [transform(ENCR, encr, key_bits), transform(INTEG, integ), transform(PRF, prf), transform(DH, dh, last=True)]
    body = b"".join(transforms)
    proposal = struct.pack("!BBHBBBB", 0, 0, 8 + len(body), 1, 1, 0, len(transforms)) + body
    return struct.pack("!BBH", next_payload, 0, 4 + len(proposal)) + proposal


def generic(next_payload: int, body: bytes) -> bytes:
    return struct.pack("!BBH", next_payload, 0, 4 + len(body)) + body


def ike_header(ispi: bytes, rspi: bytes, next_payload: int, exchange: int, flags: int, msg_id: int, payloads: bytes) -> bytes:
    return ispi + rspi + struct.pack("!BBBBII", next_payload, 0x20, exchange, flags, msg_id, 28 + len(payloads)) + payloads


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def frame(src: str, dst: str, sport: int, dport: int, payload: bytes, ident: int, macs: tuple) -> bytes:
    ip_src, ip_dst = bytes(map(int, src.split("."))), bytes(map(int, dst.split(".")))
    udp_len = 8 + len(payload)
    pseudo = ip_src + ip_dst + struct.pack("!BBH", 0, 17, udp_len)
    udp_nosum = struct.pack("!HHHH", sport, dport, udp_len, 0) + payload
    udp = struct.pack("!HHHH", sport, dport, udp_len, checksum(pseudo + udp_nosum) or 0xFFFF) + payload
    ip_nosum = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(udp), ident, 0x4000, 64, 17, 0) + ip_src + ip_dst
    ip = ip_nosum[:10] + struct.pack("!H", checksum(ip_nosum)) + ip_nosum[12:]
    return macs[1] + macs[0] + b"\x08\x00" + ip + udp


def build_session(rng: random.Random, *, init_ip: str, resp_ip: str, encr: int, key_bits: int | None,
                  prf: int, integ: int, dh: int) -> list[bytes]:
    ispi, rspi = rng.randbytes(8), rng.randbytes(8)
    macs_i = (b"\x08\x00\x27" + rng.randbytes(3), b"\x08\x00\x27" + rng.randbytes(3))
    macs_r = (macs_i[1], macs_i[0])
    sa = lambda nxt: sa_payload(nxt, encr, key_bits, prf, integ, dh)
    ke = lambda nxt: generic(nxt, struct.pack("!HH", dh, 0) + rng.randbytes(KE_BYTES[dh]))
    nonce = lambda nxt: generic(nxt, rng.randbytes(32))
    nat = lambda nxt, kind: generic(nxt, struct.pack("!BBH", 0, 0, kind) + rng.randbytes(20))

    def init_msg() -> bytes:
        return sa(34) + ke(40) + nonce(41) + nat(41, 16388) + nat(0, 16389)

    # next_payload fields chain: SA(34 KE) -> KE(40 Ni) -> Ni(41 N) -> N(41 N) -> N(0)
    init_req = ike_header(ispi, b"\0" * 8, 33, 34, 0x08, 0, init_msg())
    init_resp = ike_header(ispi, rspi, 33, 34, 0x20, 0, init_msg())

    def auth_msg(size: int) -> bytes:  # SK payload: IV + ciphertext + ICV, all opaque
        return generic(0, rng.randbytes(size))

    marker = b"\0\0\0\0"  # non-ESP marker, required on UDP 4500
    auth_req = marker + ike_header(ispi, rspi, 46, 35, 0x08, 1, auth_msg(176))
    auth_resp = marker + ike_header(ispi, rspi, 46, 35, 0x20, 1, auth_msg(128))

    return [
        frame(init_ip, resp_ip, 500, 500, init_req, rng.randrange(65536), macs_i),
        frame(resp_ip, init_ip, 500, 500, init_resp, rng.randrange(65536), macs_r),
        frame(init_ip, resp_ip, 4500, 4500, auth_req, rng.randrange(65536), macs_i),
        frame(resp_ip, init_ip, 4500, 4500, auth_resp, rng.randrange(65536), macs_r),
    ]


def write_pcap(path: Path, frames: list[bytes], start: float = 1_767_225_600.0) -> None:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # Ethernet
    for n, data in enumerate(frames):
        ts = start + n * 0.015
        out += struct.pack("<IIII", int(ts), int((ts % 1) * 1_000_000), len(data), len(data)) + data
    path.write_bytes(out)


SCENARIOS = {
    # 3DES (deprecated), HMAC-MD5-96 (forbidden), 1024-bit MODP (forbidden)
    "weak_test.pcap": dict(seed=1001, init_ip="192.0.2.10", resp_ip="192.0.2.20",
                           encr=3, key_bits=None, prf=2, integ=1, dh=2),
    # AES-256-CBC, HMAC-SHA2-384, ECP-384: passes nist-baseline and cnsa-strict
    "secure_test.pcap": dict(seed=2002, init_ip="198.51.100.10", resp_ip="198.51.100.20",
                             encr=12, key_bits=256, prf=6, integ=13, dh=20),
}


def main() -> None:
    for name, cfg in SCENARIOS.items():
        cfg = dict(cfg)
        frames = build_session(random.Random(cfg.pop("seed")), **cfg)
        write_pcap(OUT / name, frames)
        print(f"wrote {OUT / name} ({len(frames)} packets)")


if __name__ == "__main__":
    main()
