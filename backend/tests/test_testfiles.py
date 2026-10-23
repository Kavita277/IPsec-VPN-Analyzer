"""The committed test captures must match their generator and encode the documented parameters."""

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "testfiles"))
import generate_testfiles as gen  # noqa: E402


def _packets(path):
    data = path.read_bytes()
    assert struct.unpack("<I", data[:4])[0] == 0xA1B2C3D4
    pos, out = 24, []
    while pos < len(data):
        _, _, n, _ = struct.unpack("<IIII", data[pos:pos + 16])
        out.append(data[pos + 16:pos + 16 + n])
        pos += 16 + n
    return out


def _transforms(frame):
    ike = frame[14 + 20 + 8:]  # Ethernet + IPv4 + UDP
    assert ike[16] == 33 and ike[17] == 0x20  # next payload SA, IKEv2
    assert struct.unpack("!I", ike[24:28])[0] == len(ike)
    proposal = ike[28 + 4:]
    count = proposal[7]
    pos, found = 8, {}
    for _ in range(count):
        _, _, length, kind, _, ident = struct.unpack("!BBHBBH", proposal[pos:pos + 8])
        found[kind] = ident
        pos += length
    return found


def test_files_match_generator(tmp_path, monkeypatch):
    monkeypatch.setattr(gen, "OUT", tmp_path)
    gen.main()
    for name in gen.SCENARIOS:
        assert (tmp_path / name).read_bytes() == (ROOT / "testfiles" / name).read_bytes()


def test_weak_and_secure_parameters():
    weak = _packets(ROOT / "testfiles" / "weak_test.pcap")
    secure = _packets(ROOT / "testfiles" / "secure_test.pcap")
    assert len(weak) == len(secure) == 4
    assert _transforms(weak[1]) == {gen.ENCR: 3, gen.INTEG: 1, gen.PRF: 2, gen.DH: 2}        # 3DES, MD5, MODP-1024
    assert _transforms(secure[1]) == {gen.ENCR: 12, gen.INTEG: 13, gen.PRF: 6, gen.DH: 20}   # AES-CBC, SHA2-384, ECP-384
