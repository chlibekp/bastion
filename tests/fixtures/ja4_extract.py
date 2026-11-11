#!/usr/bin/env python3 -I
"""Builds tests/fixtures/ja4_vectors.json from a checkout of github.com/FoxIO-LLC/ja4.

usage: ja4_extract.py <ja4-checkout> > tests/fixtures/ja4_vectors.json

For every TCP stream in <checkout>/pcap whose expected output in python/test/testdata/<pcap>.json
carries a "JA4.<n>" key, the ClientHello handshake message (as bytes in hex, without the record
header) is paired with that fingerprint. Only the published fingerprints are used as expected values;
nothing here computes a JA4. QUIC captures are skipped (their ClientHello is encrypted).
"""
import json
import struct
import sys
from pathlib import Path


def packets(data):
    """Yields (linktype, frame) for a pcap or pcapng file."""
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        e = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        link = struct.unpack(e + "I", data[20:24])[0]
        off = 24
        while off + 16 <= len(data):
            _, _, cap, _ = struct.unpack(e + "IIII", data[off:off + 16])
            yield link, data[off + 16:off + 16 + cap]
            off += 16 + cap
        return
    off, links, e = 0, [], "<"
    while off + 12 <= len(data):
        typ, ln = struct.unpack(e + "II", data[off:off + 8])
        body = data[off + 8:off + ln - 4]
        if typ == 0x0A0D0D0A:
            e = "<" if body[:4] == b"\x4d\x3c\x2b\x1a" else ">"
            links = []
        elif typ == 1:
            links.append(struct.unpack(e + "H", body[:2])[0])
        elif typ == 6:
            iface, _, _, cap, _ = struct.unpack(e + "IIIII", body[:20])
            yield links[iface], body[20:20 + cap]
        off += ln


def tcp_payload(link, f):
    if link == 1:
        et, off = struct.unpack(">H", f[12:14])[0], 14
        while et in (0x8100, 0x88A8):
            et, off = struct.unpack(">H", f[off + 2:off + 4])[0], off + 4
    elif link == 113:
        et, off = struct.unpack(">H", f[14:16])[0], 16
    elif link == 101:
        et, off = (0x0800 if f[0] >> 4 == 4 else 0x86DD), 0
    else:
        return None
    if et == 0x0800:
        ihl = (f[off] & 15) * 4
        if f[off + 9] != 6:
            return None
        src = ".".join(map(str, f[off + 12:off + 16]))
        t = off + ihl
    elif et == 0x86DD:
        if f[off + 6] != 6:
            return None
        src = f[off + 8:off + 24].hex()
        t = off + 40
    else:
        return None
    sport, dport = struct.unpack(">HH", f[t:t + 4])
    doff = (f[t + 12] >> 4) * 4
    return src, str(sport), str(dport), f[t + doff:]


def main(root):
    root = Path(root)
    out = []
    for exp in sorted((root / "python/test/testdata").glob("*.json")):
        want = {}
        for e in json.loads(exp.read_text()):
            for k, v in e.items():
                if k.startswith("JA4.") and "srcport" in e:
                    want.setdefault((e["src"], e["srcport"], e["dstport"]), []).append(v)
        if not want:
            continue
        pcap = root / "pcap" / exp.name[:-5]
        if not pcap.exists():
            continue
        seen = {}
        for link, f in packets(pcap.read_bytes()):
            r = tcp_payload(link, f)
            if r is None or len(r[3]) < 9:
                continue
            src, sp, dp, p = r
            key = (src, sp, dp)
            if key not in want or key in seen:
                continue
            if p[0] == 0x16 and p[5] == 1:
                n = int.from_bytes(p[6:9], "big")
                if 5 + 4 + n <= len(p):  # the whole hello in the first segment
                    seen[key] = p[5:9 + n]
        for key, hello in seen.items():
            if any(o["hello"] == hello.hex() for o in out):
                continue  # the same capture appears under several names
            out.append({"source": pcap.name, "stream": "%s:%s>%s" % key, "ja4": want[key][0],
                        "hello": hello.hex()})
    json.dump(out, sys.stdout, indent=1)
    print()


main(sys.argv[1])
