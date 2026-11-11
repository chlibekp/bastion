#!/usr/bin/env python3
"""Generates src/http/h2/huffman_table.inc: the HPACK Huffman code (RFC 7541 Appendix B) and a
nibble-driven decoder for it.

The RFC code is canonical: codes are assigned in order of (length, symbol), so the 257 code
lengths below define it completely. The script checks that they form a complete prefix code
(Kraft sum exactly 1), that EOS is the 30-bit all-ones code, and a set of codes quoted verbatim
from the RFC table, then writes:

  hpack_huff_enc[257]   {code, length} per symbol
  hpack_huff_dec[256][16]  per (state, nibble): next state, flags, emitted symbol
  hpack_huff_accept[256]   states in which the input may end (a prefix of EOS of at most 7 bits)

Run: ./dev make gen-huffman
"""
import sys

LENGTHS = (
    # 0-31
    [13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
     28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28]
    # 32-63: space ! " # $ % & ' ( ) * + , - . / 0-9 : ; < = > ?
    + [6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
       5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10]
    # 64-95: @ A-Z [ \ ] ^ _
    + [13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
       7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6]
    # 96-127: ` a-z { | } ~ DEL
    + [15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
       6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28]
    # 128-255
    + [20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
       24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
       22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
       21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
       26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
       19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
       20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
       26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26]
    # 256: EOS
    + [30]
)

# Codes quoted from RFC 7541 Appendix B, as (symbol, code, length).
KNOWN = [
    (0, 0x1ff8, 13), (1, 0x7fffd8, 23), (2, 0xfffffe2, 28), (9, 0xffffea, 24),
    (10, 0x3ffffffc, 30), (13, 0x3ffffffd, 30), (22, 0x3ffffffe, 30),
    (32, 0x14, 6), (33, 0x3f8, 10), (34, 0x3f9, 10), (35, 0xffa, 12), (36, 0x1ff9, 13),
    (37, 0x15, 6), (38, 0xf8, 8), (39, 0x7fa, 11), (42, 0xf9, 8), (44, 0xfa, 8),
    (48, 0x0, 5), (49, 0x1, 5), (50, 0x2, 5), (58, 0x5c, 7), (59, 0xfb, 8), (60, 0x7ffc, 15),
    (61, 0x20, 6), (62, 0xffb, 12), (63, 0x3fc, 10), (64, 0x1ffa, 13), (65, 0x21, 6),
    (66, 0x5d, 7), (88, 0xfc, 8), (90, 0xfd, 8), (91, 0x1ffb, 13), (92, 0x7fff0, 19),
    (93, 0x1ffc, 13), (94, 0x3ffc, 14), (95, 0x22, 6), (96, 0x7ffd, 15), (97, 0x3, 5),
    (101, 0x5, 5), (115, 0x8, 5), (116, 0x9, 5), (122, 0x7b, 7), (123, 0x7ffe, 15),
    (124, 0x7fc, 11), (125, 0x3ffd, 14), (126, 0x1ffd, 13), (127, 0xffffffc, 28),
    (128, 0xfffe6, 20), (162, 0xfffe9, 20), (195, 0x7fff1, 19), (208, 0x7fff2, 19),
    (220, 0xffffffd, 28), (249, 0xffffffe, 28), (256, 0x3fffffff, 30),
]


def main():
    assert len(LENGTHS) == 257, len(LENGTHS)
    kraft = sum(1 << (30 - n) for n in LENGTHS)
    assert kraft == 1 << 30, "code lengths are not a complete prefix code: %d" % kraft
    order = sorted(range(257), key=lambda s: (LENGTHS[s], s))
    codes = [0] * 257
    code, prev = 0, LENGTHS[order[0]]
    for s in order:
        code <<= LENGTHS[s] - prev
        prev = LENGTHS[s]
        codes[s] = code
        code += 1
    assert codes[256] == (1 << 30) - 1
    for s, c, n in KNOWN:
        assert LENGTHS[s] == n and codes[s] == c, "symbol %d: have %x/%d, RFC %x/%d" % (
            s, codes[s], LENGTHS[s], c, n)

    # The trie: node = [child0, child1]; a leaf is ("sym", n).
    nodes = [[None, None]]
    for s in range(257):
        node = 0
        for i in range(LENGTHS[s] - 1, -1, -1):
            bit = (codes[s] >> i) & 1
            if i == 0:
                nodes[node][bit] = ("sym", s)
            else:
                nxt = nodes[node][bit]
                if nxt is None:
                    nodes.append([None, None])
                    nxt = len(nodes) - 1
                    nodes[node][bit] = nxt
                node = nxt
    assert len(nodes) == 256, len(nodes)
    for n in nodes:
        assert n[0] is not None and n[1] is not None

    dec = []
    for st in range(256):
        row = []
        for nib in range(16):
            node, emit, fail = st, 0, 0
            for i in range(3, -1, -1):
                child = nodes[node][(nib >> i) & 1]
                if isinstance(child, tuple):
                    assert emit == 0, "two symbols in one nibble"
                    if child[1] == 256:
                        fail = 1
                    else:
                        emit = child[1] + 1000  # marks "emitted"
                    node = 0
                else:
                    node = child
            row.append((node, 1 if emit else 0, fail, (emit - 1000) if emit else 0))
        dec.append(row)
    accept = [0] * 256
    node = 0
    accept[0] = 1
    for depth in range(1, 8):
        node = nodes[node][1]
        assert not isinstance(node, tuple)
        accept[node] = 1

    out = []
    out.append("/* Generated by scripts/gen-huffman.py from the RFC 7541 Appendix B code lengths: do not edit. */\n")
    out.append("static const struct { uint32_t code; uint8_t len; } hpack_huff_enc[257] = {\n")
    for s in range(257):
        out.append("\t{ 0x%x, %d },%s" % (codes[s], LENGTHS[s], "\n" if s % 4 == 3 or s == 256 else " "))
    out.append("};\n\n")
    out.append("/* flags: 1 = a symbol is emitted, 2 = failure (EOS) */\n")
    out.append("static const struct { uint8_t next, flags, sym; } hpack_huff_dec[256][16] = {\n")
    for st in range(256):
        out.append("\t{ ")
        for node, emit, fail, sym in dec[st]:
            out.append("{ %d, %d, %d }, " % (node, emit | (fail << 1), sym))
        out.append("},\n")
    out.append("};\n\n")
    out.append("static const uint8_t hpack_huff_accept[256] = { ")
    out.append(", ".join(str(a) for a in accept))
    out.append(" };\n")
    path = sys.argv[1] if len(sys.argv) > 1 else "src/http/h2/huffman_table.inc"
    with open(path, "w") as f:
        f.write("".join(out))
    print("wrote", path)


if __name__ == "__main__":
    main()
