# Third-party material

Notes on code, specifications and test data that Bastion takes from elsewhere, and the terms they
come with. Linked libraries and their pinned versions are in `deps/versions.env`.

## JA4 (TLS client fingerprint)

`src/tls/ja4.{c,h}` implement the **JA4** TLS client fingerprint of FoxIO, LLC, from the written
specification in `technical_details/JA4.md` of https://github.com/FoxIO-LLC/ja4. The code is written
here; no source of the reference tools was copied.

- Licence: JA4 (and only JA4) is under the 3-clause BSD licence of `LICENSE-JA4` in that repository:
  "Copyright (c) 2026 FoxIO. All rights reserved." Redistribution and use in source and binary forms are
  permitted provided that the copyright notice, the conditions and the disclaimer are retained in source
  and reproduced in binary distributions, and the name of FoxIO or its contributors is not used to
  endorse or promote products derived from the software without written permission. The licence text
  is reproduced in full in the repository above and in the upstream file named here; ship it with any
  binary distribution that includes `ja4.c`.
- Not implemented: **JA4+** (JA4S, JA4H, JA4L, JA4LS, JA4X, JA4T, JA4TS, JA4TScan, JA4D, JA4D6, JA4SScan,
  JA4E, JA4SSH). These are under the separate FoxIO License 1.1 (`LICENSE` in that repository), which
  restricts commercial use. Bastion does not include them and must not gain them without a licence
  review.
- Test vectors: `tests/fixtures/ja4_vectors.json` holds 88 distinct ClientHello messages taken from the
  `pcap/` captures of that repository, each with the fingerprint published for it in
  `python/test/testdata/*.json` (`JA4.<n>`). Source commit: `c6469a7b0dbf8fe963810162429fbfd9d1acc4d5`.
  Regenerate with `tests/fixtures/ja4_extract.py <checkout>`. The captures are third-party data and are
  used only as test input.
- One documented difference: when the first ALPN name starts or ends with a byte that is not an ASCII
  letter or digit, the written spec prints the first and last hex digit of the name, while the Python and
  Rust reference tools print `9`. Bastion follows the written spec (`non_ascii_alpn` in
  `tests/unit/test_ja4.c`); the capture `tls-non-ascii-alpn.pcapng` is the one vector where the two differ.
