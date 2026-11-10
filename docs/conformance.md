# HTTP/1.1 conformance

`tests/conformance/h1_rfc_requirements.yaml` lists requirements a server has to meet under RFC 9110
and RFC 9112, one entry each, with the section it comes from, the wording level (MUST, SHOULD,
MAY), the raw request bytes, and what must come back. `make conformance K=h1` sends every entry
to the real binary, on both the epoll and io_uring backends, with the worker sandboxed, and fails
on any entry that is not met. Later phases add their own corpora to the same target.

```
./dev make conformance K=h1
```

The corpus is a list of flat mappings written in the YAML subset described at the top of the file,
so any YAML tool can read it and the suite needs no YAML library. An entry whose `status` or
`close` shows Bastion differing from the requirement carries a `deviation:` line and is listed
below; there are none today.

## What is covered

| Area | Entries | RFC sections |
|---|---|---|
| Message parsing: line endings, NUL, bare CR, version | 9 | 9112 2.2, 2.3 |
| Request line and request-target: methods, 414, forms, Host | 18 | 9112 3, 3.2; 9110 9.1 |
| Fields: whitespace before the colon, obs-fold, counts and sizes | 7 | 9112 5; 6585 5 |
| Body framing: Transfer-Encoding and Content-Length | 12 | 9112 6.1 to 6.3 |
| Chunked bodies: extensions, trailers, overflow | 6 | 9112 7.1 |
| Connections: persistence, close, pipelining, error closes | 6 | 9112 9.3, 9.6 |
| Semantics: Date, 405 and Allow, HEAD, 204, 304, Expect | 10 | 9110 6.6.1, 8.6, 9.3, 10.1.1, 15 |

68 entries in all. The count comes from the file: `test_corpus_is_well_formed` fails when an id repeats, a required
field is missing, or there are fewer than 50 entries.

## Choices the RFCs leave open

These are not deviations (the requirement is MAY or SHOULD, or a MUST that allows either of two
behaviours) but a reader comparing with another server will see them:

- **Bare LF.** RFC 9112 section 2.2 allows a recipient to take a lone LF as a line ending.
  Bastion answers 400 unless `http1_allow_bare_lf on`, because proxies that disagree about line
  endings enable request smuggling.
- **Both Content-Length and Transfer-Encoding.** Section 6.1 allows rejecting or processing with
  the Transfer-Encoding winning, then closing. Bastion rejects with 400 and closes.
- **Repeated or listed Content-Length.** Section 6.3 lets a recipient accept a list of equal
  values. Bastion refuses every duplicate and every list, equal or not.
- **Obsolete line folding.** Section 5.2 allows rejecting or replacing each fold with SP.
  Bastion rejects with 400.
- **Transfer codings.** Only `chunked` is understood. A list ending in `chunked` after another
  coding is answered 501, a list that does not end in `chunked` 400 (both close).
- **HTTP/1.x minors.** A request with a minor above 1 is treated as HTTP/1.1 (section 2.3);
  `http/1.1` in lower case is not a version and is answered 400.
- **Absolute-form and Host.** An absolute-form target wins over a disagreeing Host (section
  3.2.2); userinfo in either is refused.
- **Close after a refusal.** A refused request whose framing is sound (405, 417) keeps the
  connection when it had no body; every other error closes it, because the bytes after it cannot
  be trusted to start a request.

## Not covered yet

Range and conditional requests, caching, `Upgrade`, `Content-Encoding`, and the request-target
forms that need routing arrive with the phases that implement them (5 onwards) and their corpora.
`TRACE` and `CONNECT` are answered 405 with `Allow` until a phase serves them.

## Differential check

`tests/conformance/h1_vs_nginx.py` sends the same requests to Bastion and to an nginx on `PATH`
and prints the entries where the two statuses differ. It is for a person to read and never fails:
nginx is not the standard, and some differences are Bastion being stricter on purpose. It needs
nginx, which the development image does not carry, so it prints a note and stops there.
