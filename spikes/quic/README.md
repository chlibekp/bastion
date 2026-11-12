# QUIC backend and 0-RTT spike (Phase 8, Task 1)

Throwaway code, not part of the release build. `spike.c` is a minimal HTTP/3 server on the pinned
ngtcp2 1.26.0 (`ngtcp2_crypto_ossl`), nghttp3 1.19.0 and OpenSSL 3.5.9: one UDP socket, poll(2),
every request answered 200 with a body naming what the TLS layer saw. It decides the approach of
Tasks 3 and 6. The client is `tests/fixtures/h3client.c` (kept: the integration tests use it).

```
./dev bash -c 'tests/fixtures/certs/gen.sh build/spike >/dev/null
  F=$(PKG_CONFIG_PATH=$PWD/build/deps/aarch64-glibc/lib/pkgconfig pkg-config --static --cflags --libs \
     libngtcp2_crypto_ossl libngtcp2 libnghttp3 openssl)
  clang -O1 -D_GNU_SOURCE spikes/quic/spike.c $F -o build/spike/quic
  clang -O1 -D_GNU_SOURCE tests/fixtures/h3client.c $F -o build/spike/h3client
  cd build/spike; K=$(openssl rand -hex 80)
  ./quic ecdsa.crt ecdsa.key 4433 $K & ./quic ecdsa.crt ecdsa.key 4434 $K & sleep 0.5
  curl -sk --http3-only https://localhost:4433/
  ./h3client --print-body --session s --wait-ticket 127.0.0.1 4433 /
  ./h3client --print-body --session s --early 127.0.0.1 4434 /'
```

Environment: Docker Desktop (arm64), Debian trixie dev image, curl 8.14.1 (HTTP/3 through OpenSSL's
own QUIC client and nghttp3 1.8), and the Alpine release image for musl.

## Findings

1. **Build (Step 1).** The pinned ngtcp2 with `--with-openssl` builds `libngtcp2_crypto_ossl.a` against
   the pinned OpenSSL, static, on glibc (`build/deps/aarch64-glibc`) and on musl
   (`build/deps/aarch64-musl`, `./dev make deps BUILD=release`). The spike links `-static` on both
   and serves `curl --http3-only` from the glibc static binary. No patch was needed. ngtcp2 still
   calls this backend "experimental" in its README; the restrictions it lists (keep `ngtcp2_conn`
   alive until the `SSL` is freed, keep the transport parameter buffer) are met by freeing in that
   order.
2. **Handshake (Step 2).** `curl --http3-only` and the ngtcp2-based test client both complete the
   handshake with ALPN `h3` and group **X25519MLKEM768**; with `--curves X25519` the group is x25519.
   ngtcp2's own example client (`osslclient`) was **NOT executed**: it needs libev headers, which the
   dev image does not have; `tests/fixtures/h3client.c` (same library, same backend) replaces it.
3. **A ClientHello in two Initials forces a Retry.** With X25519MLKEM768 the ClientHello is larger
   than one Initial. For both clients the first Initial the server reads does not carry CRYPTO
   offset 0, and `ngtcp2_conn_read_pkt` returns `NGTCP2_ERR_RETRY` (ngtcp2 buffers out-of-order
   crypto data only for a validated address). The server must answer with a Retry and drop the
   connection state; the client's next Initial carries the token and the handshake completes (one
   extra round trip). A single-packet ClientHello (x25519) needs no Retry. Consequence for Task 3:
   the endpoint sends a Retry on `NGTCP2_ERR_RETRY` whatever `quic_retry` says, and `quic_retry never`
   means "never on our own initiative"; documented in `docs/conformance.md`.
4. **0-RTT works on this backend (Step 3)**, with two server-side requirements:
   `SSL_CTX_set_max_early_data(ctx, 0xffffffff)` (RFC 9001 section 4.6.1; OpenSSL refuses any other
   non-zero value for QUIC) **and** `SSL_set_quic_tls_early_data_enabled(ssl, 1)` per connection.
   Without the second call every 0-RTT attempt is rejected. Measured: a resumed connection with
   `--early` gets `SSL_EARLY_DATA_ACCEPTED`, and its request is answered from 0-RTT, also after a Retry
   (the client resends the 0-RTT packets). So Task 6 ships HTTP/3 0-RTT.
5. **Anti-replay hook works in QUIC mode.** `SSL_CTX_set_allow_early_data_cb` is called for QUIC
   handshakes too: with the callback refusing (`SPIKE_DENY_EARLY=1`), the same resumed connection
   reports `early=rejected` and the request is still served after the handshake. Without it a
   replayed ticket is accepted every time (measured three times). Task 6 therefore installs Phase 6's
   `bst_early_allow` on the QUIC contexts, so the shared fingerprint table covers QUIC and TCP alike.
6. **Ticket keys across workers (Step 4).** Two spike processes with the same ticket key callback
   (`SSL_CTX_set_tlsext_ticket_key_evp_cb`, the mechanism Phase 6 `bst_tickets_ctx` installs) resume
   each other's tickets, with 0-RTT accepted on the other process. So QUIC contexts take the Phase 6
   callback unchanged and resumption works across workers with no new shared state. TCP and QUIC
   tickets must not cross: a TCP ticket carries a TCP `max_early_data` that OpenSSL refuses for QUIC.
   The QUIC context therefore uses its own session id context (the TCP one with a QUIC marker mixed
   in), which makes OpenSSL ignore the other transport's tickets (full handshake, no failure).
7. **QUIC v2.** With `available_versions` {v2, v1} and v2 preferred, an ngtcp2 client that starts in
   v1 is moved to v2 by compatible version negotiation (RFC 9368/9369, `version=0x6b3343cf`); curl
   offers only v1 and stays on v1.
8. **Separate SSL_CTX for QUIC.** The QUIC context differs from the TCP one in ALPN (`h3` only),
   TLS 1.3 only, `max_early_data` and the session id context, and `ngtcp2_crypto_ossl` installs its
   own record-layer callbacks per `SSL`. Task 3 builds one QUIC context per server with
   `bst_tls_ctx_build` plus a QUIC flag, sharing certificates, SNI callback, OCSP and ticket callback.
