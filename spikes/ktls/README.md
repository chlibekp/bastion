# kTLS behaviour spike (Phase 6, Task 1)

Throwaway code, not part of the release build. `spike.c` forks a blocking OpenSSL client and a
non-blocking OpenSSL server (socket BIO, `SSL_OP_ENABLE_KTLS`) over loopback TCP and prints what the
server observes. It decides the kTLS defaults of Task 4.

Run in the VM tier (Docker Desktop's kernel has no `CONFIG_TLS`):

```
./dev bash -c 'tests/fixtures/certs/gen.sh build/spike >/dev/null
  clang -O1 -D_GNU_SOURCE spikes/ktls/spike.c $(PKG_CONFIG_PATH=$PWD/build/deps/aarch64-glibc/lib/pkgconfig \
     pkg-config --cflags --libs --static openssl) -o build/spike/ktls
  scripts/vm-run.sh bash -c "modprobe tls gcm ctr ghash_generic aes_ti chacha20poly1305; \
     cd build/spike; ./ktls matrix ecdsa.crt ecdsa.key"'
```

Environment: Debian 6.12.107 (trixie) arm64 kernel in QEMU TCG (no KVM), OpenSSL 3.5.9 built with
`enable-ktls`, static. `SPIKE_NORX=1` selects kTLS TX only (see below).

## Findings

1. **Kernel crypto modules are part of the requirement.** `modprobe tls` is not enough: a
   `setsockopt(SOL_TLS, TLS_TX)` fails with `ENOENT` until `gcm(aes)` and, for ChaCha, `chacha20poly1305`
   are registered. OpenSSL then falls back to user space **silently** (`BIO_get_ktls_send` is 0, no
   error), so Bastion must detect it itself and warn (Task 4). The VM tests load
   `tls gcm ctr ghash_generic aes_ti chacha20poly1305 chacha_generic poly1305_generic`.
2. **Activation matrix** (server side, `BIO_get_ktls_send` / `BIO_get_ktls_recv`), all with
   `SSL_OP_ENABLE_KTLS`: TLS 1.2 and TLS 1.3 times AES-128-GCM, AES-256-GCM and CHACHA20-POLY1305 all
   give **tx=1 rx=1**. `/proc/net/tls_stat` counts `TlsTxSw`/`TlsRxSw` 6 and 6.
3. **OpenSSL 3.5 has no per-direction option** (`SSL_OP_NO_RX_KTLS` does not exist): `ENABLE_KTLS`
   turns on RX too. TLS 1.3 installs the write key with the server Finished and the read key only after
   the client Finished, so an info callback that clears `SSL_OP_ENABLE_KTLS` once
   `BIO_get_ktls_send` is true leaves RX in user space: measured **tx=1 rx=0** for all three TLS 1.3
   ciphers. TLS 1.2 installs RX first, so there RX goes to the kernel as well (**tx=1 rx=1**); that is
   harmless, since TLS 1.2 has no KeyUpdate and renegotiation is off.
4. **Client KeyUpdate** (TLS 1.3):
   - kTLS RX active (`tx+rx`): any client KeyUpdate, requested or not, fails the next read with
     `SSL_ERROR_SSL` (`ssl_set_new_record_layer: no suitable record layer`). The connection ends.
   - kTLS TX only: `KeyUpdate(update_not_requested)` is handled in user space, both directions keep
     working (**read=3, write ok**). `KeyUpdate(update_requested)` needs the server to rekey its sending
     direction, which a kTLS TX socket cannot do: the server's next write fails with `SSL_ERROR_SSL`
     (same reason string) and the client sees the failure.
   - Defined behaviour: an immediate error on the next read or write, never a hang. Task 4 checks
     with a packet capture that nothing follows in the clear, and closes the connection and counts it
     (`bastion_tls_ktls_keyupdate_closed_total`).
5. **NewSessionTicket under kTLS TX**: written without error (tickets go out through the kernel with
   the application traffic key). Resumption itself needs shared ticket keys (Task 6).
6. **Alerts**: a client `close_notify` with RX in the kernel (and with RX in user space) reads as
   `SSL_ERROR_ZERO_RETURN` on the server. `SSL_shutdown` after the peer has gone away returns -1 or 1
   depending on the race with the client's exit; Bastion treats the shutdown result as advisory.
7. **`SSL_sendfile` and `sendfile(2)`**: both deliver an 8 MiB file byte-identical under kTLS TX
   (0.436 s and 0.435 s in this VM). Direct `sendfile(2)` on the socket therefore works and is what
   `bst_io_send` already does, so Bastion needs no `SSL_sendfile` and can keep its io_uring splice and
   sendfile paths. (`SSL_sendfile` without kTLS fails with `uninitialized`.)
8. **Throughput** (20000 x 1 KiB request/response, then 64 MiB each way, one connection, QEMU TCG with
   software AES in the guest kernel against emulated ARMv8 crypto instructions in user space):

   | mode | small responses | download | upload |
   |---|---|---|---|
   | user-space TLS | 1786 req/s | 91.9 MiB/s | 86.4 MiB/s |
   | kTLS TX (RX in user space) | 418 req/s | 18.0 MiB/s | 88.8 MiB/s |
   | kTLS TX+RX | 413 req/s | 17.7 MiB/s | 17.2 MiB/s |

   These numbers show only relative trends and here they mostly measure the emulator: the guest kernel
   uses generic AES (`aes_ti`) while user-space OpenSSL uses the emulated crypto extension. kTLS RX
   costs the upload what it costs the download, and TX-only leaves uploads at user-space speed. They
   say nothing about real hardware; `docs/tuning.md` carries the comparison that Task 11 reruns.

## Decisions (used by Task 4)

- **Default `ktls tx`**, as architecture section 6 says. RX is not recommended: any client
  KeyUpdate kills a `tx+rx` connection, and the only measured benefit of RX is CPU in the kernel.
  `tx+rx` stays selectable.
- `ktls tx` is implemented as `SSL_OP_ENABLE_KTLS` plus an info callback that clears the option
  after TX is up on TLS 1.3 (finding 3). Metrics label connections by what actually activated
  (`tx` or `tx+rx`).
- A client `KeyUpdate(update_requested)` on a kTLS TX connection closes it (finding 4). Plain
  `KeyUpdate` works with `tx`.
- Detection of "kTLS did not activate" is `BIO_get_ktls_send`, once per connection after the
  handshake, with one warning per start (finding 1). `require` turns it into a startup error: the
  kernel capability is probed in master with a throwaway loopback connection.
- Files go through plain `bst_io_send` (sendfile or splice) when TX is active (finding 7).
- Architecture section 6 stands: no contradiction was found. Section 6 gains a note on the
  KeyUpdate behaviour and the module requirement.
