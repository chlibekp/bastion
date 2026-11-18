# Spike: XDP SYN cookies (Phase 13, Task 8)

**Status: NOT executed. The directive is not shipped.**

## What the spike was to establish

On the VM kernel (`make test-vm`, floor 6.1 and current), answer a SYN with a cookie SYN-ACK built
in XDP with `bpf_tcp_raw_gen_syncookie_ipv4`/`_ipv6` and sent back with `XDP_TX`, and check that the
kernel accepts the client's returned ACK under `net.ipv4.tcp_syncookies=2`. Record which TCP
options survive the cookie (MSS only, or window scale, SACK and timestamps through the timestamp
encoding), and how `TCP_FASTOPEN` and `TCP_DEFER_ACCEPT` behave behind it.

## Why it was not run

The Phase 13 run that built Tasks 1 to 7 and 9 did not have the time for it: it needs a
hand-built SYN-ACK path (Ethernet and IP address swap, VLAN tags kept, TCP and IP checksums, the
cookie helpers) plus a guest-side client harness, all of it under TCG emulation, which makes each
attempt slow. No part of it was attempted, so there is no evidence either way about whether XDP SYN
cookies work reliably on the supported kernels.

## Decision

The plan's own fallback applies: **no `syn_cookies` directive**. SYN floods are handled by

1. the kernel's own SYN cookies (`net.ipv4.tcp_syncookies=1`, the default on Debian and most
   distributions: cookies once the SYN queue overflows), and
2. the XDP per-source SYN rate limit (`syn_rate`, Task 4), plus `deny` lists and escalation blocks
   in XDP (Tasks 3 and 7), which drop a flood's packets before the TCP stack sees them.

The spoofed-source case (100,000 SYNs from random addresses) is what per-source limits can not
stop; there the kernel's cookies keep the listen queue from filling, at the cost of the SYN-ACK
traffic the kernel sends. `docs/conformance.md` records this.

The `doctor` check of `net.ipv4.tcp_syncookies` is not added either: `doctor` is a Phase 14
command.

## To pick it up

Run the steps above in `tests/vm/` (the guest has root, veths and a stock kernel). If the cookie
handshake works on both kernels, implement `syn_cookies off|on|auto` with
`syn_cookie_threshold`, and the tests listed in `docs/implementation-plan/13-xdp.md` Task 8.
