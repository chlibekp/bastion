# XDP packet filtering

The `xdp {}` block loads an XDP program that drops attack traffic in the network driver (or the
kernel's generic XDP hook) before the network stack spends anything on it. It is the outermost of
Bastion's DDoS layers; [DDoS protection](ddos.md) shows how it fits with the others. Without this
block no BPF program is loaded for filtering.

## Requirements

- `CAP_BPF` and `CAP_NET_ADMIN` in master at start. The packaged systemd unit grants both; a server
  without `xdp {}` (and with `quic_routing hash`) can drop them in a drop-in.
- A kernel with XDP and BPF links. `bastion doctor` reports whether BPF is loadable and the JIT on.
- A bpffs mount (normally `/sys/fs/bpf`) to pin the filter, so it survives a crash and is handed
  over across reloads and upgrades without a gap.

Without the privileges or kernel support, master logs a warning and runs without the filter.
Every request-level limit still applies. `mode ... require` turns a refused mode into a startup
error instead (see [modes](#attach-modes)).

## A first configuration

```conf
xdp {
    interface eth0;
    syn_rate 200/s burst=400;
    udp_rate 1000/s burst=2000;
    deny_file /etc/bastion/blocklist.txt;
    allow 198.51.100.0/24;
}
server { listen 80; root /srv/www; }
```

Master loads the program, fills its maps from the block and attaches it to every `interface` (up
to 8). Workers never touch it.

## What it checks

The filter looks only at traffic to **protected ports**: the ports Bastion listens on.

| Check | Directive | Default |
|---|---|---|
| Sources always passed: every later check skipped, never blocked by escalation | `allow`, `allow_file` | none |
| Sources always dropped (longest prefix match) | `deny`, `deny_file` | none |
| Escalation and admin blocks | from `escalate` and `bastionctl block` | active |
| New TCP connections (SYN without ACK) per source | `syn_rate <rate> [burst=n]` | off |
| UDP datagrams per source, to `http3` ports | `udp_rate <rate> [burst=n]` | off |
| All packets per source | `pps_rate <rate> [burst=n]` | off |
| Null, xmas, SYN+FIN and SYN+RST segments | `drop_bad_tcp_flags` | on |
| UDP from amplification source ports | `drop_reflection`, `reflection_ports` | on |
| Datagrams that cannot be QUIC on `http3` ports | `quic_check` | on |
| TCP and UDP to ports Bastion does not listen on | `drop_unprotected` | off |
| IP fragments | `drop_fragments` | off |
| IPv6 packets with more than 6 extension headers | `drop_v6_ext` | off |

`allow` wins over `deny`. List files hold one address or CIDR per line, with `#` comments.

**Rates.** The rate buckets are per CPU: the configured total is divided by the number of online
CPUs, so a source whose packets spread over several CPUs can get up to the total on each. IPv6
sources share buckets and auto blocks by `ipv6_prefix` (48, 56, 64 by default, or 128).

**Reflection ports.** `drop_reflection` drops UDP from these source ports to protected ports:
53, 123, 389, 1900, 11211, 19, 161, 111, 137, 5353, 3702, 3283, 5683 and 10001.
`reflection_ports` replaces the list. Replies to Bastion's own queries (DNS for upstreams, OCSP,
ACME) go to ephemeral ports and are not affected.

**QUIC check.** On `http3` ports, a datagram with the QUIC fixed bit clear, or a v1 or v2 Initial
under 1200 bytes, is dropped. Unknown versions pass, so version negotiation still works. It does
nothing without an `http3` listener.

## Automatic blocks

```conf
xdp {
    interface eth0;
    syn_rate 200/s burst=400;
    auto_block after=50 for=10s;
}
server { listen 80; root /srv/www; }
```

`auto_block after=N for=D` (off by default) blocks a source in XDP for `D` (default 10s, at most
1h) when a rate limit drops it `N` times within a second. Spoofed packets can trigger it, so it
only ever blocks that source key (an address, or an IPv6 prefix), briefly, and `allow` always
wins.

Escalation from request-level rules (`escalate` in a `limit_zone`, `waf_rule` or `http2_abuse`)
also lands in the XDP block map, but only for peers that completed a handshake, and never for an
address learnt from a PROXY header or `real_ip_header`
([access control](access-control.md#escalation-to-blocks)).

## Attach modes

```nginx
mode <auto|native|generic|hw> [require];
```

| `mode` | Meaning |
|---|---|
| `auto` (default) | native (in the driver) if the driver supports it, else generic |
| `native` | in the driver; the fastest |
| `generic` | the kernel's generic hook, after the driver allocated the packet: works everywhere, costs more |
| `hw` | offload to the NIC; **untested**, no such NIC was available |

A mode the driver refuses falls back to generic with a warning; with `require`, it is a startup
error.

## Pinning, crashes and restarts

When `pin_path` (default `/sys/fs/bpf/bastion`) is on a bpffs mount, each interface's link is pinned
at `<pin_path>/link_<ifname>` and every map beside it.

- A pinned link outlives the process. After a crash the filter keeps running with its last maps,
  and the next start adopts it, swapping its own program in with no gap.
- A reload adopts the pinned filter; the new configuration's lists replace the pinned ones in
  place.
- A live upgrade hands the filter to the new master through the pins, and a rollback takes it back.
- On a clean stop, `on_exit detach` (the default) removes the pins and links, so traffic is no
  longer filtered. `on_exit keep` leaves the filter running with its static lists until the next
  start adopts it; dynamic blocks expire by their TTL.

Without bpffs nothing is pinned: the links end with master whatever `on_exit` says (logged), and a
reload has a short window with no filter.

## SYN floods

There are no SYN cookies in XDP: the directive planned for them does not exist
([conformance](../conformance.md#syn-floods-kernel-syn-cookies-not-xdp-syn-cookies)). SYN floods
are met by the kernel's own SYN cookies (`net.ipv4.tcp_syncookies`, which `bastion doctor`
checks), the per-source `syn_rate`, and deny lists and blocks in XDP. A flood from spoofed sources
is left to the kernel's cookies.

## Watching it

`bastion_xdp_packets_total{reason}` counts what the filter passed or dropped. Master polls the
counts once a second and logs an `xdp: stats` line when a drop count moved (at most one a second,
so a flood cannot flood the log).

| `reason` | Meaning |
|---|---|
| `pass` | passed all checks |
| `allow` | passed by an allow rule |
| `non_ip` | not IPv4 or IPv6 |
| `malformed` | headers that do not parse |
| `tcp_flags` | `drop_bad_tcp_flags` |
| `fragment` | `drop_fragments` |
| `deny` | a deny rule |
| `blocked` | an escalation or admin block |
| `unprotected` | `drop_unprotected` |
| `syn_rate`, `udp_rate`, `pps_rate` | over a rate |
| `reflection` | `drop_reflection` |
| `quic` | `quic_check` |
| `v6_ext` | `drop_v6_ext` |
| `auto_blocked` | an `auto_block` block |

`bastionctl blocks` lists the blocks the XDP maps really hold.

## All directives

| Directive | Default | Meaning |
|---|---|---|
| `interface` | none | interfaces to attach to (repeatable, up to 8) |
| `mode` | `auto` | see [attach modes](#attach-modes) |
| `pin_path` | `/sys/fs/bpf/bastion` | bpffs directory for pinned links and maps |
| `on_exit` | `detach` | `detach` or `keep` on a clean stop |
| `allow`, `allow_file` | none | sources never dropped |
| `deny`, `deny_file` | none | sources always dropped |
| `syn_rate`, `udp_rate`, `pps_rate` | off | per-source rates, `<rate> [burst=n]` |
| `ipv6_prefix` | `64` | IPv6 source key: 48, 56, 64 or 128 |
| `auto_block` | off | `after=n for=duration` |
| `drop_bad_tcp_flags` | `on` | bad TCP flag combinations |
| `drop_reflection` | `on` | UDP from amplification ports |
| `reflection_ports` | the list above | replaces the list |
| `quic_check` | `on` | invalid QUIC on `http3` ports |
| `drop_unprotected` | `off` | traffic to ports Bastion does not listen on |
| `drop_fragments` | `off` | IP fragments |
| `drop_v6_ext` | `off` | IPv6 with more than 6 extension headers |

The [reference](../config-reference.md#xdp) has the full text. The XDP unit suites run in the VM
tier ([testing](../testing.md#vm-tests)), and the flood tests use the test-only `synflood` and
`udpflood` generators in the integration tier.
