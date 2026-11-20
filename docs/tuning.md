# Tuning

## Start with `bastion doctor`

`bastion doctor [-c file]` prints what this host offers, one row per check, with a status and the
recommended value: kernel version, io_uring (and NAPI busy poll), kTLS, BPF/XDP, Landlock,
seccomp, BBR, `busy_poll`, `tcp_syncookies`, `somaxconn`, `tcp_max_syn_backlog`, file
descriptor limits, CPUs, NUMA nodes and transparent huge pages. It only reads `/proc`, `/sys` and
its own limits, and probes by creating and freeing an io_uring and a BPF program: it never
changes a setting. With `-c`, it also checks every `require` of the configuration (`uring_napi on
require`, `ktls ... require`, `landlock ... require`, `seccomp ... require`) and exits 1 when one
would fail here; 2 is a usage or configuration error.

Sysctls it recommends are yours to set (for example in `/etc/sysctl.d/`): Bastion never writes
them.

## CPUs, NUMA and steering

| directive | effect |
|---|---|
| `workers auto` | one worker per CPU this process may use (its cpuset, not every online CPU) |
| `worker_cpu_affinity auto` | worker slot i is pinned to the i-th allowed CPU, modulo their count |
| `worker_cpu_affinity 0 2 4-7` | slot i on the i-th listed CPU, modulo the list; a CPU outside the cpuset is a config error |
| `steering incoming_cpu` (tcp_profile) | each slot's socket prefers connections the kernel received on that slot's CPU (`SO_INCOMING_CPU`) |
| `steering ebpf` (tcp_profile) | a reuseport program sends each connection to the socket of the slot pinned to the receiving CPU |
| `numa auto` (default) | with several NUMA nodes, the automatic CPU map fills one node before the next |
| `huge_pages auto\|on` | the allocator asks for transparent huge pages when the kernel offers them; otherwise normal pages, logged |
| `epoll_busy_poll 50us` (io) | the epoll backend busy-polls before sleeping (Linux 6.9 `EPIOCSPARAMS`); `uring_napi on` is the io_uring equivalent |

Every pinning decision goes through one CPU map that master builds before forking: workers pin
to it and steering points sockets at it, so a worker always sits on the CPU its socket prefers.
Without `worker_cpu_affinity`, workers are pinned only when a listener steers by CPU.

`steering ebpf` is a classic BPF program on the `SO_REUSEPORT` group (`SO_ATTACH_REUSEPORT_CBPF`):
it reads the receiving CPU and returns the slot pinned to it, else the CPU modulo the socket
count. Classic BPF does all this needs, without the `bpf()` syscall or `CAP_BPF`. It works best
when NIC queues are spread over the same CPUs (RSS or RPS): connections are then accepted on the
CPU that took their interrupt.

Busy polling trades CPU for latency: set `busy_poll` in the listener's `tcp_profile` together
with `epoll_busy_poll` or `uring_napi`. Docker Desktop's kernel does not expose
`net.core.busy_poll`; the VM tier (`tests/vm/test_tuning_vm.py`) runs that mode.

## kTLS modes (`ktls off | tx | tx+rx`)

Measured with `tests/vm/bench_ktls.py` in the QEMU guest (Debian kernel, emulated arm64, no KVM):

```
scripts/vm-run.sh python3 -m pytest tests/vm/bench_ktls.py -s -q
```

One TLS 1.2 connection per measurement: 500 small keep-alive requests, then an 8 MiB download and
a 4 MiB upload. Each mode ran once per backend (the epoll run first, then io_uring).

| mode | backend | small responses | download | upload |
|---|---|---|---|---|
| off (user-space TLS) | epoll | 295 req/s | 43.2 MiB/s | 26.9 MiB/s |
| tx | epoll | 448 req/s | 14.4 MiB/s | 11.2 MiB/s |
| tx+rx | epoll | 463 req/s | 14.3 MiB/s | 10.6 MiB/s |
| off | io_uring | 264 req/s | 43.0 MiB/s | 40.4 MiB/s |
| tx | io_uring | 609 req/s | 18.3 MiB/s | 10.5 MiB/s |
| tx+rx | io_uring | 618 req/s | 17.5 MiB/s | 10.7 MiB/s |

Read this as a trend, not a measurement of hardware. The guest is emulated: its kernel does AES with
the generic `aes_ti` code, while user-space OpenSSL uses the emulated ARMv8 crypto instructions,
so kTLS looks slow for bulk data here for a reason that does not exist on real CPUs. The samples
are tiny and each ran once, so differences of a few tens of percent (the two `off` upload rows
differ by 50%) are noise.

Comparison with the Task 1 spike (`spikes/ktls/README.md`, a standalone program, 20000 requests and
64 MiB each way):

| | spike, user space | spike, kTLS TX | this table, off (epoll) | this table, tx (epoll) |
|---|---|---|---|---|
| small responses | 1786 req/s | 418 req/s | 295 req/s | 448 req/s |
| download | 91.9 MiB/s | 18.0 MiB/s | 43.2 MiB/s | 14.4 MiB/s |

What agrees: bulk download is 2.5 to 3 times slower with kTLS in this guest, in both programs.
What does not: the spike saw small responses get 4 times slower with kTLS TX, and Bastion saw them
get 1.5 to 2.3 times faster. The spike's request loop and Bastion's HTTP path differ, so no
conclusion about the cause is drawn here. TX-only left uploads at user-space speed in the spike;
here uploads fell with `tx` as well. Neither result says anything about real hardware.

Not measured: real hardware, a KVM guest, larger transfers. A first run with 3000 requests, 32 MiB
and 16 MiB did not finish within 1500 s in the guest, twice, and the cause was not found, so the
sizes above are what completed.

What to do with this: the default is `ktls tx`. This table gives no reason to change it and none to
keep it on a CPU without AES instructions in the kernel; only a measurement on the target machine
decides.

## HTTP/2 (`listen ... tls http2`, `listen ... h2c`)

No HTTP/2 throughput or latency figures have been measured, so nothing below is a benchmark: it is
what each directive bounds, so a change can be made knowing what it costs. Every directive is in
`docs/config-reference.md`.

- **Memory per connection** is bounded by `http2_connection_window` (the most body bytes a client may
  have in flight towards the server), `http2_initial_window` times the open streams, and
  `http2_max_header_list_size`. The test `test_memory_bound` holds 256 streams on closed windows
  and requires under 64 MiB of growth in a sanitizer build.
- **Fairness against latency**: `http2_write_chunk` (64k) caps how much DATA one write round carries,
  so a more urgent response that becomes ready waits for at most one chunk. A larger value cuts
  syscalls on bulk transfers and lengthens that wait.
- **Slow readers**: a stream that has had no useful window for `send_timeout` is reset with CANCEL;
  one byte of window now and then does not count as progress.
- **Abuse limits** (`http2_abuse { }`) are leaky buckets: the rate is both the burst allowed and the
  events per second drained. The defaults leave a browser (a page of 100 requests with a third
  cancelled) far inside them; raise one only for a client you know sends that many legitimately.
  A hit is `GOAWAY(ENHANCE_YOUR_CALM)` and a count in `bastion_h2_abuse_total{kind}`.
- **h2spec was not run** (see `docs/conformance.md`).

## WAF-lite (`waf_rule`, `waf`)

- **Cost**: rules are checked one after another for every request of the scope; within a rule the
  cheap tests run first and regexes last, and the first failing test ends the rule. The target is
  under 100 µs per request for 1,000 rules on the benchmark host. **Flagged: not measured there.**
  The only figure is the unit test `evaluation_cost` (1,000 rules of two tests each, none
  matching) in the AddressSanitizer build on an arm64 Docker Desktop VM: about 100 µs per request,
  which is at the target even with the sanitizer's several-fold slowdown, but is not a benchmark.
  Keep long lists short by putting the most selective rule first, or use one `in_file` /
  `in_cidr` test instead of many rules.
- **Regexes** obey `regex_match_limit` and `regex_depth_limit`. A pattern that hits the limit
  counts as a match for `deny` and `challenge` rules (fail closed) and as no match for `allow`,
  `log` and `limit`; each hit logs a warning.
