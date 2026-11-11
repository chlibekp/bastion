# Tuning

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
