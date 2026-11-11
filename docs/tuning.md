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

What to do with this: `ktls` stays at its default. Only a measurement on the target machine
justifies turning it on.
