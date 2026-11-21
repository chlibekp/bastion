# Command line

Bastion is one binary. Run as `bastion` it is the server and a few tools; run under the name
`bastionctl` (the package installs a symlink) it is the client of the admin API and the live
upgrade driver. Everything here comes from the usage texts in `src/config/cli.c`,
`src/ops/ctl.c`, `src/ops/doctor.h` and `src/auth/basic.c`.

## `bastion`

```
bastion [-c file] [-t] [-T]
bastion serve <dir> [--port n]
bastion proxy <url> [--port n]
bastion passwd [-m KiB] [-t iterations] [-p lanes] [user]
bastion doctor [-c file]
bastion --dump-schema | --help | --version
```

| Option | Meaning |
|---|---|
| `-c file` | the configuration file (default `/etc/bastion/bastion.conf`) |
| `-t` | check the configuration and exit |
| `-T` | check, then print the effective configuration (every default, environment values expanded) and exit |
| `--dump-schema` | print every directive as JSON (the source of [config-reference.md](config-reference.md)) |
| `-h`, `--help` | print the usage text |
| `--version` | print the version, the git revision and the linked library versions |

With no check option, `bastion` runs the server in the foreground. It does not daemonise itself:
systemd or another supervisor runs it ([systemd](systemd.md)).

`-T` can print secrets that come from environment variables, and error messages echo up to 40
bytes of an offending value after expansion. Review both before pasting them anywhere.

Exit status: 0 success, 1 configuration or startup error, 2 usage error.

```
$ bastion --version
bastion 0.1.0 (git 59ba273b5bbb, OpenSSL 3.5.9 29 Sep 2026)
  ngtcp2 1.26.0, nghttp3 1.19.0
  liburing 2.15, libbpf v1.8
  pcre2 10.49 2026-09-28, zstd 1.5.7, brotli 1.2.1, zlib-ng 2.3.3, mimalloc 3.6.1
```

### `serve` and `proxy`: no configuration file

```
bastion serve /srv/www --port 8080
bastion proxy http://127.0.0.1:3000 --port 8080
```

These build a one-server configuration in memory: `listen <port>` plus `root <dir>` or
`proxy <url>`, with every other default. The port defaults to 8080. A relative directory is made
absolute before the server starts. `-c` cannot be combined with them. They suit containers and
quick tests; anything more needs a file.

### `passwd`: Basic auth entries

```
$ bastion passwd alice
Password:
Again:
alice:$argon2id$v=19$m=65536,t=3,p=1$...$...
```

Prints one `auth_basic_file` line: the user, then an Argon2id hash in PHC form. The defaults are
`m=65536` KiB of memory, `t=3` iterations and `p=1` lane; `-m`, `-t` and `-p` change them. On a
terminal it asks twice without echo; otherwise it reads one line from standard input, so
`echo secret | bastion passwd alice` works in scripts. Settings below `m=19456, t=2` print a
warning, and the server warns about such entries at load too. A user name may not contain `:`.
See [access control](guide/access-control.md#http-basic-authentication).

### `doctor`: check a host

```
bastion doctor
bastion doctor -c /etc/bastion/bastion.conf
```

Reports what the kernel and the host offer, with recommended values: kernel version, io_uring and
NAPI, kTLS, BPF and XDP, Landlock, seccomp, BBR, busy polling, SYN cookies, `somaxconn`,
`tcp_max_syn_backlog`, descriptor limits, memlock, CPUs, NUMA nodes and transparent huge pages.
It only reads (`/proc`, `/sys`, `getrlimit`, and probes that create and free an io_uring, a socket
or a BPF program) and never changes a setting. With `-c` it also checks every `require` in the
configuration (for example `ktls tx require`, `landlock on require`).

Exit status: 0, or 1 when a `require` would fail on this host, or 2 for a usage or configuration
error. [Tuning](tuning.md#start-with-bastion-doctor) explains each line.

## Signals

Send signals to master (its PID is in the `pid` file when one is configured, and is systemd's
main PID). Workers and the helper ignore them and take orders from master.

| Signal | Effect |
|---|---|
| `TERM`, `INT` | fast stop |
| `QUIT` | graceful stop: stop accepting, let connections finish within `shutdown_timeout` (default 30s), then kill what is left |
| `HUP` | reload the configuration; during a live upgrade, sent to the old master, roll back instead |
| `USR1` | reopen the access log files (log rotation) |
| `USR2` | start a live upgrade to the binary now installed at master's path |
| `WINCH` | during a live upgrade, drain the old master's workers |

How reload and upgrade work is in [architecture](architecture.md#reload); how to use them is in
[reload and upgrade](guide/reload-and-upgrade.md).

## `bastionctl`

```
bastionctl [-s socket | -c config] [--json] status | reload | upgrade
bastionctl [-s socket | -c config] [--json] blocks
bastionctl [-s socket | -c config] [--json] block <addr[/prefix]> [--ttl s]
bastionctl [-s socket | -c config] [--json] unblock <addr[/prefix]>
bastionctl [-s socket | -c config] [--json] config
bastionctl [-s socket | -c config] [--json] upstreams [name]
bastionctl [-s socket | -c config] [--json] upstream drain|enable <name> <peer>
bastionctl [-s socket | -c config] [--json] purge --tag t | --host h | --all [--store name]
bastionctl [-s socket | -c config] [--json] maintenance on|off [--server name]
bastionctl [-s socket | -c config] [--json] challenge on|off|auto
bastionctl upgrade (-p pidfile | -c config) [--timeout s] [--settle s] [--check host:port]
```

The admin commands talk to the admin API over its Unix socket, which exists only when the
configuration has an `admin {}` block. The socket is the one given with `-s`, else the one the
`-c` configuration names, else `/run/bastion/admin.sock`.

| Command | Does |
|---|---|
| `status` | master's PID, generation, workers, readiness, the last reload's outcome, whether an upgrade is running |
| `reload` | checks the configuration on disk, then reloads; a parse error comes back as the answer |
| `upgrade` | asks master to start a live upgrade and returns at once |
| `blocks` | lists the active blocks |
| `block <addr[/prefix]> [--ttl s]` | blocks an address (IPv4 `/32`, IPv6 `/48` to `/128`) for `--ttl` seconds: 1 to 86400, default 3600 |
| `unblock <addr[/prefix]>` | removes a block |
| `config` | a read-only view of the running configuration: names, addresses and file paths, never secrets |
| `upstreams [name]` | each upstream server's index, address, weight, health and drain state |
| `upstream drain\|enable <name> <peer>` | stops or resumes new requests to one upstream server; `<peer>` is its index or `host:port` as `upstreams` shows it |
| `purge --tag t \| --host h \| --all [--store name]` | purges cache entries by tag, by host or all of them, in one store or every store |
| `maintenance on\|off [--server name]` | answers 503 with `Retry-After` in every server, or one |
| `challenge on\|off\|auto` | forces the `challenge auto` decision on or off, or hands it back to the traffic sample |

`--json` prints the API's answer as it came; otherwise `status`, `blocks`, `config` and
`upstreams` print the JSON answer and the other commands print its message.

Changes made this way are not written to the configuration. Drains, maintenance and challenge
overrides last until the next reload or restart; blocks last their TTL, across reloads, and end
with a restart. The endpoints behind each command are in [admin-api.md](admin-api.md).

Exit status: 0 done, 1 failed (the API refused, the socket could not be reached, or an upgrade
was rolled back), 2 usage error.

### `bastionctl upgrade`

```
sudo bastionctl upgrade -c /etc/bastion/bastion.conf --check 127.0.0.1:443
```

With `-p pidfile` or `-c config` (for its `pid` directive), `bastionctl` drives the signal-based
live upgrade itself: it sends `USR2`, waits for the new master, sends `WINCH` to drain the old
workers, checks that the new master keeps running for `--settle` seconds (default 1) and that the
`--check` address accepts a TCP connection before and after the drain, then sends `QUIT` to commit.
If any step fails or takes longer than `--timeout` seconds (default 60) it rolls back and exits 1.
Without `-p` or `-c`, `bastionctl upgrade` only asks the admin API to start the upgrade.

## Environment

| Variable | Used for |
|---|---|
| any name in `${NAME}` | expanded in the configuration ([configuration](configuration.md#environment-variables)) |
| `NOTIFY_SOCKET`, `WATCHDOG_USEC` | set by systemd for `Type=notify` and the watchdog ([systemd](systemd.md)) |
| `LISTEN_FDS`, `LISTEN_PID` | set by systemd for socket activation ([systemd](systemd.md#socket-activation)) |

Bastion also passes state to its own next image in `BASTION_*` variables during a reload or an
upgrade. They are internal: do not set them.
