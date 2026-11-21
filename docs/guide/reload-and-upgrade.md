# Reload and live upgrade

Bastion changes its configuration and even its binary without closing listening sockets or
dropping connections in flight. A **reload** applies a new configuration; a **live upgrade** runs
a new binary beside the old one with a rollback window. [Architecture](../architecture.md#reload)
explains the mechanism; this guide is the operator's view.

## Reload

```sh
sudo bastion -t -c /etc/bastion/bastion.conf && sudo systemctl reload bastion
```

Any of these reloads:

| Way | Notes |
|---|---|
| `systemctl reload bastion` | sends `HUP` to master |
| `kill -HUP <master pid>` | without systemd |
| `bastionctl reload` | through the admin API: checks the file first and returns the parse error instead of reloading |

What happens:

1. The running binary checks the new configuration with `-t`. If it fails, the error is logged,
   nothing changes, the old configuration keeps serving and `bastion_config_reload_success`
   becomes 0.
2. Master re-executes itself in place with the same PID, keeping every listening socket.
3. A new generation of workers starts on those sockets. When all of them are ready, the old
   workers stop accepting, finish their requests within `shutdown_timeout` (30s by default) and
   exit; any still busy after that are killed.

A reload re-reads everything the configuration names: certificates and keys, password files, JWT
keys, ACL list files and `include`d files. That is also how a renewed ACME
certificate is installed.

### What a reload resets

| Kept | Reset |
|---|---|
| listening sockets (an unchanged address never stops accepting) | rate limit counters (`limit_zone`) |
| the PID | upstream health and ejections |
| metrics counters | the cache index (objects on disk stay) |
| TLS session ticket keys (resumption keeps working) | admin API drains, maintenance and challenge overrides |
| escalation and admin blocks, until their TTL | |
| a pinned XDP filter, adopted without a gap | |

A listener whose number of sockets changes (a different `workers` count) gets new sockets, and
connections still queued in the removed ones are reset. A failure after validation, such as a new
port already taken by another program, ends the server as it would at first start, so check new
ports first.

## Live upgrade

After a package upgrade, `systemctl reload bastion` already runs the new binary, because a reload
re-executes the binary at master's path. A live upgrade adds a rollback window: the old master
keeps running beside the new one until you commit.

### With `bastionctl`

```sh
sudo bastionctl upgrade -c /etc/bastion/bastion.conf --check 127.0.0.1:443
```

`bastionctl` sends `USR2`, waits for the new master to be ready, drains the old workers, waits
`--settle` seconds (default 1), checks that the `--check` address accepts TCP connections before
and after the drain, and commits. If any step fails or exceeds `--timeout` (default 60s) it rolls
back and exits 1. `-p <pidfile>` can replace `-c`. See [CLI](../cli.md#bastionctl-upgrade).

### By hand

| Step | Signal | To | Effect |
|---|---|---|---|
| 1 | `USR2` | old master | checks the binary, runs it with `-t`, renames the PID file to `<pid>.oldbin` and starts the new master; both serve |
| 2 | `WINCH` | old master | the old workers drain and are not respawned |
| 3a | `QUIT` | old master | commit: the old master exits and hands systemd the new main PID |
| 3b | `HUP` | old master | roll back: the old master restarts its workers, takes back XDP and QUIC routing, restores the PID file and stops the new master |

The old master only runs the binary at the path it was started from, and only when that file is a
regular executable owned by root or master's user and writable by nobody else (nor its directory,
unless sticky). A new master that fails at start is reaped by the old one, which restores the PID
file and keeps serving.

Under systemd the old master hands the main PID to the new one on commit
([systemd](../systemd.md#live-upgrade)). A live upgrade resets the same state as a reload.

## Stopping

| Signal | systemd | Effect |
|---|---|---|
| `QUIT` | `systemctl stop` | graceful: stop accepting, finish within `shutdown_timeout`, then kill |
| `TERM`, `INT` | | fast stop |

HTTP/3 connections get GOAWAY on a graceful stop and are closed once their requests finish. Every
queued cache write finishes before a worker exits.

## Checklist

- Run `bastion -t` first. `systemctl reload` and `bastionctl reload` check too, but the error is
  easier to read at the prompt.
- Watch `bastion_config_reload_success` and the log after each reload.
- Keep `shutdown_timeout` longer than your longest normal request, or long downloads and uploads
  are cut at each reload.
- Use `bastionctl upgrade --check` for binary upgrades you may need to undo.
