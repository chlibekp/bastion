# Admin API and bastionctl

The admin API is off unless the configuration has an `admin {}` block:

```
admin { socket /run/bastion/admin.sock mode=0600; }
```

It is HTTP/1.1 with JSON bodies over that Unix socket. Bastion never opens a network listener for
it. Master creates the socket before it starts any child. The helper process serves it, and master
does the work. Requests reach master through a shared mailbox and a typed message on the helper's
channel.

## Access

- The socket's file mode controls access. The default is `0600`, owner root. With
  `group=<name>` and a mode such as `0660`, members of that group may connect. A mode that gives
  other users any access (`0666`, `0604`, ...) is refused at load and by `bastion -t`.
- The kernel checks the mode at `connect`. The helper then reads `SO_PEERCRED`. It accepts uid 0,
  the socket's owner, or, when `group=` is set, any peer the mode let in.
- Every write action (any method other than GET) is logged with the caller's pid, uid and gid:
  `admin: POST /blocks from pid=1234 uid=0 gid=0`.
- There are no passwords or tokens. Nothing secret is stored, hard-coded or logged. Anyone who can
  open the socket is an administrator, so keep the mode tight.

## Endpoints

| Method and path | Effect | Answers |
|---|---|---|
| `GET /status` | pid, generation, workers, readiness, last reload outcome, upgrade in progress | 200 |
| `POST /reload` | checks the configuration on disk, then reloads | 202; 400 with the parse error; 409 while starting, stopping or upgrading |
| `POST /upgrade` | starts a live upgrade to the binary at master's path (as `USR2`) | 202; 409 with the reason |
| `GET /blocks` | the blocks the backend holds (with `xdp {}`, the XDP maps' real state) | 200 |
| `POST /blocks` `{"addr": "a[/p]", "ttl": s}` | blocks an address for `ttl` seconds (default 3600, 1 to 86400) | 200; 400 malformed; 409 allowlisted or past `escalation_ceiling` |
| `DELETE /blocks` `{"addr": "a[/p]"}` | removes that block | 200; 404 when there was none |

An admin block follows the same rules as a worker's escalation request. It must be a single
address (IPv4 `/32`, IPv6 `/48` to `/128`) with a TTL of at most one day, and an address in
`escalation_allow`, a trusted proxy (`real_ip_from`, PROXY sources), loopback, the `xdp` allow list
or an upstream literal is refused. Errors are `{"error": "..."}`.

`/config`, `/upstreams[/name/peer/drain|enable]`, `/cache/purge`, `/maintenance` and `/challenge`
answer 501 in this version. Each of them needs a runtime override that the workers read from
shared state, which does not exist yet.

Only one request is in flight at a time, because master handles them in order. While one is in
flight, another client gets 503 and should retry. A request (head and body) is at most 64 KiB.

## Runtime changes are not persistent

Nothing the API changes is written to the configuration file:

- A block lasts until its TTL ends or until the next reload, live upgrade or restart, whichever
  comes first. A reload starts master's block list again from the configuration, which
  `test_runtime_vs_reload` checks.
- `POST /reload` and `POST /upgrade` act on the configuration file and the binary as they are on
  disk.

## bastionctl

`bastionctl` is the bastion binary run under that name (a symlink).

```
bastionctl [-s socket | -c config] [--json] status | reload | upgrade | blocks
bastionctl [-s socket | -c config] [--json] block <addr[/prefix]> [--ttl s]
bastionctl [-s socket | -c config] [--json] unblock <addr[/prefix]>
bastionctl upgrade (-p pidfile | -c config) [--timeout s] [--settle s] [--check host:port]
```

The socket is `-s`, or the one the `-c` configuration names, or `/run/bastion/admin.sock`.
`status` and `blocks` print the JSON answer. Other commands print the answer's message, or with
`--json` the answer as it came. The exit status is 0 on success, 1 when the API refused the request
or could not be reached (for example "cannot reach the admin API at ...: No such file or
directory"), and 2 for a usage error.

`bastionctl upgrade` with `-p` or `-c` is the signal-driven live upgrade from Phase 14 Task 2. It
waits for the new master, drains, checks and rolls back by itself. `bastionctl upgrade` with `-s`,
or with no options, asks the API to start the upgrade and returns at once.
