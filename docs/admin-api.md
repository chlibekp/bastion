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

The helper answers these from shared memory, without master:

| Method and path | Effect | Answers |
|---|---|---|
| `GET /config` | a read-only view: workers, servers (names, listen addresses, certificate and key file paths, location count, configured maintenance), upstreams, cache stores, the admin socket | 200 |
| `GET /upstreams`, `GET /upstreams/<name>` | each upstream's servers: `index`, `server` (`host:port`), weight, backup, `up` (health), `drained` | 200; 404 for an unknown name |
| `POST /upstreams/<name>/<peer>/drain` | no new request goes to that server's peers, even in panic mode; requests already on them finish | 200; 404 unknown upstream or peer |
| `POST /upstreams/<name>/<peer>/enable` | undoes a drain | 200; 404 |
| `POST /cache/purge` | `{"tag": "t"}`, `{"tags": ["a", "b"]}` (1 to 64), `{"host": "h"}` or `{"all": true}`, optionally `"store": "<cache_store>"` (every store otherwise) | 200; 400 malformed; 404 unknown store or no store |
| `POST /maintenance` | `{"on": true}` answers 503 with `Retry-After` (`maintenance_retry_after`) in every server, or in one with `"server": "<a name>"`; `maintenance_allow` peers are still served. `{"on": false}` removes the override; a server configured with `maintenance on` stays in it | 200; 400; 404 unknown server |
| `POST /challenge` | `{"mode": "on"}` or `"off"` forces the `challenge auto` decision; `"auto"` hands it back to the traffic sample. Scopes with `challenge on` or `challenge off` are not affected | 200; 400; 409 with no `challenge auto` configured |

`<peer>` is the server's `index` or its `server` value as `GET /upstreams` lists them (IPv6 in
brackets), percent-encoded in the path; it must name a server the configuration has. Server names
for `/maintenance` must be names the configuration gives a `server` block.

`GET /config` never shows a key's contents, a password, a token or any value that can hold one
(headers, auth settings, templates): only names, addresses and file paths.

Only one request that needs master is in flight at a time, because master handles them in order.
While one is in flight, another such request gets 503 and should retry. A request (head and body)
is at most 64 KiB.

## Runtime changes are not persistent

Nothing the API changes is written to the configuration file:

- Drains, maintenance and challenge overrides live in shared memory that every start and every
  reload makes again, so a reload, live upgrade or restart resets them to the configuration.
  `test_runtime_vs_reload` checks this for a drain and for maintenance.
- A block lasts until its TTL ends, across reloads: the shared block table survives a reload (like
  the blocks escalation adds), and the new master reads it back into its list, dropping any block
  the new configuration exempts. So what `GET /blocks` lists and `DELETE /blocks` removes is always
  what workers enforce. A restart ends every block.
- `POST /reload` and `POST /upgrade` act on the configuration file and the binary as they are on
  disk.

## bastionctl

`bastionctl` is the bastion binary run under that name (a symlink).

```
bastionctl [-s socket | -c config] [--json] status | reload | upgrade | blocks
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

The socket is `-s`, or the one the `-c` configuration names, or `/run/bastion/admin.sock`.
`status`, `blocks`, `config` and `upstreams` print the JSON answer. Arguments become JSON through
the JSON writer and path segments are percent-encoded, so no argument can change a request's shape. Other commands print the answer's message, or with
`--json` the answer as it came. The exit status is 0 on success, 1 when the API refused the request
or could not be reached (for example "cannot reach the admin API at ...: No such file or
directory"), and 2 for a usage error.

`bastionctl upgrade` with `-p` or `-c` is the signal-driven live upgrade from Phase 14 Task 2. It
waits for the new master, drains, checks and rolls back by itself. `bastionctl upgrade` with `-s`,
or with no options, asks the API to start the upgrade and returns at once.
