# Operations

Running Bastion day to day: checking and reloading the configuration, upgrading without dropping
connections, logs, metrics, the admin API and systemd. [systemd.md](../systemd.md),
[admin-api.md](../admin-api.md) and [tuning.md](../tuning.md) go deeper.

## Processes

One master process (root) reads the configuration, binds the sockets and starts the children:
a worker per CPU (`workers auto`), which serve traffic; a helper, which writes access logs,
serves metrics and the admin API, runs health checks and maintains the cache; and, when needed,
a short-lived ACME job. Workers and the helper drop to `user` and run under their own seccomp
filters and Landlock rules. A worker that crashes is restarted by master.

## Signals

| Signal | Effect |
|---|---|
| `HUP` | reload the configuration |
| `QUIT` | graceful stop: connections finish within `shutdown_timeout` (30s) |
| `TERM`, `INT` | fast stop |
| `USR1` | reopen log files |
| `USR2` | live upgrade to the binary now at master's path |
| `WINCH` | during an upgrade, drain the old workers |

## Reload

```sh
sudo bastion -t -c /etc/bastion/bastion.conf && sudo systemctl reload bastion
```

A reload re-executes master in place (same PID) with the new configuration; the new workers take
over the listening sockets and the old ones finish their connections. A configuration that fails
to load leaves the old generation serving, and the error goes to the log. The admin API's
`POST /reload` (`bastionctl reload`) checks the file first and returns the parse error instead.
`bastion_config_reload_success` in the metrics is 0 after a failed reload.

Certificates and keys, password files, JWT keys and `include`d files are read at load, so a
reload picks up their changes too.

## Live upgrade

After installing a new package, `systemctl reload bastion` already runs the new binary. For an
upgrade with a rollback window:

```sh
sudo bastionctl upgrade -c /etc/bastion/bastion.conf --check 127.0.0.1:443
```

A second master starts beside the old one with the new binary. `bastionctl` waits for it, drains
the old workers, checks the address given with `--check`, and commits (the old master exits) or
rolls back by itself. By hand it is `USR2` to start, `WINCH` to drain the old workers, `QUIT` to
the old master to commit and `HUP` to it to roll back. Under systemd the old master hands the main
PID to the new one ([systemd.md](../systemd.md#live-upgrade)).

## Logs

- Errors and notices go to stderr, which under systemd is the journal (`journalctl -u bastion`),
  unless `error_log` names a file. The default level is `warn`; `error_log <path> info` adds
  informational lines such as certificate issuance.
- Access logs are off unless `access_log` is set. The package's configuration writes
  `/var/log/bastion/access.log` in the built-in `main` format (JSON, one object per line);
  `combined` is the nginx-style text format.

```conf
log_format timing json {
    time $time_iso8601;
    client $remote_addr;
    method $request_method;
    uri $request_uri;
    protocol $server_protocol;
    status $status;
    bytes $body_bytes_sent;
    duration $request_time;
    id $request_id;
}
access_log /var/log/bastion/access.log timing;
access_log /var/log/bastion/errors.log combined errors_only=on;
server { listen 80; root /srv/www; }
```

Workers never write log files: the helper does, from a buffer (`log_buffer`, flushed every
`log_flush_interval`). Values are escaped so no request can forge a line, and the `Authorization`,
`Cookie` and `Proxy-Authorization` headers are redacted (`log_redact_headers`,
`log_redact_query_params`). The package's `/etc/logrotate.d/bastion` rotates the files and sends
`USR1` to reopen them.

## Metrics

```conf
metrics {
    listen 127.0.0.1:9145;
    path /metrics;
}
server { listen 80; root /srv/www; }
```

The helper serves Prometheus text on its own listener, never on a site's port. Counters live in
shared memory and survive reloads, upgrades and worker crashes. Among them:
`bastion_http_requests_total`, `bastion_http_request_duration_seconds`, `bastion_connections`,
`bastion_upstream_peers_up`, `bastion_config_reload_success`, `bastion_worker_restarts_total`,
`bastion_under_attack` and `bastion_build_info`. A non-loopback `listen` draws a warning at load:
protect it with `allow` or `auth_basic` inside the block.

## The admin API

```conf
admin {
    socket /run/bastion/admin.sock mode=0600;
}
server { listen 80; root /srv/www; }
```

The admin API is off without this block. It is HTTP over a Unix socket (never a network port),
and access is the socket's file mode: root only by default, or a group with `group=` and
`mode=0660`. `bastionctl` (the same binary under another name) talks to it:

```sh
bastionctl status
bastionctl reload
bastionctl config
bastionctl upstreams
bastionctl upstream drain app 0          # no new requests to server 0 of upstream app
bastionctl upstream enable app 0
bastionctl blocks
bastionctl block 198.51.100.7 --ttl 600
bastionctl unblock 198.51.100.7
bastionctl purge --tag product-42        # also --host h or --all; there is no purge by URL
bastionctl maintenance on --server example.com
bastionctl challenge on
```

What the API changes is not written to the configuration: drains, maintenance and challenge
overrides last until the next reload or restart, blocks until their TTL. The full list of
endpoints and answers is in [admin-api.md](../admin-api.md).

## systemd

The package's unit is `Type=notify`: master reports readiness, reload progress and watchdog
keep-alives. `ExecStartPre` runs `bastion -t`, so a broken configuration never replaces a working
one at start.

```sh
sudo systemctl enable --now bastion
sudo systemctl reload bastion     # HUP
sudo systemctl stop bastion       # QUIT, graceful
systemctl status bastion
```

Change the unit with a drop-in (`systemctl edit bastion`), not the packaged file. The unit confines
master (`ProtectSystem=strict`, a capability bounding set, a system call deny list);
`systemd-analyze security bastion` scores it about 3.8. A server without `xdp {}` can drop
`CAP_BPF` and `CAP_NET_ADMIN` in a drop-in. Socket activation is optional and described in
[systemd.md](../systemd.md#socket-activation).

## Running without systemd

`bastion -c /etc/bastion/bastion.conf` runs in the foreground under any supervisor, which should
send `QUIT` to stop it gracefully and `HUP` to reload. The directories the unit would create
(`/var/lib/bastion`, `/var/cache/bastion`, `/var/log/bastion`, `/run/bastion`) must exist when the
configuration uses them: the package creates the first three. A container needs no configuration
file at all for simple cases: `bastion serve /srv/www --port 8080`.

## Checking a host

`bastion doctor [-c file]` reports what the kernel offers (io_uring, kTLS, BPF and XDP, Landlock,
seccomp, limits, sysctls) and, with `-c`, whether every `require` in the configuration can be met.
It changes nothing. See [tuning.md](../tuning.md#start-with-bastion-doctor).
