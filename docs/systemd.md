# Running Bastion under systemd

The `.deb` and `.rpm` install the unit `packaging/bastion.service` as
`/usr/lib/systemd/system/bastion.service`, a default configuration at
`/etc/bastion/bastion.conf` and the man page `bastion(8)`.

```sh
sudo systemctl enable --now bastion
systemctl status bastion
curl -i http://127.0.0.1/
```

Change settings in a drop-in (`systemctl edit bastion`), never in the packaged unit: an upgrade
replaces it. The configuration file is a conffile and is kept on upgrade.

## What the unit does

- `Type=notify`: master sends `READY=1` once the listeners serve, `STATUS=` lines, and
  watchdog keep-alives (`WatchdogSec=30s`).
- `ExecStartPre=bastion -t` refuses to start on a broken configuration.
- `systemctl reload bastion` sends SIGHUP. Master re-executes itself in place (same PID),
  sends `RELOADING=1`, then `READY=1` once the new generation serves, or once the reload failed
  and the old generation still serves (the error is in the journal).
- `systemctl stop` sends SIGQUIT to master alone (`KillMode=mixed`): connections finish within
  `shutdown_timeout`, and anything left after `TimeoutStopSec` gets SIGKILL.
- Logs: master and children write to stderr, which is the journal. Access logs default to
  `/var/log/bastion/access.log` (`LogsDirectory=`), rotated by `/etc/logrotate.d/bastion`,
  which sends USR1 to reopen them.
- `StateDirectory=`, `CacheDirectory=` and `RuntimeDirectory=` create `/var/lib/bastion`,
  `/var/cache/bastion` and `/run/bastion` with mode 0750.

## Live upgrade

After installing a new package, `systemctl reload bastion` re-executes the new binary in place.
For a zero-downtime upgrade with a rollback window, run `bastionctl upgrade` instead (or send
SIGUSR2): a second master starts beside the old one, and on commit the old master sends
`MAINPID=<new>`, which `NotifyAccess=main` accepts because it comes from the main PID. HUP to
the old master during the window rolls back.

## Sandboxing

The unit confines master: `ProtectSystem=strict`, `NoNewPrivileges=yes`, a capability bounding
set of what master needs, a deny-list `SystemCallFilter=` and more (see the comments in the unit
file). Workers, the helper and the ACME job are confined further by Bastion itself, each with
its own seccomp allowlist and Landlock rules, which a unit cannot express per process.

`systemd-analyze security bastion` scores the unit about 4.0 ("OK"). The remaining exposure is
what a server with XDP, a uid drop and its own namespaces needs. A server without `xdp {}` can
remove `CAP_BPF` and `CAP_NET_ADMIN` in a drop-in:

```ini
[Service]
CapabilityBoundingSet=~CAP_BPF CAP_NET_ADMIN
```

Do not add `RestrictSUIDSGID=yes` in a drop-in. systemd implements it with a seccomp rule that
answers ENOSYS to every `openat2()`, and Bastion opens every served file, cache object and spooled
body with `openat2(RESOLVE_BENEATH)`, with no fallback (`openat` cannot keep a path below its
root). Bastion refuses to start with `openat2 is blocked (ENOSYS)` when it sees this. Release
0.1.0 shipped the setting in its unit, and every static request there answered 500 with
`static: opening "/" failed: Function not implemented` in the log. The risk it covers is handled
otherwise: the children's seccomp filters allow no `chmod` family at all, master has neither
`CAP_FSETID` nor `CAP_FOWNER`, and `NoNewPrivileges=yes` holds for the whole unit.

## Socket activation

Optional. systemd binds the ports and passes them to master as file descriptors 3 onwards, so
the sockets exist before the server starts and stay bound across restarts.

```sh
sudo cp /usr/share/doc/bastion/examples/bastion.socket /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now bastion.socket
```

Each TCP `listen` whose address matches a passed socket exactly uses that socket for every
worker: `ListenStream=0.0.0.0:80` for `listen 0.0.0.0:80;`, and `ListenStream=[::]:443` with
`BindIPv6Only=ipv6-only` for `listen [::]:443;`. A passed socket that no `listen` names is
closed with a warning; a `listen` that no passed socket matches is bound by Bastion as usual.
HTTP/3 (UDP) listeners are always bound by Bastion.

## Without systemd

`bastion -c /etc/bastion/bastion.conf` runs in the foreground; any supervisor works. Outside
systemd the notify socket, watchdog and socket activation are simply unused.
