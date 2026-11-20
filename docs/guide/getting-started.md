# Getting started

This guide takes a fresh Linux host to an HTTPS site with HTTP/2 and HTTP/3 and a certificate
from Let's Encrypt. It assumes a host with a public address, ports 80 and 443 (TCP and UDP) open,
and DNS names that point at it.

## 1. Install

Bastion is released as a `.deb`, an `.rpm` and a static binary for amd64 and arm64
(`scripts/build-release.sh` builds them). On Debian or Ubuntu:

```sh
sudo apt install ./bastion_0.1.0-1_amd64.deb
```

On Fedora, RHEL and the like:

```sh
sudo dnf install ./bastion-0.1.0-1.x86_64.rpm
```

The package installs:

- `/usr/bin/bastion`, and `/usr/bin/bastionctl` (the same binary, see [operations](operations.md))
- a systemd unit, `bastion.service`, not started or enabled by the install
- `/etc/bastion/bastion.conf`, which serves `/usr/share/bastion/html` on port 80
- the `bastion` system user, which workers drop to
- `man 8 bastion` and the reference under `/usr/share/doc/bastion/`

The static binary needs nothing else: copy it to `/usr/local/bin/bastion` and run it under any
supervisor ([operations](operations.md#running-without-systemd)).

## 2. Check the host

```sh
bastion doctor
```

`doctor` reads what the kernel offers (io_uring, kTLS, BPF/XDP, Landlock, seccomp, limits) and
recommends settings. It never changes anything. Bastion runs without any of the optional
features: what is missing is logged once at start and the server falls back.

## 3. Write the configuration

Replace `/etc/bastion/bastion.conf` with this, using your own address and names:

```conf
acme { email admin@example.com; }
server {
    name example.com www.example.com;
    tls auto;
    root /srv/www;
}
```

That is the whole configuration of an HTTPS site:

- `acme` turns on automatic certificates. The CA is Let's Encrypt unless `ca` says otherwise. The
  email is sent to the CA for expiry notices.
- `tls auto` gets a certificate for every `name` of the server and renews it before it expires.
  Without a `listen`, the server listens on 443 with TLS (HTTP/1.1 and HTTP/2) and on 80, where
  every request except an ACME challenge is redirected to `https://`.
- Until the first certificate is issued, a temporary self-signed one serves, so the server starts
  even while the CA cannot reach it yet.
- Everything not written has a safe default: TLS 1.2 and 1.3 only, ECDHE with AEAD ciphers,
  workers sandboxed with seccomp and Landlock, files served only from below `root`, no symbolic
  links followed, dotfiles refused.

Put a page in place and add one line so the workers do not run as root:

```sh
sudo mkdir -p /srv/www
echo '<h1>It works</h1>' | sudo tee /srv/www/index.html
```

```conf
user bastion;
acme { email admin@example.com; }
server {
    name example.com www.example.com;
    tls auto;
    root /srv/www;
}
```

While you try things out, add `staging on;` to the `acme` block: Let's Encrypt's staging CA has
far higher rate limits, and its certificates are not trusted by browsers. Remove the line (and
reload) once the site works. [examples/https-auto.conf](../../examples/https-auto.conf) is this
configuration with comments.

## 4. Add HTTP/3

`tls auto` on its own does not open an HTTP/3 listener. To serve HTTP/3, write the listeners
out. Once any `listen` is written, Bastion no longer adds the port 80 redirect, so a second server
does it, and the certificate is validated over port 443 (`tls-alpn-01`):

```conf
user bastion;
acme {
    email admin@example.com;
    challenge tls-alpn-01;
}
server {
    name example.com www.example.com;
    listen 443 tls http2;
    listen 443 http3;
    tls auto;
    root /srv/www;
}
server {
    name example.com www.example.com;
    listen 80;
    redirect_https 308;
}
```

Responses over HTTP/1.1 and HTTP/2 carry `Alt-Svc: h3=":443"; ma=86400`, which tells browsers
that HTTP/3 is there. Add `listen [::]:443 tls http2;`, `listen [::]:443 http3;` and
`listen [::]:80;` for IPv6 (the listeners `tls auto` adds by itself are IPv4 only).
[examples/https-http3.conf](../../examples/https-http3.conf) has the full version.

## 5. Check and start

```sh
sudo bastion -t -c /etc/bastion/bastion.conf
sudo systemctl enable --now bastion
```

`-t` checks the file the way a start would and prints `configuration ok`, or the file, line and
column of the first error. The unit runs the same check before every start. With `tls auto`, the
check also creates the certificate storage (`/var/lib/bastion/acme`).

With ports 80 and 443 reachable, the certificate usually arrives within seconds. It is installed
through a reload, without dropping connections. Check who issued the certificate being served:

```sh
openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null \
    | openssl x509 -noout -issuer -enddate
```

Until it arrives, the issuer is the temporary self-signed certificate. Problems (the CA cannot
reach port 80, a name does not resolve, a rate limit) are logged as errors with the next retry
time: `journalctl -u bastion`. The success line `acme: example.com: certificate installed` is at
level info, which the default log level (warn) leaves out; `error_log /var/log/bastion/error.log
info;` shows it.

## 6. Try it

```sh
curl -I https://example.com/
curl -I http://example.com/          # 308 to https://
curl -I --http3-only https://example.com/   # needs a curl built with HTTP/3
```

## Where to go next

- [Static sites](static-sites.md): index files, single-page apps, caching headers, compression
- [Reverse proxy](reverse-proxy.md): upstreams, load balancing, health checks, WebSockets
- [TLS](tls.md): your own certificates, ACME options, TLS profiles, client certificates
- [Caching](caching.md): a shared HTTP cache in front of an application
- [DDoS protection](ddos.md): rate limits, connection limits, the challenge page, XDP
- [Migrating from nginx](migrating-from-nginx.md): what each nginx directive becomes
- [Operations](operations.md): reload, upgrade, logs, metrics, the admin API, systemd
- [Configuration reference](../config-reference.md): every directive, its default and an example

## Walkthrough record

A fresh-VM walkthrough was NOT executed: no VM was available. The closest substitute was run on
2026-11-20 instead, following steps 1 to 6 of this guide on a clean `debian:trixie` container
(arm64, Docker Desktop's Linux VM) against a local [Pebble](https://github.com/letsencrypt/pebble)
CA in a second container on the same Docker network:

1. Pebble 2.6.0 (Debian's `pebble` package) with `httpPort 80`, `tlsPort 443` and
   `pebble-challtestsrv` resolving every name to the site container. Its TLS certificate was copied
   to the site container as `/root/pebble-ca.pem` (not timed: with a real CA this step does not
   exist).
2. Timed from here. `apt-get update`, then `apt-get install ./bastion_0.1.0-1_arm64.deb curl`
   (the package built by `scripts/build-release.sh 0.1.0 arm64` from this tree).
3. `bastion doctor`, a page in `/srv/www`, and the step 4 configuration (HTTP/3) with
   `ca https://pebble:14000/dir;` and `ca_root /root/pebble-ca.pem;` added to the `acme` block and
   the names `example.test www.example.test`.
4. `bastion -t -c /etc/bastion/bastion.conf`: `configuration ok`.
5. `bastion -c /etc/bastion/bastion.conf` in the background (the container has no systemd).
6. Checked with curl 8.14.1 (Debian, built with HTTP/3) and Pebble's issuing root: HTTP/2
   `200` with `alt-svc: h3=":443"; ma=86400`, HTTP/3 (`--http3-only`) `200`, and port 80 answering
   `308` with `Location: https://example.test/x`.

Times from the start of step 2: package installed at 10.7 s, configuration checked at 10.7 s
(the commands were scripted, so this excludes the time a person takes to type them), certificate
on disk about 12.5 s, HTTPS and HTTP/3 answering right after. Under the 5-minute target with a
wide margin even allowing several minutes of typing, but a person following the guide by hand was
not timed.

What the run found and what changed because of it:

- `bastion -t` on a fresh install failed with `acme storage: creating /var/lib/bastion/acme: No
  such file or directory`: `/var/lib/bastion` only existed once systemd had started the unit. The
  package now creates `/var/lib/bastion`, `/var/cache/bastion` and `/var/log/bastion` itself
  (root, 0750, as the unit would), and `tests/host/test_packages_host.sh` checks it.
- The success line for an issued certificate is at level info and is not logged by default; step 5
  now says how to check the certificate instead.
- Landlock, kTLS and the eBPF QUIC routing were unavailable in that VM; each was logged as a
  warning and the server fell back as documented.
