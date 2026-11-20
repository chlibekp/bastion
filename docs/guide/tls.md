# TLS

Bastion terminates TLS 1.2 and 1.3 with OpenSSL, for HTTP/1.1, HTTP/2 and (through QUIC)
HTTP/3. Certificates come from ACME (`tls auto`) or from files (`tls_cert`).

## Automatic certificates

```conf
acme { email admin@example.com; }
server {
    name example.com www.example.com;
    tls auto;
    root /srv/www;
}
```

- One certificate covers all of a server's names. Each name must be a plain host name with a dot.
- Renewal starts `renew_before` the expiry (or when the CA's renewal information, ARI, says so).
- The protocol runs in a short-lived, sandboxed job that master starts, never in a worker. A new
  certificate is installed through a reload, without dropping connections.
- Keys and the account are made locally and stored with mode 0600 under `storage`
  (`/var/lib/bastion/acme`). Back this directory up to avoid re-issuing after a rebuild.
- Without a `listen`, the server listens on 443 (TLS, HTTP/1.1 and HTTP/2) and on 80, where
  everything except ACME challenges is redirected to https. These implied listeners are IPv4 only
  and include no HTTP/3: write the listeners out for either (next section).

### Choosing a CA and a challenge

```conf
acme {
    email admin@example.com;
    ca letsencrypt;
    staging on;
    challenge http-01;
}
server { name example.com; tls auto; root /srv/www; }
```

| `ca` | |
|---|---|
| `letsencrypt` (default) | Let's Encrypt; `staging on` uses its staging CA, for testing |
| `zerossl` | needs `eab_kid` and `eab_hmac` from your ZeroSSL account |
| `https://...` | any ACME directory URL; `ca_root` names the PEM of a private CA's root |

| `challenge` | |
|---|---|
| `http-01` (default) | the CA fetches a token from port 80 of every name |
| `tls-alpn-01` | the CA connects to port 443; use it when port 80 is closed or redirected elsewhere |
| `dns-01` | a TXT record set by your `dns_hook` script; the only one that can issue `*.example.com` |

### HTTP/3, IPv6 and a redirect, with ACME

```conf
acme {
    email admin@example.com;
    challenge tls-alpn-01;
}
server {
    name example.com;
    listen 443 tls http2;
    listen [::]:443 tls http2;
    listen 443 http3;
    listen [::]:443 http3;
    tls auto;
    root /srv/www;
}
server {
    name example.com;
    listen 80;
    listen [::]:80;
    redirect_https 308;
}
```

ACME challenges on port 80 are answered only by a server with `tls auto`, so with a separate
redirect server use `tls-alpn-01`, or keep `listen 80` in the `tls auto` server (it then serves
the site on port 80 as well). `alt_svc auto` (the default) advertises the first `http3` listener to
HTTP/1.1 and HTTP/2 clients.

## Certificates from files

```conf
server {
    listen 443 tls http2;
    listen 443 http3;
    name example.com www.example.com;
    tls_cert /etc/bastion/tls/example.com.crt /etc/bastion/tls/example.com.key;
    tls_cert /etc/bastion/tls/example.com-ecdsa.crt /etc/bastion/tls/example.com-ecdsa.key;
    root /srv/www;
}
```

The certificate file is the chain, leaf first. Giving an RSA and an ECDSA pair serves each client
the one it supports. Master reads the files before the sandbox, as root, so the key can stay
`root:root 0600`; workers can never read it. After replacing the files, reload
([operations](operations.md#reload)).

Several servers on one address pick their certificate by SNI. A handshake with no SNI, or one that
names no server, gets the default server's certificate (`tls_default_cert` to choose another;
`sni_required on` refuses it).

## TLS profiles

The defaults are safe and need no tuning:

| Setting | Default |
|---|---|
| `versions` | `1.2 1.3` (1.0 and 1.1 cannot be enabled) |
| `groups` | `X25519MLKEM768 X25519 P-256` (post-quantum hybrid first) |
| `ciphers_tls12` | `ECDHE+AESGCM ECDHE+CHACHA20` (forward secrecy and AEAD only) |
| `tickets` | on, keys rotated every 12h, the newest 3 kept |
| `early_data` (0-RTT) | off |
| `ocsp_stapling` | off |
| `ktls` | `tx`: the kernel encrypts responses where it can, else user space |
| renegotiation | always refused |

A `tls_profile` changes them for the servers that name it:

```conf
tls_profile modern {
    versions 1.3;
    ocsp_stapling on;
    early_data on;
    early_data_methods GET HEAD;
}
server {
    listen 443 tls http2;
    tls_cert /etc/bastion/tls/example.com.crt /etc/bastion/tls/example.com.key;
    tls_profile modern;
    root /srv/www;
}
```

0-RTT data can be replayed by an attacker, so only the `early_data_methods` are served from it,
once per ticket across all workers. [Tuning](../tuning.md#ktls-modes-ktls-off--tx--txrx) covers
kTLS in detail.

## Client certificates (mTLS)

```conf
server {
    listen 443 tls http2;
    tls_cert /etc/bastion/tls/example.com.crt /etc/bastion/tls/example.com.key;
    tls_client_ca /etc/bastion/tls/ca.crt;
    tls_client_auth optional;
    location /admin/ {
        auth_mtls on;
        proxy http://127.0.0.1:3000;
    }
}
```

`required` fails the handshake without a certificate; `optional` lets the connection on and lets
`auth_mtls` decide per location (403 without one).

## HSTS

`security_headers basic` adds `Strict-Transport-Security: max-age=31536000` to TLS responses.
`hsts` overrides the value:

```conf
acme { email admin@example.com; }
server {
    name example.com;
    tls auto;
    security_headers basic;
    hsts "max-age=63072000; includeSubDomains";
    root /srv/www;
}
```

Neither is on by default: turn HSTS on once the site works over HTTPS, because browsers remember
it for `max-age`.
