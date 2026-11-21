# Automatic certificates (ACME)

Bastion gets and renews certificates itself over ACME (RFC 8555), from Let's Encrypt by default.
[TLS](tls.md#automatic-certificates) shows the short version; this guide covers how issuance
works, the challenge types, other CAs, storage, renewal and what to do when issuance fails.

## The short version

```conf
acme { email admin@example.com; }
server {
    name example.com www.example.com;
    tls auto;
    root /srv/www;
}
```

- `acme {}` turns ACME on; without it `tls auto` is an error ("tls auto needs an acme {} block").
- `tls auto` in a server asks for one certificate covering every `name` of that server; a server
  with `tls auto` must have at least one `name`.
- Without a `listen`, a `tls auto` server listens on 443 (`tls http2`) and on 80, where every
  request except ACME challenges is redirected to https. These implied listeners are IPv4 only and
  do not include HTTP/3; write the listeners out for either ([HTTP/3](http3.md#turning-it-on)).
- `tls auto` and `tls_cert` cannot be combined in one server.

## How issuance works

1. **At load**, a `tls auto` server without a stored certificate gets a temporary self-signed
   one, so its port answers at once. Browsers will warn until the real certificate arrives.
2. **Master forks a short-lived job** when work may be due. The protocol never runs in a worker,
   nor in master itself, so a slow or hostile CA cannot stall the server. The job resolves the
   CA's host, loads the trust store and opens the storage directory, then drops to `user` and
   applies its own seccomp filter. Every URL the CA hands out must be on the directory's host.
3. **The challenge** is answered: HTTP-01 tokens and TLS-ALPN-01 certificates are put in shared
   memory, and workers answer the CA from there; DNS-01 runs your hook.
4. **The new certificate and key** are written next to the old pair and swapped in as one, behind
   a commit marker, so a crash never leaves half an install.
5. **Master reloads**, the same path as any certificate change: new connections get the new
   certificate, existing ones finish on the old.

Account and certificate keys are made locally. Issuance is logged at `info` level, so set
`error_log <path> info` to see it.

## Challenge types

| `challenge` | How the CA checks | Use it when |
|---|---|---|
| `http-01` (default) | fetches `http://<name>/.well-known/acme-challenge/<token>` on port 80 | port 80 reaches this server |
| `tls-alpn-01` | connects to port 443 with ALPN `acme-tls/1` | port 80 is closed, or handled by another server block |
| `dns-01` | looks up a TXT record your hook publishes | the server is not reachable from the CA, or for wildcard names |

HTTP-01 challenges on port 80 are answered only by a server with `tls auto`. If you write a
separate port 80 server that redirects, use `tls-alpn-01`, or keep `listen 80` in the `tls auto`
server ([TLS](tls.md#http3-ipv6-and-a-redirect-with-acme)).

### DNS-01 hook

```nginx
acme {
    email admin@example.com;
    challenge dns-01;
    dns_hook /usr/local/bin/acme-dns-hook;
}
```

The hook is run with `execve` (no shell), with only `PATH` and `LANG` in its environment, as:

```
<hook> set <name> <value>     # publish TXT <value> at <name>
<hook> clear <name> <value>   # remove it again
```

It must exit 0 once the record is visible, within 120 seconds. Both arguments are checked first
(a host name and a base64url digest). The runner that starts the hook is forked before the job
drops privileges and applies its sandbox, so the hook runs outside that sandbox: treat it like
any script run as root, and keep it owned by root and writable by nobody else.

## Choosing a CA

```conf
acme {
    email admin@example.com;
    ca letsencrypt;
    staging on;
}
server { name example.com; tls auto; root /srv/www; }
```

| Directive | Default | Meaning |
|---|---|---|
| `ca` | `letsencrypt` | `letsencrypt`, `zerossl`, or the `https://` URL of any ACME directory |
| `staging` | `off` | `on`: Let's Encrypt's staging directory (untrusted certificates, generous rate limits): use it while testing |
| `eab_kid`, `eab_hmac` | none | external account binding, required by `zerossl` and some private CAs; the HMAC is never logged |
| `ca_root` | system bundle | a PEM bundle to trust for the CA's HTTPS (a private CA) |
| `email` | none | the account contact, sent to the CA for expiry notices |
| `key_type` | `ecdsa-p256` | the certificate key: `ecdsa-p256` or `rsa-2048`; the account key is always P-256 |

ZeroSSL:

```nginx
acme {
    email admin@example.com;
    ca zerossl;
    eab_kid ${ZEROSSL_EAB_KID};
    eab_hmac ${ZEROSSL_EAB_HMAC};
}
```

Keeping the EAB values in environment variables keeps them out of the file
([configuration](../configuration.md#environment-variables)); remember that `-T` prints them.

## Renewal

| Directive | Default | Meaning |
|---|---|---|
| `renew_before` | `30d` | renew this long before the certificate expires (at least 1h) |
| `ari` | `on` | also renew when the CA's renewal information (ARI, RFC 9773) suggests a window that has started |

A failed attempt backs off exponentially per server, never retrying sooner than a CA's
`Retry-After`. The old certificate (or the temporary one) stays in use meanwhile, and one
server's failure never holds back another's.

## Storage

`storage` (default `/var/lib/bastion/acme`) holds everything, in a 0700 directory owned by `user`,
with every key 0600:

```
<storage>/accounts/<ca id>/account.key, kid
<storage>/certs/<first name>/cert.pem, key.pem
<storage>/state/<name>                        # renewal backoff
```

Back this directory up. Without it a rebuilt host issues new certificates, which counts against
the CA's rate limits. `bastion -t` creates the directory when it is missing.

## Troubleshooting issuance

| Symptom | Check |
|---|---|
| browsers warn about a self-signed certificate | issuance has not finished or failed: read the log (`journalctl -u bastion`) with `error_log ... info` |
| HTTP-01 fails | DNS for every `name` points at this host; port 80 is open and reaches this server; no other server block on port 80 takes the request |
| TLS-ALPN-01 fails | port 443 (TCP) reaches this server directly, without a TLS-terminating proxy in front |
| DNS-01 fails | run the hook by hand with `set`; it must exit 0 only once the record is visible from outside |
| testing burns rate limits | use `staging on` until issuance works, then remove it |

[Troubleshooting](../troubleshooting.md) has more.
