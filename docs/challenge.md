# The challenge

A very small proof-of-work gate. A client without a valid pass cookie gets a page. The page makes
the browser spend a fraction of a second hashing, posts the answer, and receives a cookie. The
server stores nothing about any of this.

```nginx
server {
    challenge on;              # or auto: only while under attack (challenge_auto_rps)
    challenge_difficulty 16;   # leading zero bits
    challenge_allow 203.0.113.0/24;  # API clients and monitoring are never challenged
    location /api/ { challenge off; }
}
```

## The protocol

1. A request without a valid pass gets `403` with `Cache-Control: no-store`.
   - If its `Accept` includes `text/html`, the body is the challenge page.
   - Otherwise the body is plain text with the header `Bastion-Challenge: required`, and there is
     no script.
2. The page carries a **token** `expiry.iphash.mac` and a **difficulty** (leading zero bits).
3. The browser finds a decimal **nonce** such that `SHA-256(token + "." + nonce)` starts with
   `difficulty` zero bits. Bits count from the most significant bit of the first byte.
4. It sends `POST /.bastion/challenge` as `application/x-www-form-urlencoded` with three fields:
   `token`, `nonce` and `redirect` (the original path and query). Bastion checks the token's MAC,
   its expiry, the client's IP prefix and the hash. It then answers `303`, setting the cookie
   `bastion_pass=<expiry>.<mac>` (`HttpOnly; SameSite=Lax; Path=/`, plus `Secure` over TLS) and a
   `Location` pointing at the redirect. The redirect is honoured only when it is a local path; anything
   else (`https://…`, `//host`, `/\host`, control characters) becomes `/`.
5. Later requests carry the cookie. Bastion verifies its MAC and expiry, and checks that the client
   is still in the same network (`challenge_ip_prefix4` /24 and `challenge_ip_prefix6` /56 by
   default).

A wrong answer is a plain `403`. A body over 4 KiB is `413`. With `challenge_escalate` every
refused answer is a strike that can block the client (see `escalate`).

## Keys and rotation

Master draws a random 32-byte key at start and shares it with the workers. The secret of
generation `g = floor(now / max(challenge_pass_ttl, challenge_token_ttl))` is
`HMAC-SHA-256(key, "bastion-challenge-gen:" || g)`. A token or pass is accepted under the current
generation or the previous one, so the secret rotates with one generation of overlap. A restart
draws a new key, and every client is challenged once more. All comparisons are constant time.

## A custom page

`challenge_page <file>` replaces the built-in page. The file is read when the configuration loads
and may be at most 1 MiB. Bastion replaces two placeholders:

- `{{bastion_challenge}}` becomes `<script>` elements that define:

  ```js
  window.BASTION = {
    token, difficulty, verifyUrl, redirect,
    solve(),          // does steps 3 and 4 in a Web Worker; resolves once the form is posted
    sha256(string),   // the digest as eight 32-bit words
    zeroBits(words, bits)
  }
  ```

  The built-in page calls `solve()` when it contains an element with `id="bastion-autostart"`.
- `{{bastion_nonce}}` becomes the response's CSP nonce, for the page's own `<script nonce=…>` and
  `<style nonce=…>`.

A page without `{{bastion_challenge}}` gives no client a token, so no client can pass. `bastion -t`
reports it as a warning. A page may ignore `solve()` and do the steps above itself.
`examples/challenge/custom.html` does exactly that.

## Content Security Policy

The challenge response sets its own policy, and it takes precedence over `security_headers strict`:

```
default-src 'self'; script-src 'nonce-N'; style-src 'self' 'nonce-N'; worker-src blob:;
form-action 'self'; base-uri 'none'; frame-ancestors 'none'
```

`N` is new for every response. The worker is started from a `blob:` URL. If a browser refuses it,
the work runs in short slices on the page itself.

## Clients that are not browsers

API clients, health checks and crawlers you trust cannot run the page. They get the documented
plain-text `403` and the `Bastion-Challenge: required` header, never a loop of pages. Give them a
way through: list their addresses in `challenge_allow`, or turn the challenge off for their
locations (`challenge off`). Under `challenge auto` they are refused only while Bastion is under
attack.

## `challenge auto`

```nginx
challenge_auto_rps 2000;        # requests per second across all workers
challenge_auto_block_rate 200;  # or refusals per second (limit rejects, blocks, waf denies)
challenge_auto_hold 60s;
server { challenge auto; }
```

All workers share a single flag. Once a second the helper sums the workers' counters. It turns the
flag on when either rate reaches its threshold. It turns the flag off only after both rates have
stayed below for `challenge_auto_hold`, so a load hovering around the threshold does not make it
flap. A client already holding a valid pass is not challenged again. `challenge on` and
`challenge off` ignore the flag. The log records each change, and
`bastion_under_attack_total` counts activations. The admin API (Phase 14) will be able to force
the flag. There is no other automatic mitigation.

## Caching

The challenge answers before any handler, so a challenge page never reaches the cache.
`Cache-Control: no-store` keeps it out of shared caches downstream too.
