# Operations

## Configuration

Copy `config/sweetcaptcha.example.yaml` (or run `scripts/init-env.sh`). `${VAR}` values come from the environment. Generate keys with:

```sh
docker compose run --rm sweetcaptcha keygen
```

Set `demo: false` in production. Each site needs its own `sitekey`, `secret` and `hostnames`. `*.example.com` matches subdomains but not the apex. Localhost entries are also allowed over plain HTTP.

| Setting | Default | Notes |
|---|---|---|
| `mode` | `standard` | Or `strict`. |
| `token_ttl` | `5m` | 30 s to 30 min. Keep it short, since single-use tokens are what charge per action. |
| `pow.base` | sha256, 15 bits, 10 puzzles | Raising it hits the slowest phones first. Solve times on phones have not been measured for these defaults. |
| `pow.step_up` | sha256, 18 bits, 16 puzzles | `scrypt` is available and narrows the GPU advantage. Start with low bits, because each attempt is far slower. |
| `pow.wait` | sha256, 21 bits, 24 puzzles | An estimated 10 s on a desktop to a few minutes on a slow phone, not measured. |
| `policy.shadow` | `false` | Records decisions without enforcing them. |
| `policy.on_definitive` | `deny` | Or `puzzle`. |
| `limits` | 30 and 300 per minute | Above soft, difficulty rises. Above hard, requests get HTTP 429. |
| `puzzles` | all three | Disable a family if its solve rate climbs. |
| `wait_fallback` | `true` | Keep this on unless another accessible route exists. |
| `support_url` | none | Shown on a deny and beside puzzles. |
| `test_mode` | none | `pass` or `fail` for integrator tests. Never use it in production. |

## Roll out in shadow mode

1. Set `policy.shadow: true`. Every visitor gets a token, and the score and reasons are recorded.
2. Watch `/admin/` for at least a week. `shadow_would_challenge` shows how many people would have been interrupted, and the `rule_*` counters show why.
3. Test by hand with keyboard-only navigation, a screen reader, a VPN, Tor and your own mobile devices.
4. Set `step_up_above` using the suggestion on the admin page, which needs at least 500 sessions, then turn shadow off.

## TLS decides how much evidence you get

The service only sees the TLS handshake on connections it terminates itself. Pick the first option you can.

| Setup | TLS evidence |
|---|---|
| Dedicated hostname, `server.tls` set, or TCP passthrough | Full |
| A terminator that forwards JA4, with `server.ja4_header` set and its address in `trusted_proxies` | Partial: no GREASE data |
| Plain reverse proxy | None, reported as unavailable and not treated as suspicious |
| CDN in front | None: the origin sees the CDN's handshake |

To enable native TLS:

```yaml
server:
  tls:
    listen: ":8443"
    cert_file: /etc/sweetcaptcha/cert.pem
    key_file: /etc/sweetcaptcha/key.pem
```

Publish the port in `compose.yaml` and mount the certificate. Keep HTTP/3 off this hostname.

## Behind a reverse proxy

Set `trusted_proxies` to your proxy's address. Otherwise rate limits see one client, and `X-Forwarded-For` is ignored. Set `SWEETCAPTCHA_BIND` to choose the published address.

## Security headers on your pages

If your site uses a Content Security Policy, allow the captcha host in `script-src` and `frame-src`. Standard mode loads a second script from that host.

## People without JavaScript

The widget needs JavaScript, so add a `<noscript>` message with a contact route on forms where that matters.

## Offline operation

The `ipdata` service downloads public lists once a day from iptoasn.com, torproject.org, Amazon and Google. It sends no visitor data. Remove the service to run with no outbound traffic: the datacenter rule then stays silent. The list of hosting networks is hand-maintained in `internal/ipdata`.

## Monitoring

- `/healthz`: process is up.
- `/readyz`: store is reachable.
- `/admin/`: counters per site for up to 35 days. Requires `admin.token`.
- `/v1/transparency?sitekey=…`: what this site's configuration reads and keeps. Public by design.

Logs contain no addresses or signals, and shadow mode logs only rule identifiers.

Watch for a rising puzzle pass rate or falling solve times in a family, which suggest it has been automated. Re-run the lab when browsers or stealth tools change.

## Failure behaviour

| Failure | Behaviour |
|---|---|
| Store down at verification | Fails closed, returning an error |
| Store down at rate check | Allowed through, with a log entry; proof of work and tokens still apply |
| IP lists missing | Datacenter rule stays silent |
| Service down | The widget reports an error through the error callback, and the form can't get a token |

## Upgrades

Restarts lose nothing of value: state is short-lived and Valkey keeps no persistence. Rotating `master_key` invalidates outstanding tokens and challenges.
