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
| `pow.base` | sha256, 14 bits × 48 | About 0.8M hashes. See [proof-of-work balancing](#proof-of-work-balancing). |
| `pow.step_up` | sha256, 16 bits × 48 | About 3.1M hashes. Runs while the checkbox is shown. `scrypt` narrows the GPU advantage; start with low bits, because each attempt is far slower. |
| `pow.wait` | sha256, 18 bits × 48 | About 12.6M hashes. |
| `pow.wait_min_duration` | `8s` | The wait path can't finish sooner, whatever the device. This costs every client the same wall time instead of punishing slow phones. |
| `pow.growth` | `1` | How fast difficulty rises under load: 0.5 slow, 1 medium, 1.5 fast, 0 off. |
| `limits.site_baseline_per_minute` | `0` (off) | Your site's normal challenges per minute. Above it, difficulty rises for everyone. |
| `policy.shadow` | `false` | Records decisions without enforcing them. |
| `policy.on_definitive` | `deny` | Or `puzzle`. |
| `policy.score_only` | `false` | Never show a checkbox or task, like reCAPTCHA v3: every request gets a token, and the site must reject low scores itself. Use it only where the backend checks `score`, or a bot gets a valid token. |
| `limits` | 30 and 300 per minute; 5 waits per hour | Above soft, difficulty rises. Above hard, requests get HTTP 429. `wait_per_hour` caps the wait path per address, and shared addresses share the cap. |
| `puzzles` | all three | Disable a family if its solve rate climbs. |
| `wait_fallback` | `true` | Lets coherent browsers leave a puzzle for a long calculation. Never offered to clients with contradictions or automation markers. If you turn it off, people who can't do visual tasks need another route, such as `support_url`. |
| `support_url` | none | Shown on a deny and beside puzzles. |
| `test_mode` | none | `pass` or `fail` for integrator tests. Never use it in production. |

## Proof-of-work balancing

Proof of work adds friction and shapes request rates. It does not stop a funded attacker: a native solver runs about 11 times faster than browser JavaScript, and a GPU thousands of times faster, so 1,000 base solves cost an attacker a fraction of a cent. The defaults therefore keep the base level light for people, and put the work on risky or high-volume clients. The [research notes](research/notes/pow_balancing.md) compare peer products and the economics.

The widget solves in 4 workers in parallel. A fixed count avoids reading the device's core count, which strict mode must not do.

| Level | Desktop (measured) | Median phone (estimate) | Low-end phone (estimate) |
|---|---|---|---|
| Base | 0.27 s median time to token, including page load | about 1 s | up to about 3 s |
| Checkbox step | about 0.8 s | about 3 s | up to about 10 s |
| Wait path | at least `wait_min_duration` (8 s) | at least 8 s, about 10 s | up to about 30 s |

The desktop figure comes from the lab on one 8-core machine. The phone figures are estimates scaled from published measurements of other products and have not been measured. Test on your own slow devices before raising anything.

**Adaptive difficulty.** Work grows on a log scale with load, capped at 16 times the configured level:

```
boost = min(4, growth × [log2(1 + excess / 8) + log2(1 + (site rate − baseline) / (4 × baseline))])
work  = configured work × 2^boost
```

`excess` is how many challenges this address requested above `soft_per_minute` in the current minute. The site term applies only when `site_baseline_per_minute` is set. With the defaults, an address 8 over its allowance does twice the work, and one 120 over does 16 times. Requests above `hard_per_minute` get HTTP 429.

## Roll out in shadow mode

1. Set `policy.shadow: true`. Every visitor gets a token, and the score and reasons are recorded.
2. Watch `/admin/` for at least a week. `would_challenge` shows how many people would have been interrupted, and the `rule_*` counters show why.
3. Test by hand with keyboard-only navigation, a screen reader, a VPN, Tor and your own mobile devices.
4. Set `step_up_above`, the threshold for showing the checkbox, using the suggestion on the admin page, which needs at least 500 sessions, then turn shadow off.

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
