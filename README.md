# SweetCaptcha

A self-hosted CAPTCHA that verifies most visitors without a task. It runs as a Docker stack and offers API compatibility with reCAPTCHA, hCaptcha and Turnstile. Nothing is sent to a third party.

It combines server-side checks on device and network consistency, interaction analysis, proof of work and single-use tokens. Questionable clients get more work or an interactive task. An opt-in strict mode, also available as a separate image, removes all device and interaction signals and uses proof of work only.

## Quick start

```sh
scripts/init-env.sh          # creates .env with random secrets, and local configs
docker compose up -d --build
```

Open <http://localhost:8787/demo/> to try each mode and provider API.

For the strict-only build, which contains no detection code:

```sh
docker compose -f compose.strict.yaml up -d --build
```

Then see [Operations](docs/OPERATIONS.md) before using it in production. In particular, TLS setup decides how much of the network evidence is available.

## Integrating

Add the script and an element to your form, then verify the token on your server:

```html
<script src="https://captcha.example.com/v1/api.js" async defer></script>
<form method="post">
  <div class="sweetcaptcha" data-sitekey="YOUR_SITEKEY"></div>
  <button>Send</button>
</form>
```

```sh
curl https://captcha.example.com/v1/siteverify \
  -d secret=YOUR_SECRET -d response="$SC_RESPONSE_FIELD"
```

To migrate from another provider, change its base URL to your SweetCaptcha host:

| Provider | Script | Verify | Form field |
|---|---|---|---|
| reCAPTCHA v2 and v3 | `/recaptcha/api.js` | `/recaptcha/api/siteverify` | `g-recaptcha-response` |
| hCaptcha | `/1/api.js` | `/siteverify` | `h-captcha-response` |
| Turnstile | `/turnstile/v0/api.js` | `/turnstile/v0/siteverify` | `cf-turnstile-response` |

[Compatibility](docs/COMPATIBILITY.md) lists what is covered, what isn't, and which applications allow a custom endpoint.

## How a visitor is handled

| Evidence | What happens | Visitor sees |
|---|---|---|
| Nothing suspicious | Token issued | A brief "Verified" |
| Soft evidence | More proof of work | A short delay |
| Strong contradictions | Interactive task, or a longer wait with no task | A puzzle or a progress bar |
| Explicit automation markers, or strong evidence combined with network evidence | Denied, with an optional support link | An error |

The score, reason codes and route are available only to your server, at verification. Details are in [Architecture](docs/ARCHITECTURE.md), and every signal is in the [signal register](docs/SIGNALS.md).

## What it does not do

**No CAPTCHA can reliably stop every bot and AI agent, and this one doesn't either.** It is built to stop commodity automation and today's default agents, and to put a cost on the rest. These limits are real:

- **A real browser with humanised input usually passes.** So does an agent running in a real person's browser. Their environment is coherent because it is real.
- **Human solver farms pass the task itself.** Only rate and reuse evidence can touch them.
- **A complete forgery of the signal document passes when TLS isn't terminated by this service.** All client signals can be fabricated, and the code is open. With native TLS, an HTTP client's handshake exposes it, but that only triggers more proof of work.
- **First visits are weaker than at global vendors.** Self-hosting means having no cross-site reputation data.
- **Interaction signals will decay.** The strongest one today, a click with no pointer path, is easy for agents to fix.
- **False positives on people have not been measured.** The lab uses no real people. Keyboard-only, screen-reader, switch and eye-tracking users, and people using VPNs, are the groups to test first. Run in [shadow mode](docs/OPERATIONS.md#roll-out-in-shadow-mode) before enforcing.
- **Rule weights are engineering estimates**, not fitted values.
- **Strict mode doesn't detect bots.** It raises the cost per request and nothing more.

Keep per-action limits and abuse controls behind any form this protects.

## Measured results

From the [lab](docs/LAB_RESULTS.md), which runs real Chromium and the real binary. It covers one browser on one machine and is a regression suite, not an efficacy study.

| Attacker | Outcome |
|---|---|
| HTTP client naming itself | Denied |
| HTTP client claiming to be Chrome | Puzzle |
| Stock Playwright | Denied |
| Automation flag hidden, agent-style input | Puzzle |
| Script-patched `webdriver` | Puzzle |
| Humanised pointer and typing | **Passes** |
| Fully forged signal document | **Passes**; more proof of work under native TLS |

## Privacy

Everything is processed on your server. Signals are reduced in the browser where possible, evaluated once and then discarded. IP addresses are not stored, and rate counters use a pseudonym that rotates daily and expires within minutes.

**That does not make a deployment compliant by itself.** You are the controller. In the EU, reading device properties falls under ePrivacy Art. 5(3) even when self-hosted, and whether the security exemption covers a given form is contested. [Privacy](docs/PRIVACY.md) has the analysis, the strict-mode guarantees and how to test them, plus wording you can and can't defensibly use. It is not legal advice.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Operations](docs/OPERATIONS.md)
- [Privacy](docs/PRIVACY.md)
- [Compatibility](docs/COMPATIBILITY.md)
- [Signal register](docs/SIGNALS.md)
- [Lab results](docs/LAB_RESULTS.md)
- [Research report](docs/research/report.md) and [notes](docs/research/notes)

## License

[MIT](LICENSE). See [NOTICE](NOTICE) for JA4 attribution.
