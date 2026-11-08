# Privacy

This is engineering guidance based on the [research report](research/report.md), not legal advice. Have counsel review anything you state publicly.

## Two modes

| | Standard | Strict |
|---|---|---|
| Runs | Device, network and interaction signals, scored on your server, plus proof of work | Proof of work and a transient rate counter |
| Detects bots | Partly; see the [limits](../README.md#what-it-does-not-do) | **No.** It raises the cost per request |
| Device reads | Yes; see the [signal register](SIGNALS.md) | None |
| Available as | Default image, per site | Default image per site, or a strict-only image without the code |

## Strict mode guarantees

Each can be tested by you. `npm run lab` tests them in a real browser, and CI checks the bundles and image.

| Guarantee | How to verify |
|---|---|
| No script reads of device or browser properties | `web/test/strict-audit.test.mjs`, and the lab's instrumented browser run, which also proves it detects reads on a standard site |
| No cookies, localStorage or IndexedDB | Browser storage inspection |
| No persistent or per-device identifier | Inspect `/v1/submit` and Valkey |
| No mouse, keystroke or timing telemetry | Network capture: the submit body holds only `c` and `nonces` |
| No third-party requests | Network capture |
| Address used only for a rate counter, under a daily pseudonym, for two minutes | `rl:*` keys in Valkey |
| No TLS or header fingerprinting | Strict sites never run the risk engine |
| Solve time is not used | `handleSubmit` in `internal/server/flow.go` |
| Strict-only image has no collector code | CI checks the image and the Go dependency graph; `sweetcaptcha ipdata` doesn't exist there |

HTTP itself still carries an address and headers to your server, and your own reverse proxy may log them. `/v1/transparency?sitekey=…` states the running configuration in machine-readable form.

The strict mode argument, that a proof-of-work solution isn't "information stored in or accessed from" the device under Art. 5(3), is our own reasoning and is untested.

## What standard mode keeps

| Data | Retention |
|---|---|
| Raw signals | Discarded after evaluation |
| IP address | Never stored |
| Rate counter | 2 minutes, under a daily-rotating pseudonym |
| Pointer path hash | 10 minutes, keyed per site and day |
| Wait path counter | 1 hour, under a daily-rotating pseudonym |
| Rule identifiers and score during escalation | About 11 minutes |
| Reason codes inside a token | Until the token expires |
| Aggregate counters | 35 days, counts only |

These periods are engineering choices. No regulator prescribes them. Hashed signals remain pseudonymous personal data for an operator who holds the key, so "anonymous" is the wrong word.

## Your obligations as operator

You are the controller. Self-hosting removes third-party transfer. It does not remove these questions.

**ePrivacy Art. 5(3) applies to standard mode.** The EDPB's Guidelines 2/2023 treat reading device properties and sending anything derived from them as access, even first-party and even when only a score or hash is sent. So computing a result in the browser doesn't avoid it.

**The security exemption is available but contested.**

- In favour: WP29 Opinion 9/2014, DSK OH Digitale Dienste v1.2 (for login protection and user-oriented security), and CNIL's FAQ for tools whose sole purpose is securing a site or login.
- Against: Austria's BVwG (W298 2274626-1, 2024) called reCAPTCHA "technically not necessary" in reasoning not limited to third parties, and a 2026 CNIL FAQ on email pixels is reported to exclude general bot detection. No court ruling on a self-hosted CAPTCHA was found.

Strength by use, in our own grading: login and credential defence is strongest, then password reset and account creation, then contact and comment forms. Site-wide scoring is weakest. In the UK, PECR now names fraud prevention as a strictly necessary purpose. The EU Digital Omnibus isn't law.

**So, for each protected form, keep a record of:**

1. The Art. 5(3) or § 25 TDDDG exemption analysis, or your consent basis.
2. A separate legitimate-interest assessment under GDPR. German guidance says this cannot substitute for point 1.
3. Whether a DPIA is needed, particularly with interaction signals on.
4. Processors in the path, such as a CDN, WAF or managed Redis.

**Consent is a poor fallback for detection,** because a bot would simply refuse. If a visitor refuses, offer the path that doesn't read device data. A strict-mode site is the natural choice.

**Don't reuse security data for analytics,** because that destroys the exemption argument. Don't gate legally mandated flows, such as a cancellation button, without an alternative.

**Accessibility.** The EU Accessibility Act has applied to in-scope consumer services since June 2025. Keep the wait path on. WCAG 2.2 SC 3.3.8 bars cognitive tests in authentication without an alternative. No accessibility testing with disabled users has been done on this project yet.

## What you can defensibly say

| Avoid | Why | Say instead, only if true for your configuration |
|---|---|---|
| "GDPR compliant" | Attaches to the controller, not a tool | "Designed to support data minimisation. You remain the controller." |
| "No consent needed", "no cookie banner" | Contested | "Strict mode sets no cookies and reads no device fingerprint. Whether consent is required depends on configuration and national law." |
| "Anonymous", "no personal data" | IP addresses are often personal data; hashes are pseudonymous | "Does not store IP addresses. Signals are discarded after evaluation." |
| "No tracking" | Overbroad if any linkage exists | "No cross-site identifiers, no third-party sharing, no reuse for analytics, in the software as shipped." |
| "Approved by CNIL/DSK" | No such approval exists | "Defaults take CNIL's FAQ and the DSK guidance into account. This is not regulator approval." |
| "Nothing leaves your browser" | False in standard mode | "Raw signals stay in the browser; only coarse features go to your own server." |
| "Bot-proof", "as good as Turnstile" | Unsupported | "Raises attacker cost; verified on your server. Dated results by attacker tier are published." |

## Licensing note

Only JA4 is implemented, which is BSD licensed. JA4H, JA4T and the other JA4+ methods restrict hosted use and are left out on purpose.
