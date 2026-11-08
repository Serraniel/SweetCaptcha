# Threat model

This document lists the ways SweetCaptcha can be bypassed or abused, what defends against each, and what remains open. It assumes the attacker has read the source code. The code is open, so any defence that relies on secrecy of method is worth nothing.

## What is protected

| Asset | Why it matters |
|---|---|
| The action behind a form (sign-up, login, comment, checkout) | This is what attackers want. SweetCaptcha only adds cost to each attempt. |
| Pass tokens | A valid token is the only thing a site's backend checks. |
| Site secrets and the master key | With these, anyone can mint or verify tokens. |
| Visitors' privacy | The service must not become a tracking tool. |
| Availability | If the service fails, forms fail closed. |

## Attacker tiers

| Tier | Example | Expected outcome |
|---|---|---|
| T1: plain HTTP client | `curl`, Python `requests` | Denied or given a puzzle |
| T2: stock browser automation | Playwright, Puppeteer, Selenium | Denied |
| T3: patched automation | Stealth plugins, a hidden automation flag, JavaScript patches | Mostly a puzzle |
| T4: AI agent | Browser agents acting from screenshots or the DOM | Puzzle when it moves unnaturally. Passes when it moves like a person. |
| T5: forged protocol | A client that forges the whole signal document | Passes behind a reverse proxy. Gets the checkbox under native TLS. |
| T6: real browser and real-looking input | Engine-patched browser, residential proxy, humanised input | Passes |
| T7: humans | Solver farms, CAPTCHA-solving services | Passes, at a price per solve |

T5 to T7 are structural limits that apply to every CAPTCHA. The aim is to make each attempt cost something, not to stop every attempt.

## Bypass routes

Each row gives the route, what defends against it today, and what is left.

### Getting a token without being a person

| Route | Current defence | Residual risk |
|---|---|---|
| Solve proof of work natively, without a browser | Missing or invalid signals send the client to a puzzle | Forged signals (next row) |
| Forge the signal document | Header and TLS cross-checks; keyed hashes tied to the challenge; a hidden link in the frame that catches scrapers following every link | **High behind a plain proxy.** Every client value can be forged, and the code shows how. Native TLS exposes non-browser handshakes, but that only adds the checkbox. |
| Patch JavaScript in a real browser | Native-function, Proxy and descriptor checks; Worker and iframe comparison | Engine-level patches (Camoufox and similar) are invisible to these checks. |
| Move and type like a person | Behaviour rules only catch crude automation | **High.** Libraries for human-like input are common. Behaviour evidence has a short shelf life. |
| Click the checkbox with a script | Untrusted clicks and clicks with no approach path lead to a puzzle | Real input events with a curved path pass. |
| Solve the puzzle with AI | Families aimed at AI weaknesses; one answer per puzzle; three attempts | A solver built for one family. The kinetic shapes can be recovered by comparing frames. |
| Guess puzzle answers | One answer per puzzle, three attempts. Per attempt: line trace and stack order 1 in 30, kinetic 1 in 511 or less, gap rings 1 in 4,095 or less | Three guesses at line trace or stack order pass about 10% of the time. That is why tasks go only to questionable clients, and why repeated attempts raise the per-address counters. |
| Take the wait path instead of a puzzle | Only offered to clients without contradictions; at most 5 per hour per address; a minimum of 8 seconds; reported as `via: wait` | Residential proxies multiply the quota. Sites that ignore `via` accept these tokens. |
| Pay human solvers | Optional `bind_client` | Solvers on the bot's own network, or proxied through it |

### Misusing tokens

| Route | Current defence | Residual risk |
|---|---|---|
| Reuse a token | Atomic single-use redemption; fails closed if the store is down | None known |
| Use a token on another site | Sealed site key, checked against the secret | None known |
| Use a token for another host or action | Allow lists rechecked at verification | Only as strict as the site configures them |
| Move a token from the solver to the attacker | Optional `bind_client` | Without `bind_client`, nothing; with it, only a farm using the same network passes. |
| Collect tokens in advance | Five-minute expiry | A farm can run just in time. |

### Weak integrations

| Route | Current defence | Residual risk |
|---|---|---|
| The site checks only `success` | `score_only` is off by default, so low scores mean a task | Sites that turn on `score_only` must check `score`. |
| The site never calls siteverify | None possible | Documentation only |
| The secret ends up in the browser | Documentation only | Integrator error |

### Attacks on the service

| Route | Current defence | Residual risk |
|---|---|---|
| Flood challenge requests | Per-address rate limit with HTTP 429; work grows on a log scale with load | Distributed floods, which the operator's own edge protection must handle |
| Make puzzle generation expensive | A puzzle costs about 20-50 ms and is only reached after proof of work | A distributed attacker who pays the work can still add server load. |
| Brute-force the admin token | Constant-time comparison; failures throttled per address | None known |
| Brute-force site secrets at siteverify | Constant-time comparison; secrets are at least 16 characters; invalid secrets throttled per address | None known |
| Forge `X-Forwarded-For` | Believed only from configured trusted proxies | Misconfigured `trusted_proxies` |
| Read raw signals from storage | Raw signals are never stored | None known |
| Steal keys from the container | Read-only, non-root, distroless image | Host compromise |

### Tuning against the open rules

An attacker can run SweetCaptcha locally and tune their tools until they pass. This cannot be prevented in an open project, and it is the main reason client checks lose value over time. The counter is maintenance: keep the lab current, watch `rule_*` counters and puzzle solve rates per family, and retire what stops working.

## Proposals, ranked by value for cost

| # | Proposal | Value | Cost | Trade-off |
|---|---|---|---|---|
| 1 | **Run native TLS** (operator action) | Turns the strongest forgery route (T5) into a checkbox | Configuration only | The captcha needs its own hostname or TCP passthrough. |
| 2 | **Optional token binding to the client address**: a pseudonym of the solver's address is sealed into the token, and siteverify compares it when `remoteip` is sent | Stops simple token handover from solver farms, and from AI services solving on separate infrastructure | Small | Mobile and IPv6 users who change address within five minutes fail. Opt-in, and compare by /24 for IPv4 and /48 for IPv6. |
| 3 | **Throttle failures** on siteverify and the admin API, per address | Closes secret and token brute forcing | Small | None |
| 4 | **Make stack order harder to guess**: ask for the back and the front shape among six | Guessing per attempt from 1 in 5 to 1 in 30 | Small | Slightly longer task |
| 5 | **Minimum human answer time for tasks**: reject answers faster than people can give them | Catches instant automated solving | Small | Must exempt nobody, so set it conservatively |
| 6 | **Randomise collector probes per challenge** | Forgers must run real JavaScript each time instead of replaying a template | Medium | Delays rather than prevents; makes the signal register harder to audit |
| 7 | **Signed agents (Web Bot Auth)** as a separate policy class | Legitimate agents can identify themselves | Medium | Only cooperative agents sign. |
| 8 | **Keep the adversarial lab current** with maintained stealth tools | Shows when a rule stops working | Ongoing | Needs maintenance |

Proposals 2 to 5 are implemented (issues #26, #27, #28 and #29). Proposal 1 is an operator decision, documented in [Operations](OPERATIONS.md). Proposals 6 to 8 are open for later.

## What an operator should do

1. Run native TLS on a dedicated hostname.
2. Set exact `hostnames` and `actions` per site.
3. Check `score` and `via` on high-value actions, not just `success`.
4. Put per-account and per-action limits behind every protected form.
5. Watch the admin counters for rising puzzle pass rates or shifts in `rule_*` hits.
6. Use shadow mode before enforcing, and test with assistive technology.
