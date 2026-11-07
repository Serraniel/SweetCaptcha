# Peer products and API compatibility for a self-hosted CAPTCHA

Research date: 2026-11-07. GitHub stars, last-push dates and SPDX IDs were read from the GitHub API that day, unless another forge is named.

Source caveats:
- Most doc pages were read through a summarising fetch tool. Identifiers, URLs, field names and values are literal as returned, but descriptions are paraphrased, so check exact wording against the linked page before quoting it.
- Claims from Cap, FCaptcha, ALTCHA, Prosopo and other vendors about their own products are vendor-authored and were not independently tested.

## (A) How do the peer products compare?

### Takeaway
Permissively licensed, self-hostable, actively maintained options exist. Almost all of them are PoW-centred, and the ones that add detection use browser verification or local rules rather than cross-site intelligence. Reputation and ML intelligence sit mostly in paid tiers or hosted services. Licences are more varied than project marketing suggests: Prosopo's bot detection is closed, Private Captcha is noncommercial only, and ALTCHA Sentinel is under a commercial EULA.

### Cited Findings

#### Open or source-available projects

| Product | Licence (exact) | Self-host | Detection approach | Pricing and limits | Maintenance (last push, stars) | Sources |
|---|---|---|---|---|---|---|
| ALTCHA (widget and libs) | MIT | Yes | PoW only: PBKDF2/SHA-256 by default; SHA-*, ARGON2ID and SCRYPT available | Free | 2026-10-22, 2,884 | [repo](https://github.com/altcha-org/altcha), [README](https://raw.githubusercontent.com/altcha-org/altcha/main/README.md) |
| ALTCHA Sentinel | Proprietary (EULA, no public repo found) | Yes | Risk score from adaptive PoW up to an interactive Code Challenge, NLP spam classifier, IP reputation, interaction analysis, rate limiters | Pro €99/mo (3 instances); Enterprise €799/mo; 30-day trial; periodic licence call to eu.altcha.org, offline licence file available. ALTCHA Cloud from €47/mo | Install and deploy repos pushed 2026-11-07 | [docs](https://altcha.org/docs/sentinel/), [pricing](https://altcha.org/pricing/) |
| mCaptcha | AGPL-3.0 | Yes | PoW only: SHA-256 with difficulty rising under load | Free | **Last commit 2025-10-07, about 13 months ago**; 2,498 | [repo](https://github.com/mCaptcha/mCaptcha) |
| Cap | Apache-2.0 (LICENSE file; GitHub reports `NOASSERTION`) | Yes: Standalone Docker plus Valkey, or `capjs-core` library | PoW (HashWX default) plus instrumentation: per-challenge generated JS run in a sandboxed iframe, with automation-tool checks. Says it "doesn't try to decide whether a visitor is human" | Free | 2026-11-07, 8,280. Repo moved from tiagorangel1 to `tiagozip/cap` | [LICENSE](https://raw.githubusercontent.com/tiagozip/cap/main/LICENSE), [how it works](https://raw.githubusercontent.com/tiagozip/cap/main/docs/guide/workings.md), [instrumentation](https://capjs.js.org/guide/instrumentation) |
| FCaptcha (new, created 2025-12) | MIT | Yes: Go, Python or Node server | Behavioural: 40+ signals, input forensics, headless and CDP detection, JA3/JA4, Web Bot Auth. SHA-256 PoW is used only as a "liveness and timing gate" | Free | 2026-11-04, 233; single vendor (WebDecoy) | [README](https://raw.githubusercontent.com/WebDecoy/FCaptcha/main/README.md), [LICENSE](https://raw.githubusercontent.com/WebDecoy/FCaptcha/main/LICENSE) |
| Anubis (Techaro) | MIT | Yes (reverse-proxy gate, not a form CAPTCHA) | SHA-256 PoW plus allow/challenge/deny policy rules, weights, GeoIP; optional non-JS `metarefresh` | Free; BotStopper (unbranded) from $50/mo | 2026-11-06, 24,005; v1.28.2 on 2026-10-23; 412 open issues and PRs | [repo](https://github.com/TecharoHQ/anubis), [BotStopper](https://raw.githubusercontent.com/TecharoHQ/anubis/main/docs/docs/admin/botstopper.mdx), [LWN](https://lwn.net/Articles/1028558) |
| go-away | MIT-form text | Yes (reverse proxy) | CEL rules, JA3N/JA4 TLS fingerprints, network-range filtering, transparent and non-JS challenges, WASM custom challenges (SHA-256 PoW example) | Free | Forge updated 2026-10-24, 24 forge stars, plus mirrors | [README](https://git.gammaspectra.live/git/go-away/raw/branch/master/README.md), [LICENSE](https://git.gammaspectra.live/git/go-away/raw/branch/master/LICENSE) |
| GoCaptcha | Apache-2.0 | Yes (Go library) | Self-described "Behavior Captcha": interactive challenge generation, not PoW | Free | 2026-03-07, 2,470 | [repo](https://github.com/wenlng/go-captcha) |
| Private Captcha | **PolyForm Noncommercial 1.0.0**; commercial use needs a paid enterprise licence under EULA | Yes (community edition, noncommercial only) | PoW with "smart difficulty scaling"; algorithm not stated on the page read | Hosted €6/mo (1k requests) to €1,199/mo (1M) | 2026-11-07, 199 | [LICENSE](https://raw.githubusercontent.com/PrivateCaptcha/PrivateCaptcha/main/LICENSE), [self-hosting](https://raw.githubusercontent.com/PrivateCaptcha/self-hosting/main/README.md), [pricing](https://privatecaptcha.com/pricing/pricing.md) |
| Procaptcha (Prosopo) | Apache-2.0, **but bot detection is "the only closed-source part of the stack"** | Partly: self-hosting serves a fixed `pow`, `puzzle` or `image` type and **skips bot detection** | Hosted: invisible checks, honeypots, risk scores, VPN and proxy filtering, behavioural learning | Free 10k/mo, 1 site; Pro $39-139/mo; Enterprise from $1,990/mo | 2026-11-07, 303 | [SELF_HOSTING](https://raw.githubusercontent.com/prosopo/captcha/main/SELF_HOSTING.md), [pricing](https://prosopo.io/pricing/) |
| BotD | MIT | Client library, no server | Client-side browser-automation detection; roadmap described as stability-only | Free | 2026-11-01, 1,494 | [repo](https://github.com/fingerprintjs/BotD), [BotD vs Pro](https://dev.fingerprint.com/docs/bot-detection-vs-botd) |
| Fail2ban | GPL-2.0 (GitHub reports `NOASSERTION`) | Yes | Fail2ban-style log-driven banning; not a CAPTCHA | Free | 2026-11-07, 18,969 | [COPYING](https://raw.githubusercontent.com/fail2ban/fail2ban/master/COPYING) |
| CrowdSec | MIT (engine; licence of other components not checked) | Yes | Not researched beyond repo metadata | Not researched | 2026-11-06, 15,496 | [repo](https://github.com/crowdsecurity/crowdsec) |
| GateCHA (new, created 2026-02) | MIT | Yes | ALTCHA PoW management server, positioned as a free Sentinel alternative; no Sentinel-style detection claimed in the part read | Free | 2026-11-02, 26 | [README](https://raw.githubusercontent.com/Upellift99/GateCHA/main/README.md) |
| Wicketkeeper (new, created 2025-06) | Server AGPL-3.0; client and example MIT | Yes | PoW | Free | 2026-01-18, 229 | [LICENSE](https://raw.githubusercontent.com/a-ve/wicketkeeper/main/LICENSE) |

#### Hosted and commercial services

| Product | Licence | Self-host | Detection approach | Pricing and limits | Sources |
|---|---|---|---|---|---|
| Cloudflare Turnstile | Proprietary | No | Proprietary | Free: 20 widgets, 10 hostnames each, unlimited siteverify, 7-day analytics. Enterprise adds ephemeral IDs, offlabel and more hostnames | [plans](https://developers.cloudflare.com/turnstile/plans/) |
| hCaptcha | Proprietary | No | Proprietary; scores are Enterprise only | Basic free (limit not stated); Pro $139/mo or $99/mo billed yearly, 100k evals then $0.99/1k; Enterprise custom | [pricing](https://www.hcaptcha.com/pricing), [docs](https://docs.hcaptcha.com/) |
| reCAPTCHA | Proprietary | No | Proprietary; v3 score | Essentials free, 10k assessments/mo per organisation, 4 score levels. Premium: $8 flat for 10,001-100k, then $1/1k, 11 levels. Enterprise: 12-month commitment. Classic keys were due to move to Google Cloud by end of 2025 | [tiers](https://docs.cloud.google.com/recaptcha/docs/compare-tiers), [billing](https://docs.cloud.google.com/recaptcha/docs/billing-information), [migration](https://cloud.google.com/recaptcha/docs/migration-overview?hl=zh-cn) |
| Friendly Captcha | Widget code: `friendly-challenge` MIT, `friendly-captcha-sdk` MPL-2.0. Service proprietary | Proxy only: the "Self-Hosted Endpoint" forwards to their API | PoW-based widget; Risk Intelligence is a paid add-on (Advanced and Enterprise) | Starter €9 (1k/mo), Growth €39 (5k/mo), Advanced €200 (50k/mo) as reported from their signup page; Enterprise custom | [friendly-challenge](https://github.com/FriendlyCaptcha/friendly-challenge), [SDK](https://github.com/FriendlyCaptcha/friendly-captcha-sdk), [endpoint](https://developer.friendlycaptcha.com/docs/v2/guides/self-hosted-endpoint), [siteverify](https://developer.friendlycaptcha.com/docs/v2/api/siteverify), [signup](https://friendlycaptcha.com/signup/) |
| MTCaptcha | Proprietary | On-prem not mentioned; first-party subdomain hosting is Enterprise | Includes "IP-based invisible captcha" and Threat SPECT at Business tier and up | Free 10k/mo, 1 domain; Core $29; Pro $95; Business $170; Enterprise custom | [pricing](https://www.mtcaptcha.com/pricing) |
| Fingerprint Pro | Proprietary (uses BotD plus proprietary technology) | Not established | Adds server-side detection of AI agents and crawlers | About $99/mo entry, overage reported at $4/1k. **Third-party figures only** | [BotD vs Pro](https://dev.fingerprint.com/docs/bot-detection-vs-botd), [competitor blog](https://cside.com/blog/fingerprintjs-pricing), [Capterra](https://www.capterra.com/p/218586/FingerprintJS/alternatives/) |
| Geetest | Proprietary | Vendor-assisted private deployment offered | Adaptive CAPTCHA and device fingerprinting products | Quote-based; GetApp's "3000 per year" figure is unverified | [deployment guide](https://www.geetest.com/en/article/online-service-deployment-choosing-guide), [GetApp](https://www.getapp.com/security-software/a/geetest-captcha/) |
| CaptchaFox | Proprietary | Not mentioned; EU hosting | "Adaptive Bot Protection", bot and proxy/VPN detection, no technical detail | Starter €15 (10k/mo), Growth €39 (30k), Team €85 (100k), Enterprise custom | [pricing](https://captchafox.com/pricing) |
| TrustCaptcha (TrustComponent) | Not stated | Not mentioned; EU infrastructure | Dynamic PoW on all plans; bot scoring (about 35 signals) only from Solo up | Free noncommercial 500/mo (PoW only); Hobby €8; Solo €36 (10k); Team €168; Enterprise €289 | [pricing](https://www.trustcomponent.com/en/products/captcha/pricing) |

Other 2025-2026 GitHub entrants worth a look (metadata and self-descriptions only, from a [GitHub search](https://api.github.com/search/repositories?q=captcha+self-hosted+created:%3E2025-01-01&sort=stars&per_page=15) and a [second search](https://api.github.com/search/repositories?q=proof-of-work+bot+protection+created:%3E2025-01-01&sort=stars&per_page=10)):
- `terem42/pow-ddos-challenge`: MIT, Nginx/OpenResty PoW, 9 stars.
- `hellmany/botguard`: no licence reported, Go middleware with JA4/ASN classification and PoW, 1 star.
- `n1yshi/Aegis-AntiBot`: MIT, 0 stars.

The same searches show a growing self-hosted **solver** ecosystem (`germondai/trawl`, `shenhao-stu/ohmycaptcha`), which matters for the threat model.

### Inferences
- The strongest candidates for a permissive, self-hosted, maintained base are Cap and FCaptcha for form CAPTCHAs, and Anubis or go-away for page gating. FCaptcha has the widest detection claims but is about 11 months old and comes from one vendor.
- mCaptcha's 13-month gap in commits makes it a poor foundation, though its AGPL licence and PoW approach remain a valid reference.
- GoCaptcha's "behavior" label seems to mean the kind of interaction the user performs, not risk analysis. I infer this from its positioning and did not review the code.

### Gaps
- `cap.so` could not be tied to this project. The sources found are `tiagozip/cap` and capjs.js.org, with a possible second docs domain at trycap.dev.
- Friendly Captcha's pricing page returned 404 at both URLs tried, so its prices come from search excerpts of its signup page. A free tier is hinted at by [a "Free CAPTCHA" page](https://friendlycaptcha.com/?p=16210) but not confirmed.
- No confirmation of current Fingerprint Pro prices from the vendor, or of Geetest prices at all.
- MTCaptcha, CaptchaFox and TrustCaptcha pricing pages do not mention on-prem. That is absence of evidence, not confirmation that it is unavailable.
- Sentinel's EULA text was not read, and its licence type is taken from the pricing page's description.

## (A) Is it true that "those offering true bot prevention, rather than only proof of work, are all paid"?

### Takeaway
**Partly true, but false as stated.** Free behavioural detection exists both as hosted services and as open-source self-hosted software. The narrower version holds up much better: a self-hosted product with mature cross-site reputation and ML intelligence is, among those reviewed, paid or closed. The exceptions below are real but young, narrower in scope, or unproven.

### Cited Findings

**Evidence for the belief**
- ALTCHA's open-source widget relies on PoW alone, while multi-signal risk scoring is in Sentinel, which needs a paid production licence — [Sentinel docs](https://altcha.org/docs/sentinel/); [pricing](https://altcha.org/pricing/).
- Prosopo's self-hosted path skips bot detection, "the only closed-source part of the stack" — [SELF_HOSTING.md](https://raw.githubusercontent.com/prosopo/captcha/main/SELF_HOSTING.md).
- Private Captcha needs a paid licence for commercial self-hosting — [self-hosting repo](https://raw.githubusercontent.com/PrivateCaptcha/self-hosting/main/README.md).
- TrustCaptcha's bot scoring starts at the Solo plan, €36/mo — [pricing](https://www.trustcomponent.com/en/products/captcha/pricing).
- Friendly Captcha's Risk Intelligence is a paid add-on — [siteverify docs](https://developer.friendlycaptcha.com/docs/v2/api/siteverify).
- hCaptcha's score and passive modes are in paid tiers — [pricing](https://www.hcaptcha.com/pricing).
- Anubis's planned advanced fingerprinting challenge is described as private to commercial BotStopper — [BotStopper docs](https://raw.githubusercontent.com/TecharoHQ/anubis/main/docs/docs/admin/botstopper.mdx).

**Exceptions: free and self-hostable**
- **FCaptcha** (MIT) claims behavioural and environmental detection, explicitly open source, with no phone-home. It publishes a benchmark harness with human personas and per-signal false-positive budgets — [README](https://raw.githubusercontent.com/WebDecoy/FCaptcha/main/README.md).
- **Cap** (Apache-2.0) adds browser verification and automation-tool checks on top of PoW — [instrumentation](https://capjs.js.org/guide/instrumentation). Its marketing says "Turnstile-tier", which is a vendor claim; its own technical page says it does not try to decide humanity — [migration page](https://raw.githubusercontent.com/tiagozip/cap/main/docs/guide/alternatives/migrate-from-recaptcha.md); [how it works](https://raw.githubusercontent.com/tiagozip/cap/main/docs/guide/workings.md).
- **go-away** (MIT-form) offers TLS fingerprinting, CEL rules and network filtering — [README](https://git.gammaspectra.live/git/go-away/raw/branch/master/README.md).
- **BotD** (MIT) detects automation client-side but is only a library, and Fingerprint says paid Pro adds server-side AI agent and crawler detection — [comparison](https://dev.fingerprint.com/docs/bot-detection-vs-botd).
- **Anubis** (MIT) combines rule and weight policy with GeoIP as well as PoW — [policies](https://raw.githubusercontent.com/TecharoHQ/anubis/main/data/botPolicies.yaml); [GeoIP note](https://raw.githubusercontent.com/TecharoHQ/anubis/main/docs/docs/admin/thoth.mdx).

**Exceptions: free of charge but hosted and closed**
- Turnstile's free plan has unlimited verification — [plans](https://developers.cloudflare.com/turnstile/plans/).
- hCaptcha Basic — [pricing](https://www.hcaptcha.com/pricing).
- reCAPTCHA Essentials, 10k/mo — [tiers](https://docs.cloud.google.com/recaptcha/docs/compare-tiers).
- MTCaptcha Free, 10k/mo — [pricing](https://www.mtcaptcha.com/pricing).
- Prosopo Free, 10k/mo with invisible checks and honeypots — [pricing](https://prosopo.io/pricing/).

### Inferences
- The real dividing line appears to be **cross-site data, not behavioural analysis**. Local signals can be open-sourced, as FCaptcha and go-away show. Reputation at scale depends on traffic a single self-hoster does not see, which explains why it stays hosted or paid.
- This leaves a usable position for SweetCaptcha: open local detection, with optional pluggable feeds. It also means parity with Turnstile should not be promised.
- Open detection logic is easier for attackers to study. FCaptcha accepts that trade-off explicitly with an "open algorithm"; whether it holds up in practice is untested.

### Gaps
- **No independent efficacy data** was found comparing FCaptcha, Cap or any other open detector with Turnstile or reCAPTCHA. "True bot prevention" therefore cannot be ranked from evidence, only by feature list.
- CrowdSec's relevance as a free reputation source was not researched.

## (A) How effective is proof of work, and which algorithm?

### Takeaway
PoW rate-limits and filters clients that do not run JavaScript, but it does not prove humanity and does not price out a resourced attacker. Algorithm choice matters a lot against GPUs (SHA-256 about 150x CPU, HashWX about 2x on one unpublished measurement), but not against botnets, and phones pay a large and regressive cost.

### Cited Findings

**Foundational research**
- Laurie and Clayton (2004) concluded that PoW would not solve spam: a setting costly enough for spammers would stop many legitimate senders, and hijacked machines could do the computing — [paper](https://www.cl.cam.ac.uk/~rnc1/proofwork.pdf). Its scope is per-email PoW, not web CAPTCHAs.

**Anubis critiques and controversies**
- Tavis Ormandy (page undated, apparently about August 2025) calculated about 2^16 SHA-256 operations per token at the default difficulty, with 7-day access. He solved a challenge in about 0.017 s with a small C program, estimated the compute at about $0 per week across deployments, and found a double-spend issue that was then fixed — [post](https://lock.cmpxchg8b.com/anubis.html).
- Farid Zakaria (2026-07-09): at difficulty 4, 65,536 hashes take about 1.3 ms in native Go against about 130 ms in browser JS, with 1-5 s felt by users. Scrapers can cache the cookie and pay once, and he released `anubis-fetch`, which impersonates Chrome's TLS fingerprint. At an assumed 2 s and 20 J per solve, 1M solves/day costs about 23 person-years and about 2 MWh per year; he calls these rough — [post](https://fzakaria.com/2026/07/09/who-does-anubis-actually-stop).
- flexagoon argues Anubis works mainly because LLM bots do not run JavaScript, and that bots which do can solve it, citing Huawei's — [post](https://fxgn.dev/blog/anubis/).
- Xe Iaso's reported counterpoint is that Anubis is "mostly doing rate limiting" and that many low-effort bots never run the challenge — [RuntimeWire](https://runtimewire.com/article/anubis-bypass-proof-of-work-bot-wall-limits) (secondary).
- Duke's pilot blocked over 4M unwanted requests per day, but some real users were blocked, usually because cookies were disabled. LWN also notes a bus-factor concern and an unclear line between project and business, and LWN itself chose not to deploy — [LWN](https://lwn.net/Articles/1028558).
- JavaScript-disabled users were blocked until the `metarefresh` challenge arrived, which remains off by default because of false-positive concerns — [OSnews](https://www.osnews.com/story/142765/anubis-tool-to-stop-ai-crawler-abuse-gains-non-javascript-option/); [docs](https://raw.githubusercontent.com/TecharoHQ/anubis/main/docs/docs/admin/configuration/challenges/metarefresh.mdx).
- Default difficulty is 4 (a few seconds), and 6 can take minutes — [LWN](https://lwn.net/Articles/1028558).
- **Conflict:** LWN describes Thoth reputation as a paid service, but the repo now marks it "Cancelled" and recommends GeoIP databases. The repo is more recent — [Thoth doc](https://raw.githubusercontent.com/TecharoHQ/anubis/main/docs/docs/admin/thoth.mdx).
- A report of Anubis-related downtime on cybersecurity sites on 2026-04-13 exists but is low-quality and unconfirmed — [threatcluster](https://threatcluster.io/cluster/anubis-protection-mechanism-causes-downtime-on-cybersecurity-faa26f79).

**GPU resistance by algorithm** ([Cap HashWX docs](https://raw.githubusercontent.com/tiagozip/cap/main/docs/guide/hashwx.md); figures are tevador's from an unpublished CUDA implementation, and Cap reproduced only the RSW row)

| Algorithm | CPU (Ryzen 3700X, 16 threads) | GPU (RTX 5060 Ti) | GPU advantage |
|---|---|---|---|
| SHA-256 | 41 MH/s | 6150 MH/s | ~150x |
| RSW | 26 H/s | 4400 H/s | ~170x |
| HashWX | 2.8 MH/s | 5.8 MH/s | ~2x |

**Algorithm used by each product**
- SHA-256: [mCaptcha](https://raw.githubusercontent.com/mCaptcha/mCaptcha/master/README.md), Anubis ([Ormandy](https://lock.cmpxchg8b.com/anubis.html)), and go-away's [example challenge](https://git.gammaspectra.live/git/go-away/raw/branch/master/README.md).
- PBKDF2/SHA-256 by default, with optional ARGON2ID and SCRYPT: [ALTCHA](https://raw.githubusercontent.com/altcha-org/altcha/main/README.md).
- HashWX by default in Standalone, opt-in in the core library, RSW deprecated: [Cap](https://raw.githubusercontent.com/tiagozip/cap/main/docs/guide/hashwx.md).
- SHA-256 hashcash used as a timing gate, where a solution under 1.5 s is scored as too fast: [FCaptcha](https://raw.githubusercontent.com/WebDecoy/FCaptcha/main/README.md).
- Argon2id at 256 MB was about 72x slower to crack than PBKDF2 on an RTX 5080 at equal user verification time, but high memory settings risk latency or failure on low-memory phones. This is one informal post, and its setup is password hashing — [DEV](https://dev.to/treszyk/architecture-vs-brute-force-what-i-learned-benchmarking-kdfs-for-my-thesis-18bo).
- ALTCHA has a `retryOnOutOfMemoryError` option for Argon2 and Scrypt, so memory failures are a known practical issue — [README](https://raw.githubusercontent.com/altcha-org/altcha/main/README.md).

**Mobile cost** (Cap's default HashWX difficulty, via BrowserStack; M3 desktop median about 490 ms) — [Cap HashWX docs](https://raw.githubusercontent.com/tiagozip/cap/main/docs/guide/hashwx.md)

| Device | Median | Slowest |
|---|---|---|
| Galaxy S24 | 1.1 s | 1.8 s |
| Pixel 6 | 1.9 s | 2.4 s |
| iPhone 12 | 2.0 s | 3.3 s |
| Redmi Note 11 | 2.4 s | 4.8 s |
| Vivo Y21 | 5.9 s | 11.0 s |

**What PoW vendors themselves concede**
- Cap: PoW alone can be solved by a script without a browser, and neither layer stops a farm of people solving by hand — [how it works](https://raw.githubusercontent.com/tiagozip/cap/main/docs/guide/workings.md).
- FCaptcha: the compute cost does not price an attacker out — [README](https://raw.githubusercontent.com/WebDecoy/FCaptcha/main/README.md).

### Inferences
- Cap's figures imply about 10,000 tokens per hour on one 16-thread CPU at d = 1,000,000 (1M hashes ÷ 2.8 MH/s ≈ 0.36 s). That is my arithmetic on reported rates, and it is a small barrier for scraping but could still matter for form spam if each token is single-use.
- **Token lifetime may matter as much as difficulty.** Anubis's 7-day reusable cookie lets a scraper pay once. Single-use tokens, as in Cap and Turnstile, charge per protected action.
- Memory hardness and HashWX address GPUs and ASICs. A botnet of ordinary devices has no such disadvantage, and it pays nothing for stolen compute, so the Laurie and Clayton botnet objection still stands.
- The ratio between attacker and weakest human is fixed by hardware: raising difficulty hits the Vivo-class phone first. PoW difficulty therefore should stay low by default, rising only with risk signals, as ALTCHA Sentinel's adaptive model does.

### Gaps
- **Requested "Tavian" source not found:** searches and a guessed URL (tavianator.com/2025/anubis_pow.html, 404) produced nothing by Tavian Barnes. The closest match is Tavis Ormandy's post, so the attribution in the brief may be a mix-up.
- No independent, controlled measurement of PoW's effect on real scraper traffic. Duke's figure is operator-reported and has no control group.
- No head-to-head mobile benchmark of Argon2id or scrypt against SHA-256 and HashWX on the same devices.
- HashWX GPU figures have not been independently reproduced, and a purpose-built implementation could change the ratio.
- Algorithm details for Friendly Captcha and Private Captcha were not confirmed.

## (B) What is the exact reCAPTCHA v2 and v3 API?

### Takeaway
A compatibility layer needs one verify endpoint plus a script that exposes `grecaptcha`, fills `g-recaptcha-response`, and handles the overloaded `execute()`. Score semantics (v3: 1.0 means human) and action checking are the main behavioural contract.

### Cited Findings

**Verify** — [docs](https://developers.google.com/recaptcha/docs/verify)
- `POST https://www.google.com/recaptcha/api/siteverify`
- Alternate host: `https://www.recaptcha.net/recaptcha/api/siteverify` — [hCaptcha switch guide](https://docs.hcaptcha.com/switch); [FAQ](https://developers.google.com/recaptcha/docs/faq)
- Params: `secret` (required), `response` (required), `remoteip` (optional)
- Cloudflare says reCAPTCHA also accepts a GET query-parameter style, so accepting GET improves compatibility — [Turnstile migration](https://developers.cloudflare.com/turnstile/migration/recaptcha/)

| Response field | Version | Meaning |
|---|---|---|
| `success` | v2, v3 | Boolean |
| `challenge_ts` | v2, v3 | ISO format `yyyy-MM-dd'T'HH:mm:ssZZ`; time the challenge loaded |
| `hostname` | v2, v3 | Site where it was solved |
| `apk_package_name` | v2 Android | Package name, replaces hostname |
| `error-codes` | v2, v3 | Optional list |
| `score` | v3 | 0.0-1.0 |
| `action` | v3 | Action name; the caller should verify it |

`error-codes` values: `missing-input-secret`, `invalid-input-secret`, `missing-input-response`, `invalid-input-response`, `bad-request`, `timeout-or-duplicate` — [docs](https://developers.google.com/recaptcha/docs/verify).

Sources for response fields: [verify](https://developers.google.com/recaptcha/docs/verify), [v3](https://developers.google.com/recaptcha/docs/v3).

**Script** — [display docs](https://developers.google.com/recaptcha/docs/display); [v3 docs](https://developers.google.com/recaptcha/docs/v3)
- `https://www.google.com/recaptcha/api.js` (also `https://www.recaptcha.net/recaptcha/api.js`)
- `onload=<function>`: called after dependencies load
- `render=explicit|onload` (default `onload`). For v3: `render=<site key>`
- `hl=<language code>`

**DOM** — class `g-recaptcha`; hidden form field `g-recaptcha-response`.

| Attribute | Values | Default | Notes |
|---|---|---|---|
| `data-sitekey` | Site key | Required | |
| `data-theme` | `light`, `dark` | `light` | |
| `data-size` | `normal`, `compact`, `invisible` | `normal` | |
| `data-tabindex` | Integer | `0` | |
| `data-callback` | Function name | | Receives the token |
| `data-expired-callback` | Function name | | |
| `data-error-callback` | Function name | | Usually network errors |
| `data-badge` | `bottomright`, `bottomleft`, `inline` | `bottomright` | Invisible mode |
| `data-action` | Action name | | v3 automatic binding on a button with `data-sitekey` and `data-callback` |
| `isolated` | Boolean | `false` | Render parameter only |

Sources: [display](https://developers.google.com/recaptcha/docs/display), [invisible](https://developers.google.com/recaptcha/docs/invisible), [v3](https://developers.google.com/recaptcha/docs/v3).

**JS API**
- `grecaptcha.render(container, parameters, inherit)` returns a widget ID; `container` is an ID string or DOM element, and `inherit` makes it use existing `data-*` for unset parameters — [invisible](https://developers.google.com/recaptcha/docs/invisible)
- `grecaptcha.reset(opt_widget_id)` and `grecaptcha.getResponse(opt_widget_id)` default to the first widget — [display](https://developers.google.com/recaptcha/docs/display)
- `grecaptcha.execute(opt_widget_id)` for v2 invisible — [invisible](https://developers.google.com/recaptcha/docs/invisible)
- `grecaptcha.execute(siteKey, {action: 'submit'})` for v3, resolving with a token via `.then` — [v3](https://developers.google.com/recaptcha/docs/v3)
- `grecaptcha.ready(fn)` runs `fn` when the library loads — [v3](https://developers.google.com/recaptcha/docs/v3)

**Rules and test keys**
- Actions may contain only alphanumerics, slashes and underscores, and must not be user-specific — [v3](https://developers.google.com/recaptcha/docs/v3).
- Tokens expire after two minutes (stated on the v3 page) — [v3](https://developers.google.com/recaptcha/docs/v3).
- v2 test keys always pass: site `6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI`, secret `6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe` — [FAQ](https://developers.google.com/recaptcha/docs/faq).

### Inferences
- `execute()` must branch on argument type: a string site key means v3, while a widget ID or nothing means v2.
- Treat the `render=<site key>` query value as v3 mode, since `explicit` and `onload` are the only other values.
- Tests against the published v2 test keys are a good conformance check, but they exercise Google's service. A compat server should probably not accept them outside test mode.

### Gaps
- Whether v3 honours `badge` through `grecaptcha.render` with `render=explicit` was not confirmed.
- `grecaptcha.enterprise.*` and the `recaptchaenterprise.googleapis.com` assessment API were not researched. They use a different contract and matter now that keys are moving to Google Cloud.
- The v2 pages read do not separately state token expiry.
- Content types accepted by Google's siteverify beyond the documented POST were not confirmed.

## (B) What is the exact hCaptcha API?

### Takeaway
hCaptcha is close to reCAPTCHA but has one dangerous difference: its score is **inverted** (higher means riskier). It also uses more specific error codes and adds a `sitekey` verify param.

### Cited Findings

**Verify** — [docs](https://docs.hcaptcha.com/)
- `POST https://api.hcaptcha.com/siteverify`, `application/x-www-form-urlencoded` (docs say not JSON, not GET)
- Params: `secret` (required), `response` (required), `remoteip` (recommended), `sitekey` (optional, expected sitekey)
- Response: `success`, `challenge_ts`, `hostname`, `credit` (optional, deprecated), `error-codes` (optional), `score` (Enterprise), `score_reason` (Enterprise)
- Older host seen in integration code: `https://hcaptcha.com/siteverify` — [ruby gem README](https://raw.githubusercontent.com/ambethia/recaptcha/master/README.md)

**Error codes** — [docs](https://docs.hcaptcha.com/)
`missing-input-secret`, `invalid-input-secret`, `missing-input-response`, `invalid-input-response`, `expired-input-response` (120 s default), `already-seen-response`, `bad-request`, `missing-remoteip`, `invalid-remoteip`, `not-using-dummy-passcode`, `sitekey-secret-mismatch`

**Score** — 0.0 means no risk and 1.0 means confirmed threat, the reverse of reCAPTCHA, so callers change `score < threshold` to `score >= threshold` — [switch guide](https://docs.hcaptcha.com/switch).

**Script** — `https://js.hcaptcha.com/1/api.js` — [config docs](https://docs.hcaptcha.com/configuration)

| Query param | Values | Default | Notes |
|---|---|---|---|
| `onload` | Function name | | Must be defined before the API loads |
| `render` | `explicit`, `onload` | `onload` | |
| `hl` | Language code | Auto-detected | Also accepted by `render` |
| `recaptchacompat` | `on`, `off` | `on` | Controls the `window.grecaptcha` hook |

**DOM** — class `h-captcha`; form field `h-captcha-response` — [docs](https://docs.hcaptcha.com/)

| Attribute | Values | Default |
|---|---|---|
| `data-sitekey` | Sitekey | Required |
| `data-theme` | `light`, `dark` | `light` |
| `data-size` | `normal`, `compact` (`invisible` per [invisible docs](https://docs.hcaptcha.com/invisible)) | `normal` |
| `data-tabindex` | Integer | `0` |
| `data-callback` | Function name, receives token | |
| `data-expired-callback` | Function name | |
| `data-chalexpired-callback` | Function name | |
| `data-open-callback` | Function name | |
| `data-close-callback` | Function name | |
| `data-error-callback` | Function name, receives error code string | |
| `data-orientation` | `portrait`, `landscape` | Enterprise only officially |

The same keys pass to `hcaptcha.render()` without the `data-` prefix — [config docs](https://docs.hcaptcha.com/configuration).

**JS API** — [config docs](https://docs.hcaptcha.com/configuration)
- `hcaptcha.render(container, params)` returns a widget ID
- `hcaptcha.reset(widgetID)` and `hcaptcha.getResponse(widgetID)` default to the first widget
- `hcaptcha.getRespKey(widgetID)`
- `hcaptcha.execute(widgetID)`; `{ async: true }` returns a Promise resolving to `{ response, key }`
- Success callback receives `(token, key)` in the docs' example — [docs](https://docs.hcaptcha.com/)

**Invisible** — either a `<button class="h-captcha">` with `data-callback`, or a `div` with `data-size="invisible"` plus `hcaptcha.execute()` — [invisible docs](https://docs.hcaptcha.com/invisible).

**Test keys** — secret `0x0000000000000000000000000000000000000000` with sitekey `10000000-ffff-ffff-ffff-000000000001` and token `10000000-aaaa-bbbb-cccc-000000000001`. Enterprise sets are `20000000-...-000000000002` (safe) and `30000000-...-000000000003` (bot) — [docs](https://docs.hcaptcha.com/#integration-testing-test-keys).

### Inferences
- A shared backend should keep one internal risk value and convert it per endpoint. FCaptcha does this, using lower-is-human on its own and hCaptcha paths and reCAPTCHA v3 semantics on `/recaptcha/api/siteverify` — [README](https://raw.githubusercontent.com/WebDecoy/FCaptcha/main/README.md).
- Fill both `h-captcha-response` and `g-recaptcha-response` on the hCaptcha path. FCaptcha does, and it costs little even though the official behaviour is unconfirmed.

### Gaps
- **Whether hCaptcha officially posts `g-recaptcha-response` as well is unconfirmed.** Official pages read do not say; [FCaptcha](https://raw.githubusercontent.com/WebDecoy/FCaptcha/main/README.md) fills both. Test with a real widget.
- `hcaptcha.setData` and `hcaptcha.close` are not on the config page. `setData` appears only in a [third-party wrapper's README](https://www.npmjs.com/package/starboy-hcaptcha) as Enterprise; `close` was not found.
- The exact shape of `score_reason` (a list of strings or otherwise) was not confirmed.

## (B) What is the exact Cloudflare Turnstile API?

### Takeaway
Turnstile has the most explicit contract and the easiest verify semantics to copy. It accepts JSON and form bodies, supports idempotent retries, and has a documented reCAPTCHA compatibility mode that is a useful design template.

### Cited Findings

**Verify** — [docs](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/)
- `POST https://challenges.cloudflare.com/turnstile/v0/siteverify`, `application/x-www-form-urlencoded` or `application/json`; responses are always JSON
- Params: `secret` (required), `response` (required), `remoteip` (optional), `idempotency_key` (optional UUID for safe retries)
- Tokens: maximum 2048 characters, valid 300 s, single use

| Response field | Meaning |
|---|---|
| `success` | Boolean |
| `challenge_ts` | ISO 8601 solve time |
| `hostname` | Where the challenge was served |
| `error-codes` | Array |
| `action` | Client-set identifier |
| `cdata` | Client-set custom data |
| `metadata.ephemeral_id` | Device fingerprint ID, Enterprise only |

**Error codes** — `missing-input-secret`, `invalid-input-secret`, `missing-input-response`, `invalid-input-response`, `bad-request`, `timeout-or-duplicate`, `internal-error` — [docs](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/).

**Script** — `https://challenges.cloudflare.com/turnstile/v0/api.js` with `render=explicit`, `onload=<function>` — [client docs](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/); and `compat=recaptcha` — [migration](https://developers.cloudflare.com/turnstile/migration/recaptcha/).

**DOM** — class `cf-turnstile`; hidden input `cf-turnstile-response`, renameable with `response-field-name` — [config](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/widget-configurations/).

**Configuration** — [widget configurations](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/widget-configurations/)

| JS param | Attribute | Values | Default |
|---|---|---|---|
| `sitekey` | `data-sitekey` | Sitekey | Required |
| `action` | `data-action` | ≤32 chars: alphanumeric, `_`, `-` | |
| `cData` | `data-cdata` | ≤255 chars: alphanumeric, `_`, `-` | |
| `callback` | `data-callback` | Function, receives token | |
| `error-callback` | `data-error-callback` | Function, receives error code | |
| `execution` | `data-execution` | `render`, `execute` | `render` |
| `expired-callback` | `data-expired-callback` | Function | |
| `before-interactive-callback` | `data-before-interactive-callback` | Function | |
| `after-interactive-callback` | `data-after-interactive-callback` | Function | |
| `unsupported-callback` | `data-unsupported-callback` | Function | |
| `timeout-callback` | `data-timeout-callback` | Function | |
| `theme` | `data-theme` | `light`, `dark`, `auto` | `auto` |
| `language` | `data-language` | `auto`, ISO 639-1, language-country | `auto` |
| `tabindex` | `data-tabindex` | Integer | `0` |
| `response-field` | `data-response-field` | `true`, `false` | `true` |
| `response-field-name` | `data-response-field-name` | Name | `cf-turnstile-response` |
| `size` | `data-size` | `normal`, `flexible`, `compact` | `normal` |
| `retry` | `data-retry` | `auto`, `never` | `auto` |
| `retry-interval` | `data-retry-interval` | ms, < 900000 | `8000` |
| `refresh-expired` | `data-refresh-expired` | `auto`, `manual`, `never` | `auto` |
| `refresh-timeout` | `data-refresh-timeout` | `auto`, `manual`, `never` | `auto` |
| `appearance` | `data-appearance` | `always`, `execute`, `interaction-only` | `always` |
| `feedback-enabled` | `data-feedback-enabled` | `true`, `false` | `true` |

Note the case differences: `cData` in JS, `data-cdata` in HTML, `cdata` in the response.

**JS API** — [client docs](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/). The page shows usage rather than formal signatures.
- `turnstile.render(container, options)` returns a widget ID
- `turnstile.execute(container)`
- `turnstile.reset(widgetId)`
- `turnstile.remove(widgetId)`
- `turnstile.getResponse(widgetId)`
- `turnstile.isExpired(widgetId)`
- `turnstile.ready(callback)`

**Client error families** (passed to `error-callback`) — [docs](https://developers.cloudflare.com/turnstile/troubleshooting/client-side-errors/error-codes/)

| Codes | Meaning | Retry |
|---|---|---|
| 110100, 110110, 110200 | Sitekey or domain configuration | No |
| 110600, 110620 | Timeouts | Yes |
| 200100 | Clock wrong or challenge cached | No |
| 200500 | Iframe failed to load | Yes |
| 300*, 600* | Generic failure, bot behaviour | Yes |
| 400020, 400021, 400070 | Sitekey problems | No |

**Test keys** — [docs](https://developers.cloudflare.com/turnstile/troubleshooting/testing/)
- Sitekeys: `1x00000000000000000000AA` (pass), `2x00000000000000000000AB` (fail), `1x00000000000000000000BB` (invisible pass), `2x00000000000000000000BB` (invisible fail), `3x00000000000000000000FF` (forces interaction)
- Secrets: `1x0000000000000000000000000000000AA` (pass), `2x0000000000000000000000000000000AA` (fail), `3x0000000000000000000000000000000AA` (`timeout-or-duplicate`)
- Dummy token: `XXXX.DUMMY.TOKEN.XXXX`

**reCAPTCHA compat mode** — [migration](https://developers.cloudflare.com/turnstile/migration/recaptcha/)
- `?compat=recaptcha` gives implicit rendering of reCAPTCHA-style widgets, the `g-recaptcha-response` input, and a `grecaptcha` alias.
- It supports only up to v2: `render()` and v2 invisible via `execute()`. Siteverify rejects GET.

### Inferences
- Exposing Turnstile's verify contract is likely the cheapest first target: it has one clear host path and a defined replay and retry model.
- For `idempotency_key`, a retry with the same key should return the first result rather than `timeout-or-duplicate`. That reading fits the stated purpose but was not checked against a detailed spec.

### Gaps
- Exact idempotency semantics (retention window, conflicting key reuse) were not read.
- A formal `turnstile.execute` second argument and exact `isExpired` return type are not on the page read; the return type is presumably boolean.
- HTTP status codes for failed verifications were not recorded.

## (B) What is the Friendly Captcha siteverify API?

### Takeaway
Both versions are simple, but neither matches the reCAPTCHA family. They differ in field names, auth and error shape, so they need their own adapter.

### Cited Findings

| | v1 | v2 |
|---|---|---|
| Endpoint | `POST https://api.friendlycaptcha.com/api/v1/siteverify` | `POST https://global.frcapi.com/api/v2/captcha/siteverify` |
| Auth | `secret` param | `X-API-Key` header |
| Token param | `solution` | `response` (16 KB max) |
| Other param | `sitekey` (optional) | `sitekey` (optional) |
| Form field | `frc-captcha-solution` | `frc-captcha-response` |
| Body | JSON or form | JSON or form |
| Success | `{success, errors?}` | `{success, data: {event_id, challenge: {timestamp, origin}, risk_intelligence}}` |
| Failure | `errors` array | `{success: false, error: {error_code, detail}}` |

Sources: [v1](https://developer.friendlycaptcha.com/docs/v1/api/), [v2](https://developer.friendlycaptcha.com/docs/v2/api/siteverify).

- v1 errors: `secret_missing` (400), `secret_invalid` (401), `solution_missing` (400), `bad_request` (400), `solution_invalid` (200), `solution_timeout_or_duplicate` (200) — [v1](https://developer.friendlycaptcha.com/docs/v1/api/)
- v2 errors: `auth_required` (401), `auth_invalid` (401), `sitekey_invalid` (400), `response_missing` (400), `response_invalid` (200), `response_timeout` (200), `response_duplicate` (200), `bad_request` (400) — [v2](https://developer.friendlycaptcha.com/docs/v2/api/siteverify)
- A 200 status does not mean the solution was valid; callers must read `success` — [v2](https://developer.friendlycaptcha.com/docs/v2/api/siteverify)
- v1 docs advise accepting the form and alerting if verify returns non-200 in production — [v1](https://developer.friendlycaptcha.com/docs/v1/api/). A compat layer's outages therefore may **fail open** in clients that follow this advice.

### Inferences
- Friendly Captcha is lower priority for a first compat release, given the separate shape and smaller installed base implied by fewer integrations seen here. That is a judgment, not a measured market share.

### Gaps
- Friendly Captcha widget DOM and JS API were not researched.
- The EU endpoint URL was not retrieved.

## (B) Which libraries and frameworks allow a configurable endpoint?

### Takeaway
Support varies widely. A few expose full URLs, some allow only a domain, and popular ones may offer only a `google.com`/`recaptcha.net` switch or nothing. Compat servers should therefore serve **the original provider paths**, so that base-URL-only settings work.

### Cited Findings

| Software | Setting | Scope | Source |
|---|---|---|---|
| Gitea | `RECAPTCHA_URL`; code appends `/api/siteverify`. Also native `MCAPTCHA_URL` | Full base URL | [config](https://raw.githubusercontent.com/go-gitea/gitea/main/custom/conf/app.example.ini), [code](https://raw.githubusercontent.com/go-gitea/gitea/main/modules/recaptcha/recaptcha.go) |
| Ruby `recaptcha` gem | `verify_url`, `api_server_url` | Full URLs | [README](https://raw.githubusercontent.com/ambethia/recaptcha/master/README.md) |
| `google/recaptcha` (PHP) | `CurlPost(?string $siteVerifyUrl)` | Full URL, in code | [source](https://raw.githubusercontent.com/google/recaptcha/master/src/ReCaptcha/RequestMethod/CurlPost.php) |
| `mkopylec/recaptcha-spring-boot-starter` | `verification-url` | Full URL (repo last pushed 2019) | [README](https://raw.githubusercontent.com/mkopylec/recaptcha-spring-boot-starter/master/README.md) |
| Statamic Captcha addon | `CAPTCHA_SERVER_URL` for FCaptcha | Full URL | [FCaptcha README](https://raw.githubusercontent.com/WebDecoy/FCaptcha/main/README.md) |
| `django-recaptcha` | `RECAPTCHA_DOMAIN`, `RECAPTCHA_PROXY`; verify URL is `https://%s/recaptcha/api/siteverify` | Domain only, HTTPS and path fixed | [README](https://raw.githubusercontent.com/django-recaptcha/django-recaptcha/main/README.md), [client](https://raw.githubusercontent.com/django-recaptcha/django-recaptcha/main/django_recaptcha/client.py) |
| Keycloak | "Use recaptcha.net" toggle | `google.com` or `recaptcha.net` only | [code](https://raw.githubusercontent.com/keycloak/keycloak/main/services/src/main/java/org/keycloak/authentication/forms/AbstractRegistrationRecaptcha.java) |
| `react-google-recaptcha` | `window.recaptchaOptions.useRecaptchaNet` | `recaptcha.net` only | [README](https://raw.githubusercontent.com/dozoisch/react-google-recaptcha/master/README.md) |
| Contact Form 7 (WordPress) | `wpcf7_use_recaptcha_net` filter; endpoint is otherwise hardcoded | `recaptcha.net` only, for both script and verify | [service](https://plugins.svn.wordpress.org/contact-form-7/trunk/modules/recaptcha/service.php), [script](https://plugins.svn.wordpress.org/contact-form-7/trunk/modules/recaptcha/recaptcha.php) |

Contact Form 7 also has filters for its sitekey, secret, verify result and score threshold (`wpcf7_recaptcha_threshold` defaults to 0.50), so reCAPTCHA v3 score semantics matter there — [service](https://plugins.svn.wordpress.org/contact-form-7/trunk/modules/recaptcha/service.php).

Gitea's native `MCAPTCHA_URL` shows a further path: being accepted as a named first-class provider — [config](https://raw.githubusercontent.com/go-gitea/gitea/main/custom/conf/app.example.ini).

### Inferences
- Serving `/recaptcha/api/siteverify` and `/recaptcha/api.js` covers `django-recaptcha` given a domain that holds a valid certificate.
- For Gitea, set `RECAPTCHA_URL` to `https://host/recaptcha/` so the appended path resolves to the same route, as [FCaptcha's example](https://raw.githubusercontent.com/WebDecoy/FCaptcha/main/README.md) does.
- Toggle-only integrations (Keycloak, CF7, `react-google-recaptcha`) cannot be repointed through settings. They need code changes, custom plugins, or network-level interception.

### Gaps
- **Nextcloud:** no native configurable-endpoint support was confirmed. The Nextcloud registration README has no captcha mention in the check run, and the app-store query failed to parse.
- **Mastodon:** path checks returned 404, so configuration was not confirmed.
- `marsidev/react-turnstile` README showed no `scriptOptions` match, possibly because docs moved; not confirmed.
- WordPress core HTTP filters (for example, intercepting outbound requests) might repoint CF7 verification, but I did not verify this.
- Discourse, Laravel and other common integrations were not checked.

## (B) How do drop-in replacements typically work?

### Takeaway
The working pattern in the products reviewed is **base-URL substitution with mirrored paths and globals**, not DNS interception. No documented production example of DNS-based replacement was found. FCaptcha is the clearest and most complete precedent; Cap copies only the verify request shape.

### Cited Findings

**Levels of compatibility seen**

| Level | Example | What changes for the integrator |
|---|---|---|
| Client and server mirrored per provider | [FCaptcha](https://raw.githubusercontent.com/WebDecoy/FCaptcha/main/README.md) | Script URL and verify URL only |
| Same vendor shim for a competitor | [Turnstile `compat=recaptcha`](https://developers.cloudflare.com/turnstile/migration/recaptcha/), [hCaptcha `recaptchacompat`](https://docs.hcaptcha.com/configuration) | Script URL, verify URL, secret, sitekey |
| Server shape only | [Cap](https://raw.githubusercontent.com/tiagozip/cap/main/docs/guide/alternatives/migrate-from-recaptcha.md) | New widget tag and field `cap-token`; verify hostname |
| Forwarding proxy | [Friendly Captcha Self-Hosted Endpoint](https://developer.friendlycaptcha.com/docs/v2/guides/self-hosted-endpoint) | Not a replacement: still calls their API |

**FCaptcha's path map** — [README](https://raw.githubusercontent.com/WebDecoy/FCaptcha/main/README.md)

| Provider | Script | Siteverify | Form field |
|---|---|---|---|
| Turnstile | `/turnstile/v0/api.js` | `/turnstile/v0/siteverify` | `cf-turnstile-response` |
| hCaptcha | `/1/api.js` | `/siteverify` | `h-captcha-response` and `g-recaptcha-response` |
| reCAPTCHA | `/recaptcha/api.js` | `/recaptcha/api/siteverify` | `g-recaptcha-response` |

The script on each path answers to that provider's JS API, such as `turnstile.render`, `hcaptcha.getResponse` and `grecaptcha.reset`.

**Cap** — `POST https://<host>/<site-key>/siteverify` with JSON `secret` and `response`, returning `{ "success": true }`, single use. This takes the same parameters as reCAPTCHA but uses a site-key-prefixed path — [guide](https://capjs.js.org/guide/), [migration](https://raw.githubusercontent.com/tiagozip/cap/main/docs/guide/alternatives/migrate-from-recaptcha.md).

**Cross-provider verify matrix** (from the sections above)

| | reCAPTCHA | hCaptcha | Turnstile |
|---|---|---|---|
| Token lifetime | 2 min | 120 s default | 300 s |
| Replay error | `timeout-or-duplicate` | `already-seen-response` | `timeout-or-duplicate` |
| Expiry error | `timeout-or-duplicate` | `expired-input-response` | `invalid-input-response` (per the error table; Cloudflare describes `timeout-or-duplicate` as already validated) |
| JSON body | Not confirmed | Docs say no | Yes |
| Score direction | 1.0 = human | 1.0 = threat | No score (free fields) |
| `action` in response | Yes (v3) | No | Yes |

### Inferences
- **Recommended design:**
  1. Mirror provider paths on one host, and serve per-provider scripts with the matching global, class and field.
  2. Accept the broadest input on all verify routes: POST form and JSON, and GET on the reCAPTCHA route.
  3. Translate errors and score at each route's edge from one internal result.
- **DNS or hosts override is limited.** Browsers would need `www.google.com`, `js.hcaptcha.com` or `challenges.cloudflare.com` to resolve to your server with a certificate they trust, which a public CA will not issue to you. It could only work where you control the trust store, such as managed devices or server-side verify calls using a private CA. Overriding `www.google.com` also affects everything else on that host, so `www.recaptcha.net` is a much safer target where a toggle exists. This is my reasoning, not a sourced practice.
- **Sitekey and secret format checks** in third-party code could reject non-matching keys. Replacing credentials works only if the formats are tolerated, so test it. Consider issuing keys in provider-like formats.
- **Do not use provider names or branding in the widget UI**, even when paths mirror them, to avoid confusion about who is verifying. Whether API-path mirroring carries any legal risk was not researched; Cloudflare, hCaptcha and FCaptcha precedents show technical practice only.

### Gaps
- **No source documented DNS-based CAPTCHA replacement in production.** Searches instead surfaced [recaptcha-domain-replicator](https://pypi.org/project/recaptcha-domain-replicator/), a token-harvesting and testing tool that is not a suitable model.
- FCaptcha's compat claims come from its README. I did not run it or test conformance, so how complete its JS API shims are is unknown.
- Legal and terms-of-service issues for API-compatible replacements were not researched.
