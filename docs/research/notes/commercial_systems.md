# How commercial bot-defence and CAPTCHA systems work internally (state at 2026-11-07)

Evidence tags used throughout:
- **[VENDOR]**: the vendor's own docs or blog.
- **[ACADEMIC]**: a peer-reviewed paper or preprint.
- **[RE]**: an independent reverse-engineering writeup, unverified by the vendor, often version-specific.
- **[BYPASS-SEO]**: a scraping or solver vendor's blog. These have a commercial interest and are the weakest class. Treat as leads only.
- **(snippet)**: seen only in a search-result summary. The full page was not read, or the direct fetch failed.

Dates are given where known. No vendor publishes its full signal list or decision logic, so every signal-level claim below is either high-level vendor language or RE.

## What does each system collect and evaluate?

### Takeaway
All of these systems share one shape: passive request and client telemetry, an obfuscated and rotating collector, a risk score from a model, then a graduated response of silent pass, cheap browser challenge, or visual challenge. Vendors confirm that shape but almost never the details. Most specifics (VM design, cookie semantics, signal lists) come from RE or bypass-vendor sources.

### Cited Findings

**reCAPTCHA v2, v3 and Enterprise (Google)**
- [VENDOR] v3 returns a 0.0-1.0 score with a suggested starting threshold of 0.5. Named actions make risk analysis adaptive to context. "reCAPTCHA learns by seeing real traffic on your site", so staging scores may differ from production. The docs do not list signals — [reCAPTCHA v3 docs](https://developers.google.com/recaptcha/docs/v3)
- [VENDOR] Enterprise has 11 score levels (only 0.1, 0.3, 0.7 and 0.9 without a billing account). Reason codes include AUTOMATION, UNEXPECTED_ENVIRONMENT, TOO_MUCH_TRAFFIC, UNEXPECTED_USAGE_PATTERNS and LOW_CONFIDENCE_SCORE. It also has `extendedVerdictReasons`, a challenge outcome of PASSED, FAILED or NOCAPTCHA, and an SMS-fraud score — [Interpret assessment](https://docs.cloud.google.com/recaptcha/docs/interpret-assessment-website)
- [RE, January 2026, script version 41] The BotGuard script is reported as a bytecode VM with 512 registers and state-machine control flow. Reported signals are mouse, keyboard, scroll, touch, focus and visibility events; navigator, screen, performance and timer-jitter data; WebDriver checks; and statistical summaries (Welford variance, reservoir sampling). The token pipeline is serialise, compress, ARX cipher, then base64url with a `!` prefix. The page's own code listings do not agree with each other and its register counts are inconsistent, so treat the details as approximate — [RESONEO BotGuard analysis](https://think.resoneo.com/botguard-google/)
- [RE, old, date not established] `/recaptcha/api2/anchor` returns an init call carrying base64 parameters. The interpreter has two entry points, one at load and one on checkbox click. Bytecode is XTEA-encrypted with a position-based keystream, and the key is derived by hashing the interpreter's own source through `Function.toString()`, which is a self-integrity binding — [InsideReCaptcha](https://github.com/toogle/InsideReCaptcha)
- [RE] `bgdata` is reported to hold a script, VM bytecode and VM config, with dead code inflating the file past 60,000 lines. The same repo claims BotGuard was removed on 04/01/2026; I could not verify this and the RESONEO analysis describes it as active in 2026 — [elyelysiox/recaptcha](https://github.com/elyelysiox/recaptcha) (snippet)
- [ACADEMIC, 2024] Browser history and cookies from a real user cut mean challenges from 8.38 to 2.71 (median 5 to 2, p reported as 0.00). Mouse trajectory shape did not matter between straight lines and Bézier curves (p = 0.57), though no movement at all was worse (median 13 vs 7 vs 5) — [Breaking reCAPTCHAv2](https://arxiv.org/html/2409.08831v1)

**Cloudflare Turnstile and Managed Challenge**
- [VENDOR, 2022] Turnstile reviews "headers, user agent, and browser characteristics" and uses ML models that detect common features of visitors who previously passed a challenge — [Cloudflare blog](https://blog.cloudflare.com/turnstile-private-captcha-alternative/)
- [VENDOR, current] Ephemeral IDs are short-lived identifiers built from aggregated client-side signals. They link interactions to a device without cookies, are deliberately not fully unique, and are exposed in siteverify only to Enterprise customers — [Ephemeral IDs blog](https://blog.cloudflare.com/turnstile-ephemeral-ids-for-fraud-detection/)
- [VENDOR, current] Separate passive layers exist. JavaScript Detections reports a pass/fail field (`cf.bot_management.js_detection.passed`) usable in WAF rules, and Precursor provides session-level detection that can influence challenge issuance in Armed mode — [How challenges work](https://developers.cloudflare.com/cloudflare-challenges/concepts/how-challenges-work/)

**hCaptcha and hCaptcha Enterprise**
- [VENDOR] Enterprise adds `score`, `score_reason`, passive and nearly passive "No-CAPTCHA" modes, and IP or user-agent "Challenge" rules. Passing `remoteip` improves accuracy and enables risk scores for Enterprise. The docs do not explain how scores are computed — [hCaptcha docs](https://docs.hcaptcha.com/)
- [RE, version-specific, date not established] `hsw` is Rust compiled to WASM with obfuscation added from about version 1.40.16. Community repos list separate components for N-data encryption, request payload encryption, fingerprint blob encryption and an AES key fetcher. Execution is claimed to take usually under 10 ms — [Implex hcaptcha-reverse](https://www.github.com/Implex-ltd/hcaptcha-reverse) (snippet). A separate attempt to make the WASM readable was abandoned as too hard — [shiftmeplease/hcaptcha](https://github.com/shiftmeplease/hcaptcha) (snippet)

**DataDome**
- [VENDOR, date unknown] Picasso is an invisible canvas render whose hash is used for device-class fingerprinting, run during its CAPTCHA and Device Check. The technique was originally conceived by Google. DataDome pairs it with browser fingerprinting, behavioural patterns, IP and session reputation, and residential proxy detection — [DataDome threat research](https://datadome.co/threat-research/the-art-of-bot-detection-picasso-for-device-class-fingerprinting/) (snippet; direct fetch returned 403)
- [BYPASS-SEO, 2026] Claims of per-request scoring in about 2 ms, around 85,000 per-site models, and a score recomputed on each request so the cookie does not whitelist a session. These are unconfirmed by primary sources I could read — [Scrappey](https://scrappey.com/qa/web-automation/how-datadome-detects-bots), [ScrapeBadger](https://scrapebadger.com/blog/how-to-bypass-datadome-anti-bot-protection-a-complete-2026-guide) (snippets)
- [ACADEMIC, data from September to November 2023] OpenWPM was used to infer which fingerprint APIs DataDome and BotD accessed, and `hardwareConcurrency` under 8 was strongly associated with DataDome evasion — [FP-Inconsistent](https://arxiv.org/html/2406.07647v3)

**Arkose Labs**
- [VENDOR] Two 0-100 scores: Global (telltales common across customers) and Custom (customer-specific telltales). The band is taken from the higher score: High 81-100, Medium 41-80, Low 0-40. Category precedence is ALLOWLIST/DENYLIST, then FRD-FRM (fraud farms and captcha solvers), BOT-ADV, BOT-STD, CUSTOM, NO-THREAT. An explicit farm category is notable — [Arkose risk score docs](https://developer.arkoselabs.com/docs/risk-score)
- [VENDOR] Sessions that do not qualify for transparent mode get an interactive challenge, and the Verify API's `session_details` reports whether it was solved — [Verify API v4](https://developer.arkoselabs.com/docs/verify-api-v4-response-fields-and-examples-copy) (snippet)

**Kasada**
- [BYPASS-SEO/RE, unverified, no primary docs found] Reported as two headers: `x-kpsdk-ct` (expensive to produce, about 30 minutes, reusable) and `x-kpsdk-cd` (per-request proof-of-work, single-use, tracked server-side), bound by an HMAC check. The client is an obfuscated VM over encrypted bytecode whose output acts as evidence the VM truly ran. Environment and timing are collected, and solutions that finish too quickly are said to be flagged — [LAVX News](https://news.lavx.hu/article/the-arms-race-of-web-automation-deconstructing-kasada-s-vm-based-anti-bot-system), [Evomi](https://evomi.com/blog/kasada-shape-and-the-next-generation-of-anti-bot-what-scrapers-need-to-know) (snippets)

**Akamai Bot Manager**
- [BYPASS-SEO] Edge scoring on IP reputation, the `_abck` cookie and sensor data, TLS handshake characteristics and behavioural telemetry, with a collector said to gather 100+ signals — [Scrapfly](https://scrapfly.io/blog/posts/akamai-bot-manager-understanding-abck-cookies-and-sensor-data) (snippet). Conversely, one source notes that public Akamai material gives no definitive deployment-independent specification for `_abck` or `sensor_data` — [UMA Technology](https://umatechnology.org/akamai-bot-manager-what-the-_abck-cookie-and-sensor-data-actually-mean/) (snippet). Cookie-segment semantics and the required number of submissions are unconfirmed.

**PerimeterX / HUMAN**
- [VENDOR] Human Challenge is a "press and hold" button. Behind the scenes the browser is issued a proof-of-work challenge the device must solve before proceeding — [HUMAN FAQ](https://humansecurity.com/learn/resources/human-challenge-faq) (snippet; direct fetch returned 403)
- [BYPASS-SEO] Reported measurement of hold duration, pressure, finger movement and timing, plus fingerprint and IP reputation. Sources disagree on `_px3` lifetime — [Scrappey](https://scrappey.com/qa/web-automation/how-perimeterx-detects-bots) (snippet)

### Inferences
- The Function.toString-derived key (reCAPTCHA) and the "VM output proves execution" claim (Kasada) suggest a common pattern: the VM's main job is to make collected signals expensive to forge and costly to re-derive per version, rather than to hide a secret permanently. RE evidence is thin, so this is my reading, not a stated design.
- hsw's reported sub-10 ms run time suggests it serves integrity and telemetry rather than meaningful compute cost.
- The ETH cookie result and Cloudflare's "features of those who previously passed" point to the same thing: prior-good-history is a large part of the silent-pass decision.

### Gaps
- No vendor documents its signal weights, models or thresholds. Nothing in my sources allows a per-signal value estimate for any vendor.
- Kasada, Akamai and HUMAN internals rest almost entirely on commercial bypass sources. The direct DataDome and HUMAN pages returned 403 to my fetcher.
- I did not obtain reliable information on `hsl`, or a technical account of Arkose's client fingerprint. One search tool declined the Arkose reverse-engineering portion of the query, so this area is under-researched, not shown to be undocumented.

## How does Turnstile's challenge pipeline work, how are scripts rotated, and what RE writeups exist?

### Takeaway
Cloudflare confirms the pipeline categories (proof-of-work, proof-of-space, web API probing, browser-quirk and behaviour checks, Private Access Tokens) and the principle of a rotating challenge suite, but publishes no parameters. I found no credible public writeup of the Turnstile VM. The best public VM accounts concern reCAPTCHA's BotGuard and are partial.

### Cited Findings
- [VENDOR] Pipeline step one is "a series of small non-interactive JavaScript challenges" whose results tune difficulty to the specific request. Types named are proof-of-work, proof-of-space, probing for web APIs, and other challenges for detecting browser quirks and human behaviour — [Turnstile docs](https://developers.cloudflare.com/turnstile/index.md) (snippet), [Cloudflare blog, 2022-09-28](https://blog.cloudflare.com/turnstile-private-captcha-alternative/)
- [VENDOR, 2022] It "automatically chooses from a rotating suite of non-intrusive browser challenges", with a platform to "rotate new challenges in and out" as effectiveness changes. Computational hardness "may vary by visitor, but is targeted to run fast" — [Cloudflare blog](https://blog.cloudflare.com/turnstile-private-captcha-alternative/)
- [VENDOR] Modes: Managed (checkbox only when risk warrants), Non-interactive, Invisible — [Turnstile docs](https://developers.cloudflare.com/turnstile/index.md) (snippet)
- [VENDOR] "Challenge Pages and Turnstile rely on the same underlying mechanism." Under Attack Mode issues Managed Challenges. Sources of challenges include WAF rules, Bot Fight Mode and DDoS protection — [How challenges work](https://developers.cloudflare.com/cloudflare-challenges/concepts/how-challenges-work/)
- [VENDOR] Managed Challenge selects a challenge type dynamically from browser signals and request characteristics. Most humans pass automatically, interaction appears only if non-human attributes are detected, and failure of a non-interactive challenge leads to another interstitial — [Challenge pages](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/)
- [VENDOR] Extensions altering the User-Agent or Web APIs such as Canvas and WebGL are unsupported, which implies these surfaces are checked for consistency. A Managed Challenge solved from a different IP than issued is invalid and can loop. A domain cannot serve a challenge requested for another domain — [How challenges work](https://developers.cloudflare.com/cloudflare-challenges/concepts/how-challenges-work/)
- [VENDOR, 2022] Private Access Tokens involve Origin, Client, Attester (Apple, which checks device components) and Issuer (Cloudflare). The origin learns URL and IP, the attester does not learn the site or IP, and the issuer learns the site but not device data. PATs validate an authentic device and signed application, not a person's behaviour. Support at announcement was iOS 16 and macOS 13, and customers must use Managed Challenge rather than Legacy CAPTCHA — [Cloudflare PAT blog](https://blog.cloudflare.com/eliminating-captchas-on-iphones-and-macs-using-new-standard/)
- [VENDOR, 2022 figures] Cloudflare's own CAPTCHA use fell 91% with Managed Challenge, and average challenge time fell from 32 seconds to about 1 second — [Intelligent CIO, reporting Cloudflare](https://www.intelligentcio.com/me/2022/10/07/cloudflare-launches-a-user-friendly-privacy-preserving-alternative-to-captchas/) (snippet)
- [VENDOR, 2022] "Turnstile never looks for cookies" — [Cloudflare blog](https://blog.cloudflare.com/turnstile-private-captcha-alternative/). Pre-clearance is a separate case: the widget can issue a persistent `cf_clearance` cookie for WAF-protected API endpoints — [Challenge pages](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/). The "never" statement is from 2022 and should not be assumed to describe all current behaviour.
- [RE] The reCAPTCHA analysis observed a cipher constant change between two captures about 20 minutes apart (1426, then 3328) and a hashed script URL that changes over time. Two observations do not establish a rotation schedule — [RESONEO](https://think.resoneo.com/botguard-google/)

### Inferences
- A self-hosted design can copy the structure: a small rotating pool of probes, a per-request plan chosen server-side, and a verdict computed server-side from probe results. The per-version rebuild is what gives rotation its value.
- PATs prove device authenticity, not intent. A genuine Apple device running automation could still hold one, so PAT should lower friction rather than grant trust outright. The source does not discuss this case directly.

### Gaps
- I found no credible public Turnstile VM writeup. My one targeted search returned only unrelated crackmes and a work-in-progress executor for a ChatGPT turnstile variant (a different product). A better search might find more, but I should not imply one exists.
- Cloudflare publishes no proof-of-work or proof-of-space parameters, quirk lists, or rotation cadence.
- Current PAT coverage, and whether a self-hosted operator can act as an issuer accepted by Apple's attester, were not established. The 2022 post is the only source I read. The IETF Privacy Pass specifications should be checked directly.

## What token formats, TTL, single-use semantics and binding do they use?

### Takeaway
The public CAPTCHA products converge on an opaque token, a 2-5 minute TTL, single-use server-side redemption and hostname and action fields that the site must check itself. Edge bot managers instead use longer-lived cookies, reportedly rechecked by telemetry.

### Cited Findings

| System | TTL | Single use | Binding fields returned | Source and class |
|---|---|---|---|---|
| Turnstile | 300 s; max length 2048 chars | Yes (`timeout-or-duplicate`) | `hostname`, `action`, `cdata`, `challenge_ts`; Enterprise `metadata.ephemeral_id` | [VENDOR](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/) |
| reCAPTCHA v2 siteverify | 2 min | Yes | `hostname` or `apk_package_name`, `challenge_ts` | [VENDOR](https://developers.google.com/recaptcha/docs/verify) |
| reCAPTCHA v3 | 2 min | Yes (same verify endpoint) | adds score and action | [VENDOR](https://developers.google.com/recaptcha/docs/v3) |
| reCAPTCHA Enterprise | Not stated on the page read | Not stated on the page read | `valid`, `invalidReason`, `hostname`, `action`, `createTime`; compare to `expectedAction` | [VENDOR](https://docs.cloud.google.com/recaptcha/docs/interpret-assessment-website) |
| hCaptcha | 120 s default | Yes (`already-seen-response`) | `hostname`, `challenge_ts`; Enterprise `score`, `score_reason` | [VENDOR](https://docs.hcaptcha.com/) |
| Arkose | Not found | `previously_verified` flags reuse rather than simply rejecting | `session_details`, risk band and category | [GitLab integration docs](https://docs.gitlab.com/ee/integration/arkose.html) (snippet), [Arkose](https://developer.arkoselabs.com/docs/risk-score) |
| Kasada | CT about 30 min reusable; CD per request | CD single-use | HMAC between CT and CD | [BYPASS-SEO, unverified](https://evomi.com/blog/kasada-shape-and-the-next-generation-of-anti-bot-what-scrapers-need-to-know) |
| DataDome, Akamai, HUMAN | Not documented publicly in what I read | Cookie-based | Sources conflict | [BYPASS-SEO](https://scrappey.com/qa/anti-bot/what-is-perimeterx) |

- [VENDOR] hCaptcha warns that `hostname` comes from the user's browser and "should not be used for authentication", and may return `not-provided` under unusually high challenge traffic. Passing `sitekey` to siteverify stops tokens issued on one sitekey being redeemed on another, which matters most when the redeeming sitekey has a harder difficulty — [hCaptcha docs](https://docs.hcaptcha.com/)
- [VENDOR] Google says to verify the action name and treats a mismatch as a possible falsified action. Action names must not be user-specific — [v3 docs](https://developers.google.com/recaptcha/docs/v3), [Interpret assessment](https://docs.cloud.google.com/recaptcha/docs/interpret-assessment-website)
- [VENDOR] Managed Challenge effectively binds to the issuing IP, since solving from a different IP is invalid — [How challenges work](https://developers.cloudflare.com/cloudflare-challenges/concepts/how-challenges-work/)
- [RE] The reCAPTCHA token is reported as `!`-prefixed and encrypted — [RESONEO](https://think.resoneo.com/botguard-google/)

### Inferences
- Binding checks in these products are mostly opt-in at the relying site, and many integrations will skip them. A self-hosted product can improve on this by making hostname, action, sitekey and client IP checks mandatory on the verify API.
- Since hostname is client-derived in hCaptcha's own description, a self-hosted token should sign the server-observed origin, while recognising that a non-browser client can still lie about Origin.
- Single-use semantics require a shared redemption store with a TTL matching token lifetime. With a 2-5 minute TTL this store stays small.

### Gaps
- Token internal formats are opaque by design and vendors do not document them.
- I found no primary TTL for the Arkose token, `cf_clearance` lifetime, or Enterprise reCAPTCHA token.

## How much depends on cross-site global reputation, and what local replacements are viable?

### Takeaway
Cross-site history visibly matters but is not quantifiable from outside, and no vendor publishes the share. The one direct measurement (ETH) shows a strong effect from a real user's cookies and history. Local replacements can capture part of the value, chiefly consistency rules and per-site learning, but cannot replace cross-site prior-good-history.

### Cited Findings
- [ACADEMIC] Real-user cookies and history reduced mean challenges from 8.38 to 2.71, a significant effect, with bot and human challenge counts then indistinguishable (bot mean 2.71, human 3.50, p = 0.11). Note the sample was 50-100 runs per configuration, on Google's demo site, and the paper has some internal inconsistencies — [Breaking reCAPTCHAv2](https://arxiv.org/html/2409.08831v1)
- [ACADEMIC] A repeated non-VPN IP led to flagging after about 20 runs (the paper gives 19th, 20th and 21st in different places), while a fresh VPN IP per run passed all 100 runs, median 13 challenges vs 9 — [Breaking reCAPTCHAv2](https://arxiv.org/html/2409.08831v1)
- [VENDOR] Arkose separates Global and Custom telltales, so both shared and per-customer signal exist in production, and a score of 0 is possible on either — [Arkose risk score](https://developer.arkoselabs.com/docs/risk-score)
- [VENDOR] Google says reCAPTCHA learns from real traffic on your site and benefits from context about both legitimate and abusive behaviour — [v3 docs](https://developers.google.com/recaptcha/docs/v3)
- [VENDOR] Cloudflare's Ephemeral IDs catch abuse with rotating IPs through patterns beyond IP address, with account-creation thresholds as the main example. This use is per-customer, though the signal generation sits on Cloudflare's platform — [Ephemeral IDs blog](https://blog.cloudflare.com/turnstile-ephemeral-ids-for-fraud-detection/)
- [ACADEMIC] Rules needing no cross-site data cut evasion substantially. Pairwise spatial rules (device claims vs screen or touch values, timezone vs IP location) and temporal rules (immutable attributes changing for the same cookie or IP) reduced evasion by 48.11% against DataDome and 44.95% against BotD, with little loss on held-out data (0.23% and 0.42%) — [FP-Inconsistent](https://arxiv.org/html/2406.07647v3)
- [ACADEMIC] These rules have a cost: true negative rate on 2,206 student requests was 96.84%, with false positives mostly from User-Agent spoofing. Tor was flagged in all cases because of timezone and IP mismatch — [FP-Inconsistent](https://arxiv.org/html/2406.07647v3)

### Inferences
- Viable local replacements, in rough order of expected value (my judgement, not a measurement):
  1. Spatial and temporal consistency rules, maintained like filter lists.
  2. Velocity limits keyed by a short-lived device identifier, ASN and account, not IP alone.
  3. Per-site baselines from the operator's own traffic and labelled outcomes such as confirmed abuse and successful logins.
  4. A first-party signed "returning good client" token as a site-scoped analogue of prior history.
  5. Public IP intelligence (datacentre ranges, known proxies).
  6. An optional opt-in shared feed across deployments, which reintroduces some global view at a privacy cost.
- New visitors are the hard case. A self-hosted deployment starts with no history for a first-time human, so it will see either more challenges or more bot passes on first contact than a global vendor would.
- The FP-Inconsistent rules should be treated as starting templates. They target 2023 bot services, and the authors expect adaptation.

### Gaps
- No source quantifies what fraction of any vendor's detection power comes from cross-site data. The ETH effect size measures one bundle (cookies and history) on one product, and cannot separate Google-account signal from reCAPTCHA-specific history.
- I did not find measurements for the local-replacement options other than consistency rules.

## What do solver services and academic studies show about bypass rates, which defences held up, and what about image CAPTCHAs vs LLMs?

### Takeaway
Grid-style and recognition image CAPTCHAs are broken by commodity models at low cost. Fine-grained localisation, counting and composed tasks are currently harder, but that margin is shrinking and should be seen as temporary. No independent evidence supports a ranking of commercial vendors, and solver-reported 99% figures are unverified.

### Cited Findings

**Human vs bot performance**
- [ACADEMIC, 2023] Across 1,400 participants and 14,000 CAPTCHAs, bot accuracy was 85-100% (mostly above 96%) against human accuracy of 50-85%, and bots were faster almost everywhere. The exception was reCAPTCHA image challenges, at human 18 s vs bot 17.5 s — [Searles et al., USENIX Security 2023](https://arxiv.org/pdf/2307.12108) (snippet). Note that press coverage gives the human upper bound as 84% — [TechXplore](https://techxplore.com/news/2023-08-bots-captcha-humans.amp) (snippet)

**reCAPTCHA v2**
- [ACADEMIC, 2024] 100% solve rate with fine-tuned YOLOv8, vs 68-71% in prior work, using Selenium on Firefox against Google's demo site. Classifier accuracy was only 82.4% top-1, and the bot was "never blocked". This shows that per-challenge accuracy need not be high when retries are free — [Breaking reCAPTCHAv2](https://arxiv.org/html/2409.08831v1). The authors' "100%" is on a demo site with small samples, so it may not carry over to production deployments with risk policies.

**LLM vision solvers**
- [ACADEMIC, USENIX Security 2026] COGNITION tested 7 models, including GPT-5, GPT-5.1, Claude Sonnet 4.5, Gemini 2.5 Pro and Flash, and Qwen3-VL, on 18 task types from the Open CaptchaWorld benchmark — [COGNITION](https://www.usenix.org/system/files/usenixsecurity26-wang-junyu.pdf)
  - Overall, strong models reach about 50-60% one-shot success (GPT-5 59.4% rising to 60.7% with optimised prompts).
  - "Broken" tier, above 40% average: Path_Finder, Select_Animal, Misleading_Click, Image_Recognition, Bingo, Object_Match, Unusual_Detection, Image_Matching, Coordinates, Connect_Icon, Dart_Count. These cost under 10 cents per success with latency in the tens of seconds.
  - "Hard" tier: Patch_Select, Rotation_Match, Click_Order, Pick_Area, Place_Dot, Dice_Count. These cost one to two orders of magnitude more per success.
  - External categories: Hole_Counting 0/140, Symbol_Count 2.9% pooled (best model 10%), Relation_Match 8.1% pooled (best 16.7%).
  - Reference point cited there: human solver services run about 80-90% one-shot accuracy at about 0.5-2 US cents per challenge. On that basis, off-the-shelf LLMs are not yet always cheaper than human farms even on broken types.
  - Hardening test: replacing grid selection with "click on all visible eyes" at 15 px tolerance took baselines of above 80-95% down to 0.0% for GPT-5, GPT-5.1 and Gemini 2.5 Pro, 23.3% for Claude Sonnet 4.5 and 20.0% for Qwen3-VL. The abstract's "over 95% to 0%" overstates this; use the table.
  - Caveats: the threat model is restricted to direct API calls on raw instances, without task decomposition or agent orchestration. The authors say so explicitly and note such systems measure different capability. The conclusion also says 21 task types where the abstract says 18 (18 plus 3 external).
- [ACADEMIC] COGNITION's comparison table lists an agentic VLM solver (Halligan) at 60.7% closed-world and 70.6% in field tasks, over 2,600 closed-world challenges and 3,000 live tasks. This is read from a table whose extraction was messy, so confirm against the original — [COGNITION](https://www.usenix.org/system/files/usenixsecurity26-wang-junyu.pdf)
- [ACADEMIC, 2026 preprint] A system combining LLMs with classical computer vision exceeded 90% across its darknet CAPTCHA types. Only Gemini 3.1 Pro did well on rotation CAPTCHAs, with others near chance — [Breaking Darknet CAPTCHAs](https://arxiv.org/html/2608.28794v1) (snippet). This suggests that rotation, in COGNITION's hard tier, is eroding or at least model-dependent. These are different CAPTCHA families, so the comparison is imperfect.
- [ACADEMIC, 2026 preprint] A fine-tuned YOLOv8 detector with an open-weight VLM reached 85.4% overall and 84.2% macro accuracy over 16 classes, learning from repeated encounters — [Schneier on Security, October 2026](https://www.schneier.com/blog/archives/2026/10/training-ais-to-solve-captchas.html) (snippet), [arXiv 2609.02393](https://arxiv.org/pdf/2609.02393) (too large to fetch; not read in full)
- [Non-peer-reviewed, 2026] A proof of concept reports commodity AI on one laptop solving reCAPTCHA v2 grids using an open-source vision model — [UNU C3](https://c3.unu.edu/blog/captchas-losing-ground-to-ai) (snippet)

**Detection evasion measured in the wild**
- [ACADEMIC, data from 2023] 507,080 purchased bot requests from 20 services against a honey site. Average evasion was 52.93% against DataDome (range 2.56-97.12%) and 44.56% against BotD (range 0.02-100%). My extraction's detection-rate figures appeared swapped: the complements of the evasion rates are 47.07% for DataDome and 55.44% for BotD. The paper also has internal inconsistencies, including two BotD evasion figures — [FP-Inconsistent](https://arxiv.org/html/2406.07647v3). Limits: a single period, a small service set, and a honey site rather than a high-value protected flow.
- [ACADEMIC, earlier] Web Runner 2049 evaluated 15 anti-bot services, 14 of which used WebGL or Canvas fingerprinting, with bots the authors deployed — [as described in FP-Inconsistent](https://arxiv.org/html/2406.07647v3) (I did not read the original).

**Solver services**
- [BYPASS-SEO, self-reported, conflicting] CapSolver about $1.20 per 1,000 Turnstile vs 2Captcha $2.89; 2Captcha about $2.99 per 1,000 reCAPTCHA v2 and $0.50 per 1,000 for ordinary image CAPTCHAs; CapSolver from $0.65 per 1,000. Claimed success is about 99%. Speed claims are 3-9 s for CapSolver on reCAPTCHA v2 and a median of about 13 s for human pools — [AIMultiple](https://research.aimultiple.com/captcha-solving-services), [Scrapfly](https://scrapfly.io/blog/posts/best-captcha-solving-api), [Dev.to](https://dev.to/agenthustler/best-captcha-solving-services-for-web-scraping-in-2026-tested-compared-3g3f) (snippets). I found no independent controlled measurement of these services, and could not attribute each figure to a specific page among these.

**Defences countering solvers**
- [VENDOR] Arkose assigns an explicit FRD-FRM category for fraud farms and solvers, with precedence over botnet labels. It is the only vendor I read that exposes farm detection as a first-class outcome — [Arkose risk score](https://developer.arkoselabs.com/docs/risk-score)
- [ACADEMIC] COGNITION recommends monitoring: a sudden spike in success rates or a convergence of solve times can indicate an automated solver and should trigger a template update. It also recommends rotating render styles and instruction wording — [COGNITION](https://www.usenix.org/system/files/usenixsecurity26-wang-junyu.pdf)

### Inferences
- The strongest evidence-based claim is about challenge types, not vendors: discrete-choice grids should not be relied on as a security boundary.
- At sub-cent to low-cent prices per solve, a challenge's value is a small per-action cost plus a signal. It cannot stop an attacker whose per-action profit exceeds that. This reasoning follows from the price points and is not directly measured.
- Hard-tier task advantages should be treated as a window of perhaps months to a few years, given the movement seen across 2023-2026 results. That time estimate is my judgement.
- Usability of hardened tasks is unproven: COGNITION reasons that they are intuitive but I saw no human study on the hardened task in the text read. Precise 15 px clicks may also pose accessibility and touch-screen issues.

### Gaps
- No independent head-to-head of reCAPTCHA Enterprise, Turnstile, hCaptcha, DataDome, Arkose, Kasada, Akamai and HUMAN exists in my sources, so "which held up best" cannot be answered with evidence. The only vendor-level measurements cover DataDome and BotD, from 2023.
- Neither the ETH study nor COGNITION measures end-to-end success against a production deployment's risk engine plus challenge together.
- No reliable measurement of true solver pass-through rates on Turnstile or Arkose was found.

## What does this imply for a self-hosted design, and which limits should be stated honestly?

### Takeaway
Build a layered risk engine, with image challenges as a small and replaceable component: server-side verdicts, mandatory token binding, consistency rules, per-site learning, and a rotating collector. Publicly state that this raises attacker cost and catches unsophisticated to moderate automation, but does not reliably stop real browsers with residential proxies, human farms or capable agents.

### Cited Findings
Evidence behind the design, each covered above:
- A graduated pipeline with non-interactive first and interactive only on risk gave Cloudflare a reported 91% reduction in CAPTCHA use — [Cloudflare blog](https://blog.cloudflare.com/turnstile-private-captcha-alternative/)
- Consistency rules cut evasion by about 45-48% without any global data, at about 3% false positives in a small test — [FP-Inconsistent](https://arxiv.org/html/2406.07647v3)
- Grid CAPTCHAs fall to commodity models, whereas fine localisation with counting raises cost now — [COGNITION](https://www.usenix.org/system/files/usenixsecurity26-wang-junyu.pdf), [Breaking reCAPTCHAv2](https://arxiv.org/html/2409.08831v1)
- Presenting CAPTCHAs instead of hard blocks can reduce the cost of false positives — [FP-Inconsistent](https://arxiv.org/html/2406.07647v3)
- Humans are not reliably accurate on CAPTCHAs (50-85%), so a challenge is itself a false-positive source — [Searles et al.](https://arxiv.org/pdf/2307.12108)
- Mouse trajectory shape alone did not distinguish Bézier from straight lines in reCAPTCHA v2's outcome, so a naive behavioural check adds little — [Breaking reCAPTCHAv2](https://arxiv.org/html/2409.08831v1). This reflects one product's response and not the potential of behavioural signals generally.

### Inferences

All items in this section are my synthesis.

**Priority order for build effort**
1. Server-side protocol correctness. Signed, short-lived (2-5 minutes), single-use tokens, with mandatory sitekey, action, hostname and optional IP binding, and a redemption store. Cheap, and the common failure mode elsewhere.
2. Risk pipeline and response ladder. Silent pass, then cheap proof-of-work with a probe, then visual challenge, then block or rate limit. Log everything in shadow mode first, as Google advises for thresholds.
3. Consistency rules for client claims, TLS and HTTP fingerprints, and temporal stability, shipped as updatable lists.
4. Local velocity and reputation, keyed on device identifier, ASN and account, with per-site tuning from operator feedback.
5. Collector integrity. Obfuscated rotating builds with per-version server-side validation, and encrypted payloads with self-integrity checks. Value lies in rebuild cost, and it decays if not refreshed, so automate the rotation.
6. Proof-of-work. Use as a rate limiter and cost adder, adjusted by risk, not as a humanity signal. Keep it short for humans on low-end phones.
7. Visual challenges. Least durable. Prefer fine localisation and composed tasks, rotate templates and wording, cap retries (ETH shows free retries defeat imperfect classifiers), and provide an accessible alternative.
8. Solver and farm monitoring. Track solve-time convergence, success spikes, and token-generation vs token-use environment mismatch.
9. Device attestation such as PAT, only if issuer participation proves possible. Otherwise out of scope.

**Limits to state honestly**
- A real browser on a residential or mobile IP, driven by a careful operator, will often look like a human to any client-side check. Even commercial services saw about half of purchased bot traffic evade in the 2023 honey-site study.
- Human solver farms pass any human-oriented test. Detection can only rely on context such as velocity, device reuse and token mismatch.
- Multimodal agents already solve recognition tasks, and the hard set will shrink.
- A self-hosted system has no cross-site prior history, so expect weaker first-visit decisions than global vendors, and say so.
- Client-side code is ultimately readable. Obfuscation buys time, not secrecy.
- Privacy tools, Tor, VPNs, spoofing extensions and old devices will create false positives. Provide a fallback, and publish measured false-positive rates by segment.
- Avoid quoting a single "bot detection rate". Report by attacker tier, using the operator's own red-team and shadow-mode data, and date the figures. Public numbers from vendors or solvers are not comparable.

### Gaps
- I found no public data on the marginal value of each layer, so the priority order is a judgement rather than a measurement.
- Self-hosted PoW parameters, TLS and HTTP fingerprinting efficacy, and legal or privacy constraints on fingerprinting (for example GDPR consent) were outside what I verified here, and need their own sources.
- Sources for 2026 are partly preprints I read only through snippets (arXiv 2608.28794, 2609.02393). The report should cite them cautiously.
