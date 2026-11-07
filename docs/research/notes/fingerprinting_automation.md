# Browser/device fingerprinting and automation detection for a self-hosted CAPTCHA (as of 2026-11-07)

Reading guide for the report writer:
- Ratings for entropy, stability, spoofing robustness and cost are **my engineering judgement**, not measurements. I found no source that measures them across this signal set.
- `[K]` marks API names or behaviour from background knowledge that I did not verify this session. Check them against MDN or the spec before relying on them.
- Sourcing is weak in places. Much 2025-2026 material comes from vendors, or from scraping or anti-detect vendors with a commercial interest. These are flagged inline. Castle (Antoine Vastel) is also a vendor, but it explains mechanisms and cites commits.

---

## Client signals: what to collect, what each reveals, and how privacy browsers distort them

### Takeaway
Client signals are most useful as inputs to consistency checks, not as identifiers. Canvas, audio, WebGL, screen and hardware values are now legitimately noised or normalised by Brave, Firefox RFP, Tor/Mullvad and, by default, Safari 26. A noised or generic value must therefore never count as bot evidence on its own.

### Cited Findings

**Purpose of signals**
- Castle's guide to building your own detection prioritises resilience over uniqueness or stability, because the goal is detecting automation rather than long-term tracking — [Castle part 1, Oct 2025](https://blog.castle.io/roll-your-own-bot-detection-fingerprinting-javascript-part-1/)
- Its core set is `hardwareConcurrency`, `deviceMemory`, `maxTouchPoints`, UA, screen, languages, timezone, platform, unmasked WebGL vendor/renderer, canvas, automation flags, and a Worker re-collection of a subset — [Castle part 1](https://blog.castle.io/roll-your-own-bot-detection-fingerprinting-javascript-part-1/)
- Its collector wraps each signal in try/catch and records failures as `'ERROR'`. Canvas output is hashed with SHA-256 and truncated to 8 hex characters — [Castle part 1](https://blog.castle.io/roll-your-own-bot-detection-fingerprinting-javascript-part-1/)
- If an anti-canvas extension is detected, the canvas hash is replaced with `IGNORE` so noise does not break the rate-limit key — [Castle part 2](https://blog.castle.io/roll-your-own-bot-detection-server-side-detection-part-2/)

**Entropy and stability evidence (older, limited)**
- In a large AmIUnique-based study, canvas (PNG) had normalised entropy of about 0.42, against 0.491 in the original AmIUnique measurement. Normalised values fall as the dataset grows, because the denominator is log2(N) — [Andriamilanto et al., arXiv 2006.09511](https://arxiv.org/pdf/2006.09511)
- The 2016 AmIUnique slides call canvas the 4th most revealing attribute and "really stable" — [Laperdrix, IEEE S&P 2016 slides](https://www.ieee-security.org/TC/SP2016/slides/25-3/laperdrix.pdf). This predates default noise in Safari and Brave.
- AmIUnique dropped its three-object WebGL rendering test as too unreliable and collects vendor/renderer strings instead — [Laperdrix slides](https://www.ieee-security.org/TC/SP2016/slides/25-3/laperdrix.pdf)

**WebGPU and UA-CH**
- `GPUAdapter.info` exposes `vendor`, `architecture`, `device`, `description`, `isFallbackAdapter` and `subgroupMinSize`/`subgroupMaxSize`. Empty strings are allowed, browsers may vary the detail, it needs a secure context, it is available in Workers, and MDN marks it Limited availability — [MDN GPUAdapterInfo](https://developer.mozilla.org/en-US/docs/Web/API/GPUAdapterInfo)
- `navigator.userAgentData` provides `brands`, `mobile` and `platform` as low-entropy values. `getHighEntropyValues()` provides `architecture`, `model`, `platformVersion`, `fullVersionList` and others. `WorkerNavigator.userAgentData` also exists. It is not Baseline — [MDN UA-CH API](https://developer.mozilla.org/en-US/docs/Web/API/User-Agent_Client_Hints_API). Firefox and Safari not shipping the JS API is `[K]`.

**Privacy browser behaviour**
- **Firefox RFP** — [Mozilla wiki](https://wiki.mozilla.org/Security/Fingerprinting):
  - Timezone UTC, locale en-US, `hardwareConcurrency` 2.
  - Window dimensions rounded to multiples of 200x100, absolute screen coordinates obscured, orientation spoofed.
  - Timers reduced to 100 ms with jitter, Performance API mostly disabled.
  - `WEBGL_debug_renderer_info` disabled.
  - `enumerateDevices` reports one "Internal Camera" and one "Internal Microphone".
  - WebSpeech disabled, plugins and mimeTypes empty, fonts restricted to an allowlist.
  - `prefers-color-scheme` always light, system media queries never match.
  - Browser version reported as latest ESR; OS not spoofed.
- Under RFP, canvas read-back returns noise, and Mozilla recommends its less disruptive Fingerprinting Protection mode for most users — [Mozilla support](https://support.mozilla.org/kb/resist-fingerprinting)
- **Brave** farbles canvas, WebGL/WebGL2 (including unmasked vendor/renderer strings and `readPixels`), Web Audio, `navigator.plugins`, `enumerateDevices`, `navigator.userAgent` and others — [Brave](https://brave.com/privacy-updates/4-fingerprinting-defenses-2.0/)
- Brave's seed is an HMAC of a per-browser-session token with the top-frame domain, so values are stable per site within a session and change between sessions and between sites. Default mode perturbs real values; Maximum returns randomised values — [Brave](https://brave.com/privacy-updates/4-fingerprinting-defenses-2.0/). This post is older and does not cover `hardwareConcurrency` or `deviceMemory`, although FP-Inconsistent observed those changing in Brave — [FP-Inconsistent](https://arxiv.org/html/2406.07647v3)
- **Tor Browser** starts with a content window rounded to multiples of 200x100 — [Tor support](https://support.torproject.org/tor-browser/features/fingerprinting-protections/)
- **Mullvad Browser** aims for the same protections as Tor Browser. It reports UTC, a common version and OS, uses size buckets, disables WebGL `readPixels`, and auto-declines canvas prompts that lack user input — [Mullvad hard facts](https://mullvad.net/en/browser/hard-facts). The page may be somewhat stale.
- **Safari 26** enables Advanced Fingerprinting Protection for all browsing by default, per secondary sources. It reportedly injects noise into 2D canvas and WebGL read-back and `AudioBuffer` samples — [ppc.land](https://ppc.land/safari-26-tracking-changes-to-impact-marketing-measurement/), [9to5Mac](https://9to5mac.com/?p=1011798)
- One author lists screen size, `hardwareConcurrency` and SpeechSynthesis voices as also covered, but could not reliably reproduce the subset. Treat the exact API list as unconfirmed — [engineered.at](https://engineered.at/articles/safari-26-advanced-fingerprinting-protection-a-confusing-feature)

### Inferences

**Catalogue.** Ratings are judgement. "FP" means false-positive risk. "Use" is the recommended role.

| Signal | Collect via | Reveals | Entropy / stability | FP risks | Spoof robustness | Cost | Use |
|---|---|---|---|---|---|---|---|
| Canvas 2D | `toDataURL`, `getImageData`, `measureText` | Rasteriser, fonts, OS/GPU | High / medium; volatile on driver and browser updates | Noised in Brave, RFP, Safari 26; blocked by Tor/Mullvad and extensions | Medium: easy to noise, harder to noise plausibly | ~1-10 ms | Compare main vs Worker `OffscreenCanvas` vs iframe, plus a noise test. Never allowlist by hash |
| WebGL renderer | `getParameter(VENDOR/RENDERER)`, `WEBGL_debug_renderer_info` | GPU, software renderer | Medium / high | RFP disables; Brave farbles; VDI/Citrix use software | Low for the string, medium for the rest | ~5-30 ms (context creation) | OS-vs-GPU plausibility; main vs Worker |
| WebGL/WebGL2 parameters | `getParameter(MAX_*)`, `getSupportedExtensions`, `getShaderPrecisionFormat` | Real GPU limits | Medium / high | Brave farbles some | Medium-high: must match a real GPU | ~5 ms | Check limits against claimed renderer class |
| WebGPU adapter | `navigator.gpu.requestAdapter()`, `.info`, `.limits`, `.features` | GPU family, fallback adapter | Low-medium / high | Often absent; empty strings legal | Medium | ~10-100 ms, async | Compare with WebGL family. Absence is neutral. `isFallbackAdapter=true` is soft |
| AudioContext | `OfflineAudioContext`, `getChannelData` | Audio stack, engine | Low-medium / medium | Noised in Brave, Safari 26 | Medium | ~5-50 ms | Noise detection and engine class only |
| Fonts | `measureText`/DOM width probes, `document.fonts.check` `[K]` | OS, installed software | High / medium | Tor/Mullvad/RFP allowlist | Medium | 10-100 ms for a small list | Small OS-defining list only (Windows vs macOS vs Linux) |
| UA-CH | `userAgentData`, `Sec-CH-UA*` headers | Brand, version, platform | Medium / high | Absent in Firefox, Safari `[K]` | Low alone, high across layers | ~1 ms | JS vs header vs Worker vs TLS comparison |
| Navigator | `userAgent`, `platform`, `languages`, `hardwareConcurrency`, `deviceMemory`, `maxTouchPoints`, `plugins` | Claimed identity | Medium / high | RFP normalises; UA-switcher extensions | Low alone | <1 ms | Consistency inputs |
| Screen/window | `screen.*`, `outerWidth`, `innerWidth`, `devicePixelRatio`, `visualViewport` | Device class, headless defaults | Medium / medium | RFP/Tor rounding; kiosks; docked windows | Low | <1 ms | Impossible combinations. Default sizes are soft |
| Timezone/Intl | `Intl.DateTimeFormat().resolvedOptions()`, `getTimezoneOffset` | Locale vs IP region | Low-medium / high | UTC in RFP/Tor/Mullvad; VPN and travel | Medium | <1 ms | Soft geo check. **Exempt UTC** |
| Permissions | `permissions.query` vs `Notification.permission` | Headless-shell inconsistency | Low / high | Enterprise policy; browser differences | Medium | ~1 ms | Treat a mismatch as soft-to-medium, Chromium only |
| Media devices | `enumerateDevices` (labels hidden without permission) | Device count | Low / medium | RFP fixed; Brave farbled; servers and VMs have none | Low | ~1-10 ms | Soft only. Do not request permission |
| Speech voices | `speechSynthesis.getVoices` | OS voice set | Medium / medium; async loading | Disabled in RFP; possibly limited in Safari | Medium | Up to ~100 ms | OS plausibility, skip if empty |
| Storage quota | `navigator.storage.estimate()` | Disk class, private mode | Low / low | Private modes, disk size, Safari | Low | ~1 ms | Low value. Skip or log only |
| Timer behaviour | `performance.now` deltas, rAF cadence `[K]` | Clamping, throttled or virtual time, rendering loop | Low / medium | RFP 100 ms; background tabs; battery saver | Medium | ~10-100 ms | Check claim-vs-resolution; detect no rAF while "visible" |
| Math/engine quirks | `Math.*` results, `eval.toString().length`, error messages | True JS engine | Low / high | Few | **High**: hard to fake without changing engine | <1 ms | Verify claimed engine |
| Error-stack format | `new Error().stack`; BotD's `null[0]()` | Engine, wrappers, injected frames | Low / high | Extensions add frames | Medium-high | <1 ms | Engine check, wrapper detection |
| Worker consistency | `Worker`, re-collect navigator, WebGL via `OffscreenCanvas` | Main-world-only patches | n/a | CSP blocking blob workers; some extensions patch only main world | **High** against JS patching; low against engine-level patching | ~10-50 ms | Top-tier. Serve the worker from your own origin |
| Iframe consistency | Same-origin `iframe.contentWindow` | Patches missing from new realms | n/a | Extensions | Medium-high | ~5 ms | Top-tier. Also `srcdoc`, nested realms |
| CSS media queries | `matchMedia`, computed `ActiveText`/system colours | OS, pointer type, colour scheme | Low-medium / high | RFP forces values | Medium | <1 ms | Cross-check `pointer`/`hover` with touch claims; OS colours vs claimed platform |

**Design notes**
- The Safari 26 change makes the noise problem mainstream. Any rule of the form "canvas noise means suspicious" would now hit ordinary Apple users, not just a niche.
- Worker and iframe checks should compare **claim-level** values, not raw canvas bytes, unless the noise is known to be per-domain deterministic. Brave's seed design suggests equality within a session, but I did not test this across contexts.
- A render-twice test separates per-call noise from per-session noise, but the outcome differs per browser and needs lab calibration.
- `speechSynthesis`, WebGPU and `enumerateDevices` are async and can be slow. Run them with a strict time budget and record `timeout` as a neutral value.
- Missing APIs should map to "unknown", never "fail".

### Gaps
- No current, per-signal entropy or stability table was found. [Assessing Web Fingerprinting Risk](https://arxiv.org/pdf/2403.15607) looks relevant but I did not read it, and FP-Stalker was not retrieved. The older figures above are pre-Safari 26.
- No primary WebKit technical documentation of Safari 26 AFP was found. A controlled lab test should settle the API list.
- WebGPU availability by browser was not verified, because the compatibility table was missing from the fetched page.
- Voices, audio, fonts, storage quotas, and timer cost and FP figures have no direct source this session. Their table rows are judgement.
- Whether Firefox's default Fingerprinting Protection (not RFP) changes these values on normal Firefox was only seen in a forum post, so it is not asserted here.

---

## Automation artefacts and the 2026 state of stealth tooling

### Takeaway
Static artefacts still catch default-configured and low-effort automation cheaply, but modern tools target exactly these checks. The classic `Runtime.enable` stack-getter signal died in May 2025, and residual variants are contested. `navigator.webdriver` is a cheap positive only. Durable detection now depends on cross-context consistency, native-tamper checks for JS-patched tools, cross-layer checks, behaviour and population statistics. Engine-level tools such as Camoufox defeat JS lie detection by design.

### Cited Findings

**CDP `Runtime.enable` side channel**
- **Mechanism:** an Error with a custom `stack` getter is logged with `console.debug()`. CDP serialisation ran the getter only when the client had enabled the Runtime domain — [Castle, Aug 2025](https://blog.castle.io/why-a-classic-cdp-bot-detection-signal-suddenly-stopped-working-and-nobody-noticed/)
- **The fix:** V8 commits on 7 and 9 May 2025 ("Avoid error side effects in DevTools", "Apply getter guard throughout error preview") added `getErrorProperty(...)` in `value-mirror.cc`, skipping user getters for `.stack`, `.name` and `.message`, so the flag stays false. Castle no longer relies on this signal or on `navigator.webdriver` — [Castle](https://blog.castle.io/why-a-classic-cdp-bot-detection-signal-suddenly-stopped-working-and-nobody-noticed/)
- **Source conflict on residual variants:**
  - [Crawlex](https://blog.crawlex.net/blog/playwright-puppeteer-selenium-detection/) labels the Runtime.enable signal obsolete.
  - [Scrapfly, Oct 2026](https://scrapfly.io/blog/posts/chrome-cdp-stealth-browser-automation-detection-explained) reports that the Brotector test on Chrome 152 recorded `stackLookupCount:0` and `nameLookupCount:3` with `Runtime.enable`, and no detection when attached without that domain. This is a getter on `Error.prototype.name`.
  - [rebrowser-bot-detector](https://raw.githubusercontent.com/rebrowser/rebrowser-bot-detector/main/README.md) still ships a check using stack hook and `name` reads.
  - A [DEV post, Apr 2026](https://dev.to/shuicici/v8s-official-devtools-fingerprint-patch-has-two-live-bypasses-heres-why-the-spec-is-to-blame-5gdn) claims inherited-getter and prototype-Proxy paths remain live, but offers source reasoning only, with no test data.
- Castle wrote that it still detects CDP-based automation through other unnamed JS signals that leak in certain setups — [Castle](https://blog.castle.io/why-a-classic-cdp-bot-detection-signal-suddenly-stopped-working-and-nobody-noticed/)
- **False positive:** this check flags humans with DevTools open — [Castle Playwright, Mar 2025](https://blog.castle.io/how-to-detect-headless-chrome-bots-instrumented-with-playwright/), [Rebrowser](https://rebrowser.net/blog/how-to-fix-runtime-enable-cdp-detection-of-puppeteer-playwright-and-other-automation-libraries)
- Secondary reporting of Castle's experience: "Even the simplest bots, the ones that used to get caught, don't trigger the CDP signal anymore" — [Centinel Analytica](https://www.centinelanalytica.com/blog/patched-chromium-browsers) (quoted second-hand; not located in the Castle post)

**Driver artefacts**
- **ChromeDriver:** `cdc_adoQpoasnfa76pfcZLmcfl_*` properties and `window.ret_nodes`; prefix editing defeats a literal match but not a structural one — [Crawlex](https://blog.crawlex.net/blog/playwright-puppeteer-selenium-detection/), citing Castle
- **BotD's structural pattern:** `/^([a-z]){3}_.*_(Array|Promise|Symbol)$/` plus `__selenium_*`, `__webdriver_*`, `__driver_evaluate` and others — [BotD source](https://github.com/fingerprintjs/BotD/blob/main/src/sources/distinctive_properties.ts)
- **Playwright:** `__playwright__binding__`, `__pwInitScripts`, functions with `__installed`, and exposed-function `toString()` containing binding code. Results are version-specific (HeadlessChrome 133) — [Castle](https://blog.castle.io/how-to-detect-headless-chrome-bots-instrumented-with-playwright/)
- **Puppeteer:** fewer distinctive globals. Binding names via `Runtime.addBinding` remain but internal names change between versions, so hard-coded checks decay — [Crawlex](https://blog.crawlex.net/blog/playwright-puppeteer-selenium-detection/)
- **`navigator.webdriver`:** `--disable-blink-features=AutomationControlled` makes it false — [Castle](https://blog.castle.io/how-to-detect-headless-chrome-bots-instrumented-with-playwright/)
- **Headless:** since the Nov 2022 unification, headless runs on the same codebase as Chrome, so API-discrepancy detection became largely ineffective — [Castle, Jun 2025](https://blog.castle.io/from-puppeteer-stealth-to-nodriver-how-anti-detect-frameworks-evolved-to-evade-bot-detection/). The `HeadlessChrome` UA token is obsolete for `--headless=new` — [Crawlex](https://blog.crawlex.net/blog/playwright-puppeteer-selenium-detection/)

**Open-source check suite: [rebrowser-bot-detector](https://raw.githubusercontent.com/rebrowser/rebrowser-bot-detector/main/README.md)**
- `sourceUrlLeak`: Puppeteer source URL in stacks.
- `mainWorldExecution`: instrumented `document.querySelector` calls.
- `cdpBindingGlobals`: empty-named native functions; soft, because it can be imitated.
- `headless`: for chrome-headless-shell, missing `window.chrome` and the Notification/permissions mismatch; soft signals are no pointer, 800x600, SwiftShader.
- `platformMismatch`: including `ActiveText` system colour by OS.
- `workerConsistency`: UA, platform and brands mismatch is strong; languages and core count weaker.
- `bypassCsp`.
- `viewport`: 800x600 and 1280x720, soft.
- `mobileEmulation`: `maxTouchPoints` 1 with desktop platform, Chromium under an iPhone UA.
- `documentInterception`: empty `nextHopProtocol` with data transferred.
- `popupBlocking`: `window.open` without a click opens; soft.
- `ipcFloodingProtection`: all 300 `history.replaceState` calls succeed when normally only 200 per 10 s do.
- `storagePartitioning`: Chromium 148+, specific domains only.
- `nativeTampering`: Proxy wrappers, cyclic `__proto__`, wrappers in stacks, `iframe.contentWindow` returning the parent.

**Lie detection**
- CreepJS `queryLies` tests native API functions for — [CreepJS `src/lies/index.ts`](https://github.com/abrahamjuliot/creepjs/blob/master/src/lies/index.ts):
  - Illegal-invocation and TypeError behaviour on `.prototype`, `call`, `apply`, `new`, `class extends`.
  - Null-prototype conversion and `Function.prototype.toString` output against known native forms.
  - Presence of `prototype`, `arguments`, `caller`.
  - Own keys exactly `length,name`.
  - Own properties on `navigator`/`screen` instances.
  - Proxy tells through stack frames (`at Function.toString` vs `at Object.toString`), Gecko strict-mode errors, and "too much recursion" from prototype cycles.
  - It runs these from a nested "behemoth" iframe realm in Blink.
- CreepJS code is MIT but the name is trademarked, and public forks must be renamed — [CreepJS](https://github.com/abrahamjuliot/creepjs). Last commit 2026-06-11, per GitHub API query this session.
- Its components include contentWindow, CSS system and computed styles, Math runtime, console errors, DomRect, SVG, audio, canvas, TextMetrics, WebGL, fonts, voices, screen, "Resistance (known patterns)" and timezone — [CreepJS](https://github.com/abrahamjuliot/creepjs)
- BotD's detector list: `app_version`, `distinctive_properties`, `document_element_keys`, `error_trace`, `eval_length`, `function_bind`, `languages_inconsistency`, `mime_types_consistence`, `notification_permissions`, `plugins_array`, `plugins_inconsistency`, `process`, `product_sub`, `rtt`, `user_agent`, `webdriver`, `webgl`, `window_external`, `window_size` — [BotD tree](https://github.com/fingerprintjs/BotD/tree/main/src/detectors)
- BotD is MIT with a "stability-only" roadmap. Its own table says it does **not** detect puppeteer-extra stealth, browserless, undetected-chromedriver or pyppeteer_stealth, and it rates headless detection as partial — [BotD README](https://github.com/fingerprintjs/BotD)
- BotD's detection rate is limited in practice: bots exploited PDF-plugin presence and touch support to evade it — [FP-Inconsistent](https://arxiv.org/html/2406.07647v3)
- Wrapper patches leak through stack traces and exception types, and naive overrides create side effects — [Castle, Jun 2025](https://blog.castle.io/from-puppeteer-stealth-to-nodriver-how-anti-detect-frameworks-evolved-to-evade-bot-detection/)

**Stealth tools (status from GitHub API and READMEs, 2026-11-07)**

| Tool | Status | Approach | Detection implication |
|---|---|---|---|
| [Patchright](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright) | Active, Apache-2.0, Chromium only | Avoids `Runtime.enable` via isolated contexts; patches `Console.enable` leak and command flags; init scripts injected via routes into HTML. README's "undetectable" claim is self-reported | Protocol artefact checks fail by design. rebrowser's detector also lists older Patchright `exposeFunction` leaks |
| [rebrowser-patches](https://github.com/rebrowser/rebrowser-patches) | Active, MIT | Disables automatic `Runtime.enable`, using isolated world or an enable/disable window, which leaves a small timing window; patches are fragile — [Rebrowser](https://rebrowser.net/blog/how-to-fix-runtime-enable-cdp-detection-of-puppeteer-playwright-and-other-automation-libraries) | Older versions left binding globals; tuned against public test suites |
| [nodriver](https://github.com/ultrafunkamsterdam/nodriver) | Active, AGPL-3.0 | No chromedriver or Selenium; README exposes CDP domains | **Conflict:** [Castle](https://blog.castle.io/from-puppeteer-stealth-to-nodriver-how-anti-detect-frameworks-evolved-to-evade-bot-detection/) says it eliminates CDP use, but the README describes CDP access. Do not assume "no CDP" |
| [Selenium-Driverless](https://github.com/kaliiiiiiiiii/Selenium-Driverless) | **Archived**; author says they can no longer maintain it. API reports MIT, [Scrappey](https://scrappey.com/qa/web-automation/what-is-selenium-driverless) says CC BY-NC-SA (conflict) | CDP directly, no chromedriver | No `cdc_` or webdriver artefacts; forks may continue |
| [Camoufox](https://github.com/daijro/camoufox) | Active repo, MPL-2.0 | Firefox fork with C++-level patches; Juggler page agent in an isolated world; input patches model real mouse coalescing | JS lie checks are unlikely to fire. See below |
| puppeteer-extra-stealth | Reportedly no longer actively updated — [Scrappey](https://scrappey.com/qa/web-automation/what-is-selenium-driverless) (secondary) | JS overrides | Largely covered by lie checks |

**Camoufox evidence is mixed and non-independent**
- A vendor claims its September 2026 benchmark flagged every Camoufox session — [Centinel](https://www.centinelanalytica.com/blog/what-is-camoufox)
- A separate benchmark found it passed roughly as many Cloudflare targets as other tools — [DEV benchmark](https://dev.to/ianlpaterson/anti-detect-browser-benchmark-2026-7-stealth-tools-31-cloudflare-targets-651-verdicts-4361)
- An unofficial page mentions mismatched data and an older Firefox base hurting results — [camoufox-web.pages.dev](https://camoufox-web.pages.dev/stealth)
- A maintainer step-down is reported through an aggregator — [scour.ing](https://scour.ing/@abnv/p/https://camoufox.com)
- Reported base versions conflict: Firefox 152 in [ScrapingBee](https://www.scrapingbee.com/blog/how-to-scrape-with-camoufox-to-bypass-antibot-technology/) vs 135 in the DEV benchmark.

**Software rendering**
- Chromium's intent-to-remove says WebGL context creation will fail rather than fall back to SwiftShader, with an opt-in `--enable-unsafe-swiftshader` flag. Deprecation began in Chrome 130 and desktop shipping was estimated for 137. SwiftShader was about 2.7% of WebGL contexts, is not used on mobile, and a developer raised concerns about Citrix users — [blink-dev](https://groups.google.com/a/chromium.org/g/blink-dev/c/yhFguWS_3pM)
- Spoofing the renderer name while the wider WebGL surface still looks like SwiftShader is described as a cross-signal inconsistency — [Scrappey](https://scrappey.com/qa/anti-bot/what-is-the-swiftshader-renderer-tell) (vendor, secondary)

**Evidence that public signal sets decay**
- FP-Inconsistent, 507,080 requests from 20 bot services in Sept-Nov 2023. Evasive bots mainly used low `hardwareConcurrency` against DataDome and PDF plugin plus touch support against BotD — [arXiv 2406.07647v3](https://arxiv.org/html/2406.07647v3)
- The paper's abstract and body disagree on which evasion figure (52.93% or 44.56%) belongs to which detector, per my reading of the fetched text. Cite with care.

### Inferences

**Status of each check as of 2026.** Ratings are judgement and should be validated with an in-house lab of current tool versions.

| Check | Status | Use |
|---|---|---|
| `navigator.webdriver === true` | Still catches defaults; `false` means nothing | Strong positive, ignore negatives |
| Driver globals (`cdc_` structure, `__pwInitScripts`, `__playwright__binding__`, `__selenium_*`) | Current for stock tools; beaten by patched tools | Cheap strong positive. Scan structurally, not by exact name |
| `HeadlessChrome` in UA or `Sec-CH-UA` | Still catches careless clients | Cheap strong positive |
| Classic own-`stack` getter CDP probe | **Obsolete** since May 2025 | Remove |
| `Error.prototype.name` / inherited-path CDP probes | Contested; Patchright-style tools avoid the domain anyway | Log-only until lab-tested against each Chrome stable. FP on DevTools users |
| Native-function lie tests | Effective against JS patching tools; blind to engine-level patches | Medium-strong when several fire. Discount for known extension patterns |
| Worker/iframe consistency | Effective unless spoof is at engine level or injected into all realms | Top-tier |
| SwiftShader/llvmpipe renderer | Fewer legitimate Chrome users if fallback removal shipped, but VDI, VMs and enterprise policy remain | Soft signal; never block alone |
| Default viewport, no pointer | Soft | Score only |
| `ipcFloodingProtection`, popup, nested-partition probes | Reveal launch flags, but intrusive and fixable by flags | Run only in lab, or at most log-only; opening a popup or spamming history in a widget is unacceptable UX |
| Headless-only API differences (old Vastel-era `plugins`, `chrome` object, etc.) | Largely obsolete for new headless | Keep only for chrome-headless-shell and older stacks |

**Design consequences**
- Treat `lies` as two classes: **human-tool lies** (privacy extension patterns, known farbling) and **automation lies** (patches to `navigator.webdriver`, `permissions.query`, `Function.prototype.toString`, or UA-CH). Weigh only the second heavily. FP-Inconsistent's few real-user false positives were mainly UA spoofers ([source](https://arxiv.org/html/2406.07647v3)), so this distinction has empirical support.
- Rotate probe implementation, not just names: multiple equivalent forms, randomised order, per-release shuffling. Static checks copied from public suites are the target of tools tuned to pass them, a concern Castle raises for rebrowser ([source](https://blog.castle.io/from-puppeteer-stealth-to-nodriver-how-anti-detect-frameworks-evolved-to-evade-bot-detection/)).
- Engine-level tools can only be addressed by population plausibility (does this GPU, OS, font and voice combination exist?), cross-layer checks, IP/ASN, behaviour, and cost imposition (PoW, rate limits). Expect limited detection and plan for adding cost rather than for a perfect classifier.
- Keep a test harness in CI: Chrome stable + Firefox + Safari + Brave + Tor/Mullvad as negative controls; Playwright, Puppeteer, Selenium, Patchright, rebrowser and Camoufox as positive controls.

### Gaps
- No independent, reproducible 2026 benchmark of these tools against open-source checks was found. Available benchmarks are vendor-run, target Cloudflare, or lack methodology.
- `Runtime.enable` residual behaviour on current Chrome lacks an independent test. Only Scrapfly's control run has numbers, and it did not publish a full procedure.
- Whether Chrome 137 shipped the SwiftShader fallback removal as planned, and whether an enterprise policy exists, was not confirmed.
- DataDome's CDP and "end of fingerprinting" posts returned HTTP 403, so they could not be read. [Antoine Vastel's personal blog](https://antoinevastel.com) was not reviewed directly; his Castle posts were used instead.
- Detection vectors specific to Juggler/Firefox automation were not found in a primary source.
- `[K]` Whether utility-world names or `sourceURL` markers remain current for each driver was not established; only Puppeteer's `sourceUrlLeak` is sourced above.

---

## Network signals: TLS, HTTP/2 and IP data in a self-hosted Docker stack

### Takeaway
JA4 and the Akamai-style HTTP/2 fingerprint are practical self-hosted if something you control terminates TLS and captures the handshake. A TCP-routed Go listener gives full data; proxy modules give partial data via a trusted header. **Licensing matters:** JA4 is BSD, but JA4H, JA4T and the rest are under a licence that restricts commercial distribution and hosted services. IP context can be done entirely with local free datasets, so no client data needs to leave the deployment.

### Cited Findings

**JA4 family and licensing**
- JA4 format `a_b_c` — [FoxIO JA4 spec](https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/technical_details/JA4.md):
  - `a`: transport (`t`/`q`/`d`), TLS version, SNI flag, cipher count, extension count, first and last characters of the first ALPN.
  - `b`: first 12 hex of SHA-256 of sorted ciphers.
  - `c`: first 12 hex of SHA-256 of sorted extensions plus signature algorithms in original order.
  - GREASE is ignored; SNI and ALPN are excluded from hash `c`.
- JA4 sorts extensions, reducing unique fingerprints for modern browsers — [Cloudflare docs](https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/). Chrome's JA3 varies per connection because of extension permutation — [fingerproxy](https://raw.githubusercontent.com/wi1dcard/fingerproxy/master/README.md). So JA3 needs sorting to be useful.
- JA4 (TLS client) is BSD 3-Clause. FoxIO says it has no patent claims on it — [FoxIO README](https://github.com/FoxIO-LLC/ja4), [LICENSE-JA4](https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/LICENSE-JA4)
- JA4S, JA4H, JA4L, JA4LS, JA4X, JA4T, JA4TS, JA4SSH and others use FoxIO License 1.1 and are patent-pending per the README. Internal business use without direct monetisation counts as non-commercial; **hosted or managed service provision does not**, nor does providing maintenance, support or development services for the software, nor charging for access — [FoxIO LICENSE](https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/LICENSE)
- JA4H fingerprints each HTTP request; its header count excludes Cookie and Referer — [JA4H doc](https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/technical_details/JA4H.md). The fetched doc did not contain the full field layout.
- Cloudflare: fingerprints identify a client *type* rather than an individual, are absent on non-TLS traffic, and **resumed sessions skip fingerprint calculation**. Enterprise-only Bot Management is needed. `ja4Signals` include `h2h3_ratio_1h`, `browser_ratio_1h`, `heuristic_ratio_1h`, `uas_rank_1h`, `ips_rank_1h`, `reqs_quantile_1h` — [Cloudflare](https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/). The field semantics are undefined on that page; the names suggest per-fingerprint hourly aggregates.

**HTTP/2**
- Akamai's format is `S[;]|WU|P[,]#` plus pseudo-header order: SETTINGS, the WINDOW_UPDATE increment (`00` if absent) and PRIORITY frames, with order differing by client implementation — [Akamai white paper, Black Hat EU 2017](https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf)
- A modern example is `3:100;4:10485760;2:0|1048510465|0|m,s,a,p` — [fingerproxy](https://raw.githubusercontent.com/wi1dcard/fingerproxy/master/README.md)

**Self-hosted implementation options**
- **fingerproxy** (Go, Apache-2.0, pushed Oct 2026): HTTPS reverse proxy terminating TLS, forwarding `X-Ja3-Fingerprint`, `X-Ja4-Fingerprint`, `X-Http2-Fingerprint` — [README](https://raw.githubusercontent.com/wi1dcard/fingerproxy/master/README.md). A search snippet from its package page flagged bugs in JA3/JA4 code of *other* projects (gospider007/fp, TrackMe), which shows how easy these are to implement incorrectly.
- **Finch** (Go, Apache-2.0): JA3, JA4 with QUIC, JA4H and HTTP/2, with rule-based routing — [ecosyste.ms](https://awesome.ecosyste.ms/projects/github.com%2F0x4d31%2Ffinch). Bundling JA4H still needs licence review.
- **Go libraries:** [helloprint](https://pkg.go.dev/github.com/Easonliuliang/helloprint) (MIT; `net.Listener` wrapper) and [psanford/tlsfingerprint](https://pkg.go.dev/github.com/psanford/tlsfingerprint) (reads ClientHello without consuming it).
- **Precedent:** the self-hosted FCaptcha v1.19.0 computes JA4 natively when the Go server terminates TLS. Go 1.24 is required because older `crypto/tls` did not expose the ClientHello extension list. Behind nginx or Cloudflare it trusts a proxy header. Its release notes admit a Chrome fingerprint was mislabelled as Go's default — [FCaptcha release](https://github.com/WebDecoy/FCaptcha/releases/tag/v1.19.0)
- **Proxy modules:** NGINX ja4-nginx-module, HAProxy plugins (JA4, JA4H), F5 — [FoxIO README](https://github.com/FoxIO-LLC/ja4). Community Caddy modules exist, e.g. [inkress/caddy-ja4](https://github.com/inkress/caddy-ja4) and [lum8rjack/caddy-ja4h](https://github.com/lum8rjack/caddy-ja4h) (found by repo search, maturity not assessed).

**TLS/UA cross-checks in the wild**
- FP-Inconsistent's bots show IP-vs-timezone disagreement: only 56% of requests from one service claiming Europe matched by timezone, against 99.83% by IP — [FP-Inconsistent](https://arxiv.org/html/2406.07647v3)

**Free local IP data**
- [iptoasn](https://iptoasn.com/): IP-to-ASN and country TSVs (v4, v6, combined), hourly updates, public domain (PDDL v1.0).
- [DB-IP IP to ASN Lite](https://db-ip.com/db/download/ip-to-asn-lite): CC BY 4.0, monthly, CSV/MMDB, reduced coverage and accuracy. **Web applications must link back to DB-IP.com on pages that display or use results.**
- Directly downloadable when probed on 2026-11-07 (HTTP 200): [AWS ip-ranges.json](https://ip-ranges.amazonaws.com/ip-ranges.json), [GCP cloud.json](https://www.gstatic.com/ipranges/cloud.json), [Cloudflare ips-v4](https://www.cloudflare.com/ips-v4), [GitHub meta](https://api.github.com/meta), [Tor bulk exit list](https://check.torproject.org/torbulkexitlist).

### Inferences

**Deployment topologies (best to worst for signal fidelity)**
1. **Go app is the TLS endpoint for a dedicated `captcha.example.com`.** Full ClientHello, H2 frames, clean header order. The simplest case: use `tls.Config.GetConfigForClient` with `ClientHelloInfo` `[K]`, plus an H2 framing shim like fingerproxy's, or a listener that peeks at raw bytes.
2. **Customer proxy does layer-4 SNI passthrough to the Go listener**, with PROXY protocol to preserve client IP. Same fidelity. Works with Traefik/HAProxy/nginx `stream`/Caddy L4 `[K]`, and most users can route one hostname this way.
3. **Fingerproxy-style sidecar in front of the app.** Good if the app shouldn't handle TLS. Certificate handling moves to the sidecar.
4. **Proxy module passes a trusted header** (nginx, HAProxy, Caddy). Usually JA4 only. **H2 data is typically absent.** The backend must accept the header only from known proxy IPs; otherwise it can be forged.
5. **CDN in front** (Cloudflare etc.). The handshake is with the CDN, so the origin sees the CDN's fingerprint. Only forwarded values are usable, and Cloudflare's require Enterprise.
6. **Plain L7 proxy with no module.** No TLS or H2 fingerprint at all. Header order may be rewritten too. Must degrade gracefully: mark as `network_signals: unavailable`, not as suspicious.

**Pitfalls**
- Fingerprints belong to the connection, not the request. Attach them via connection context and capture them on the first request of each connection. H2 coalescing means multiple requests share one.
- TLS resumption changes what's visible. Cloudflare skips calculation on resumed sessions; on your own listener the ClientHello is still sent, but with different extensions (`pre_shared_key`) `[K]`. Hash `c` will differ, so learn both variants or disable tickets on this hostname.
- QUIC/HTTP/3 needs separate handling. Simplest option: don't advertise HTTP/3 on the captcha hostname, which also keeps H2 frames observable.
- An H1 fallback from a browser claiming to be modern Chrome is itself suspicious on a direct connection, but normal through corporate TLS-intercepting proxies.
- Corporate MITM proxies, antivirus TLS inspection and some mobile carriers produce a TLS fingerprint that doesn't match the browser. So treat TLS-vs-UA mismatch as strong evidence, **not as sufficient alone**. Sources located did not quantify this.

**How to do TLS vs UA matching**
- Don't maintain a static list of "good" JA4 values by hand; it will go stale with each browser release. Use family-level rules: is `b`/`c` in a learned cluster for claimed brand ± versions?
- Bootstrap with a small seed from test browsers, then update via local rolling statistics.
- A local analogue of Cloudflare's `ja4Signals` is feasible and privacy-friendly: rolling hourly counters per JA4 of distinct IP buckets, UA families claimed, success rates and request volume. A JA4 claiming many unrelated browser families is a strong sign.
- Treat impersonation libraries (curl-impersonate and similar `[K]`) as expected. TLS can be made to match, while H2 and browser JS execution must match too. Cross-layer means TLS + H2 + header order + JS engine together, not any one.

**Licensing recommendation (not legal advice)**
- Ship JA4 (BSD) and the Akamai-style H2 fingerprint by default.
- Do **not** bundle JA4H, JA4T or JA4L in a distributed or commercial product without review. If SweetCaptcha will be sold, hosted or supported commercially, the FoxIO licence likely bites. Internal self-hosting by end users looks permitted, but commercial distribution/support by the project does not. Note "patent-pending" means a home-grown clone of the same method may not be free of risk either.
- A generic own header-order hash is a likely alternative, subject to review.

**IP processing without external sharing**
- Load iptoasn (primary, public domain) plus cloud range lists into an in-memory radix tree or MMDB, refreshed by a sidecar cron job in the Docker stack. Fail open if data is stale, and alert on age.
- Prefer iptoasn over DB-IP Lite where the backlink requirement would be awkward for a widget.
- Use an ASN classification list (hosting vs eyeball) maintained in the project. No free dataset checked here provides this classification directly, so cloud lists cover only major providers.
- Tor exit = **route to a privacy-compatible flow** (PoW or interactive challenge), never block.
- Datacenter ASN is medium-weight. VPN users and corporate egress legitimately appear there. Residential proxies bypass it entirely, so it won't catch sophisticated actors.
- Never call external reputation APIs at request time. Bundled data keeps lookups local and removes a data-transfer issue.

### Gaps
- **Azure** (weekly Service Tags file with changing URL `[K]`) and **Oracle/DigitalOcean/Hetzner/OVH** range sources were not verified. A DigitalOcean geofeed URL returned a redirect only, and I did not follow it.
- MaxMind GeoLite2 current licence terms were not verified.
- No free source of a hosting-vs-eyeball ASN classification was verified.
- No measurement of false-positive rates from TLS inspection or corporate proxies was found, nor of JA4 stability across Chrome releases.
- The licence status of the Akamai method and any H2 patent issues were not found. The white paper is public, but that is not the same as a licence.
- Header-order fingerprinting: Castle's server-side post does *not* cover TLS or header order despite its title, and I found no primary 2023-2026 source on browser header-order behaviour. The technique here is `[K]`.
- The JA4H field layout was not retrievable from the fetched doc; it should be read in full if considered.

---

## Consistency-based classification and hashed, non-persistent signal design

### Takeaway
Cross-signal contradictions are stronger than absolute values, because real devices support only limited configurations. A liar must keep every layer coherent, whereas absolute values are easy to copy and, increasingly, are legitimately normalised. Signals can be evaluated in memory per challenge, with only salted, truncated, short-lived values kept, because consistency needs comparison rather than identification.

### Cited Findings
- FP-Inconsistent rests on the insight that real devices support limited configurations. It flags attribute pairs showing more configurations than expected — [arXiv 2406.07647](https://arxiv.org/abs/2406.07647)
- Results — [v3](https://arxiv.org/html/2406.07647v3):
  - Reduced evasion by 48.11% (DataDome) and 44.95% (BotD).
  - Combined detection rose from 55.44% to 76.88% (DataDome) and from 47.07% to 70.86% (BotD).
  - Spatial rules alone reached 76.04% and 70.33%; temporal alone 56.53% and 48.09%.
  - Rules trained on 80% lost only 0.23% and 0.42% accuracy on the remaining 20%.
- Example inconsistencies — [v3](https://arxiv.org/html/2406.07647v3):
  - 9 of the top 10 evading iPhone screen resolutions don't exist.
  - Device type vs max touch points.
  - IP geolocation vs timezone.
  - Temporal: one cookie with different `navigator.platform` or core counts.
- Real users: 96.84% true negative rate on 2,206 student requests; few false positives, mainly UA spoofers — [v3](https://arxiv.org/html/2406.07647v3). This is a small, non-representative sample.
- Privacy tools — [v3](https://arxiv.org/html/2406.07647v3):
  - Brave not flagged, except temporal false positives where a cookie persisted while `hardwareConcurrency` and `deviceMemory` changed.
  - **All Tor requests were flagged** because of IP vs timezone conflict.
  - Safari, uBlock Origin and AdBlockPlus were not flagged. Testing predates Safari 26.
- Castle's cross-checks: UA Windows vs platform macOS, Apple GPU on Windows, core count over 90, Worker vs main, and a proposed browser-version vs available-API check. It rejects payloads older than 15 minutes and returns a generic 400 to avoid leaking signals — [Castle part 2](https://blog.castle.io/roll-your-own-bot-detection-server-side-detection-part-2/)
- Castle warnings — [part 2](https://blog.castle.io/roll-your-own-bot-detection-server-side-detection-part-2/), [part 1](https://blog.castle.io/roll-your-own-bot-detection-fingerprinting-javascript-part-1/):
  - All client data is untrusted, and a static key in the script can be extracted.
  - Many devices such as iPhones look nearly identical, so static fingerprint thresholds may block real users.
  - Calibrate on real traffic, use a decoupled policy layer with dry-run and staged rollout, log rule matches and measure errors.
- Fingerprinting alone isn't enough: attackers spoof canvas, simulate mouse input and use residential proxies and CAPTCHA farms, so combine with behavioural, proxy and contextual signals — [Castle Playwright](https://blog.castle.io/how-to-detect-headless-chrome-bots-instrumented-with-playwright/)

### Inferences

**Why contradictions beat absolutes**
- Absolute values are public and copyable. Blocklists hit the wrong people (Tor's generic values, Safari's noise).
- Contradiction scales the attacker's cost: each new relation forces coherence across layers (OS ↔ GPU ↔ fonts ↔ voices ↔ TLS ↔ H2 ↔ engine ↔ realm). Rules also keep working when a value is simply unknown.
- The limit: consistency rules catch sloppy spoofing, not real browsers on real devices driven by automation. Those are coherent by definition and need behaviour, rate and cost controls.

**Rule structure**

| Tier | Example | Action |
|---|---|---|
| A: impossible | JS engine ≠ claimed brand (Math/stack format); Worker UA or platform ≠ main; `userAgentData.platform` ≠ `navigator.platform` family; native-API Proxy on `navigator.webdriver`; driver globals | Heavy score; can fail outright if 2+ independent ones fire |
| B: implausible | Apple GPU on Windows UA; TLS family ≠ UA family; H2 fingerprint ≠ browser; iPhone UA with non-existent screen; touch claim vs `pointer: coarse` | Medium score, escalate |
| C: suspicious context | Datacenter ASN; software renderer; default viewport; non-UTC timezone mismatching IP country; header anomalies | Light score |
| D: privacy profile | RFP-coherent (UTC + en-US + 2 cores + rounded window + Gecko engine); known Brave farbling; Safari noise; Tor exit | **No penalty**; route to privacy-compatible challenge |

**False-positive guards**
- UTC timezone never counts as a geo mismatch. This one exemption addresses the Tor false positive found in FP-Inconsistent.
- Group rules by independent evidence so that correlated signals (for example, five rules all derived from a UA switcher) don't add up to a block. One root cause should count once.
- A UA-switcher extension can produce Tier A-looking results. Soft-fail to a harder challenge rather than rejecting.
- Avoid temporal rules across long periods, which would need persistence and break for Brave. Consider only within-challenge or short session comparisons.
- Enforce hard fails only after shadow mode shows acceptable rates per browser family.
- Provide an accessible fallback path, since no scoring path should be a dead end.

**Hashed, non-persistent design**
1. **Challenge-bound collection.** Server issues nonce plus issued-at; the payload is bound to nonce, origin and IP bucket, expires in minutes (Castle: 15), and is one-time-use. Client encryption is only friction, as Castle says.
2. **Evaluate raw values in memory, then drop.** Plausibility rules need coarse categories, so normalise first: `os_family`, `engine`, `gpu_class` (integrated, discrete, software, mobile), `screen_bucket`, `tz_offset_bucket`. Log rule IDs and categories rather than raw strings.
3. **Equality via hashes.** Main/Worker/iframe comparisons only need `HMAC(nonce, value)`. Equality is checkable without ever transmitting the raw value.
4. **Rate-limit buckets.** `HMAC(daily_rotating_salt, coarse_attrs)` truncated (Castle uses 8 hex for canvas). Truncation deliberately adds collisions, so the value works for buckets but not for identification. Destroying the salt at rotation breaks linkability across days.
5. **No client storage and no cross-site identifier.** No cookies or `localStorage` fingerprint, separate salts per tenant/site.
6. **Excluded canvas where noised.** Follow Castle's `IGNORE` approach when noise is detected.
7. **Retention.** Short TTL in Redis or memory; aggregate counters only beyond that.
8. **Minimise.** Don't request high-entropy UA-CH fields, device labels, fonts beyond a tiny list, or anything requiring a permission prompt. Don't send raw canvas or audio data.

### Gaps
- No published study evaluates these rules on 2026 traffic, or after Safari 26 and post-2025 stealth tools. FP-Inconsistent data dates to 2023.
- No empirical evidence was found comparing salted/truncated designs with raw-value detection accuracy. The design above is my proposal.
- Legal treatment (GDPR, ePrivacy consent for device access) was not researched here. Hashing does not automatically make data anonymous, so this needs its own legal review.

---

## Highest-value signals at lowest privacy cost

### Takeaway
Prioritise signals that detect contradictions without identifying a person: engine check, realm consistency, UA-CH vs headers vs TLS, driver artefacts, and native-tamper checks. They are cheap, need no stored identifier, and survive privacy browsers. Avoid canvas, audio and font hashes as identity signals: they have the highest privacy cost and are the most degraded by browser noise.

### Cited Findings
- JA4 groups many similar clients, identifying a client type rather than an individual — [Cloudflare](https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/)
- Worker comparison of UA, platform and brands is rated a strong signal, while languages and core count are weaker — [rebrowser-bot-detector](https://raw.githubusercontent.com/rebrowser/rebrowser-bot-detector/main/README.md)
- Spatial consistency rules did better than temporal rules in FP-Inconsistent, at 76.04% vs 56.53% and 70.33% vs 48.09% — [v3](https://arxiv.org/html/2406.07647v3). Spatial rules need no persistence, so the less privacy-invasive approach also performed better in that study.
- Castle prioritises resilience over uniqueness and stability for bot detection — [Castle part 1](https://blog.castle.io/roll-your-own-bot-detection-fingerprinting-javascript-part-1/)
- Castle's multi-layer stack combines behaviour, environment "red pills", proxy and network detection and time-series analysis — [Castle](https://blog.castle.io/why-a-classic-cdp-bot-detection-signal-suddenly-stopped-working-and-nobody-noticed/)

### Inferences

**Priority order** (judgement; validate in shadow mode)

| Rank | Signal | Value | Privacy cost | Why |
|---|---|---|---|---|
| 1 | Worker and iframe consistency (claims only, equality via HMAC) | High vs JS patching | Very low | No identity; no raw data needed |
| 2 | JS engine vs claimed browser (Math, stack format, `eval.toString`) | High | Very low | Low entropy, hard to fake |
| 3 | UA ↔ UA-CH JS ↔ `Sec-CH-UA` header ↔ platform | High | Low | Already sent by browser |
| 4 | Driver artefacts and `webdriver` positives | High on cheap bots | Very low | Boolean flags only |
| 5 | Native-function tamper checks | High vs JS stealth | Very low | Boolean flags; extension-FP care |
| 6 | JA4 + H2 fingerprint vs claimed family | High vs HTTP clients | Low | Client-type level, passive; infrastructure-dependent |
| 7 | Local ASN class, cloud lists, Tor flag | Medium | Low if evaluated locally and not stored | Context only, no third party |
| 8 | WebGL renderer *class*/limits vs OS | Medium-high | Medium, reduce by bucketing | Software-rendering and GPU/OS contradictions |
| 9 | Coarse screen, touch, pointer media-query checks | Medium | Low | Impossible-device checks |
| 10 | Timezone offset vs IP country (exempt UTC) | Low-medium | Low-medium | Coarse only |
| Avoid or minimise | Canvas/audio hash as identity, full font lists, device labels, high-entropy UA-CH, long-term temporal linking | Declining with noise | High | High uniqueness, volatile, noisy by default in major browsers |

**A minimal v1 set**
- Client: ranks 1-5 plus 8-9, in under ~100 ms total with a hard timeout budget. Canvas only as a noise-status boolean, not stored.
- Server: challenge nonce, header checks, local IP/ASN lookup, and JA4 + H2 when topology allows.
- Outcome: a score and rule IDs, feeding a graded response (invisible pass, PoW, interactive), never an outright block on a single soft signal.
- Pair with non-fingerprint controls, since coherent real-browser automation will pass all of these.

### Gaps
- No source directly ranks signals by detection value against privacy cost; this ranking is my synthesis.
- No field data was found on detection lift per signal for a small self-hosted deployment, which has far less traffic for learning than a CDN. Rolling per-JA4 statistics may be weak at low volume, so bundled seed data and project-shared rule updates may be needed (without sharing user data).
