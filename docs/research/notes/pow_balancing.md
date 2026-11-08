# PoW difficulty balancing for SweetCaptcha (as of 2026-11-08)

## Summary
- **Measured (this repo, Ryzen 7 5700X, Node 22/V8):** the SweetCaptcha JS SHA-256 solver (`web/src/shared/sha256.ts`) runs at **1.0 MH/s on one core**. The solver is **single-threaded**: one worker, run in sequence.
- On that rate, **base (15×10 = 328k hashes) takes about 0.33 s on a desktop**, which is about right. **Step-up (18×16 = 4.2M) takes about 4 s on a desktop and about 13 s on a median phone. Wait (21×24 = 50M) takes about 50 s on a desktop and minutes on phones.** Both are far above any peer default.
- Peer defaults cluster at **about 0.3–0.5 s on a desktop and 1–2 s on a median phone at the base level, with harder levels at about 1–4 s on a desktop**. Cap: 1M HashWX hashes, 0.5 s desktop, 1.1–5.9 s phones. mCaptcha: 50k / 3M / 5M. Private Captcha: 0.28 / 1.05 / 4.0 s.
- **PoW does not stop a funded attacker.** Native SHA-256 runs about 11× faster than our JS, and a GPU about 22,000× faster. 1,000 base solves cost about $0.0003 on cloud CPU and about $0.000001 on a GPU. PoW is friction and rate shaping. It pays off only where legitimate volume per user is tiny, such as forms. Spend the difficulty budget on risky clients, not on everyone.
- **Biggest levers, in order:** (1) parallelise the solver across workers (about 3–4× more work for the same wait); (2) use more, smaller sub-puzzles for lower variance; (3) use scrypt (or HashX/HashWX-style) at higher levels to cut the GPU advantage; (4) adapt difficulty in log space from per-IP rate, site-wide rate and risk score; (5) for "wait", rely partly on a server-enforced delay rather than pure CPU.

## Peer products (defaults from source and docs)
| Product | Default work | Adaptation | Source |
|---|---|---|---|
| ALTCHA v1 | SHA-256, `maxnumber` 1e6 (expected about 0.5M hashes, 1 puzzle) | static; v2 adds PBKDF2/scrypt/Argon2id `cost`, `memoryCost`, `parallelism`; solve `timeout` 90 s | [v1/index.ts](https://github.com/altcha-org/altcha-lib/blob/main/src/v1/index.ts), [v2/types.ts](https://github.com/altcha-org/altcha-lib/blob/main/src/v2/types.ts), [algorithms.md](https://github.com/altcha-org/altcha-lib/blob/main/docs/algorithms.md) |
| Cap | HashWX `hashwxDifficulty` 1,000,000 split into `hashwxChallengeCount` 4 (range 50k–5M); legacy SHA-256 50 × 4 hex (16 bits) = 3.3M; `expiresMs` 600,000; workers = cores (or 8) | per site key; `riskFlags` returned "so you can raise the difficulty" | [hashwx.md](https://github.com/tiagozip/cap/blob/main/docs/guide/hashwx.md), [capjs-core.md](https://github.com/tiagozip/cap/blob/main/docs/guide/capjs-core.md), [widget.md](https://github.com/tiagozip/cap/blob/main/docs/guide/widget.md) |
| mCaptcha | `difficulty_factor` = expected hashes: 50,000 ("almost instant"), 3,000,000 ("roughly 1.5 s"), 5,000,000 (">3.5 s") | levels keyed to `visitor_threshold` (avg / peak / "broke my site" traffic), 30 s cooldown window | [default.toml](https://github.com/mCaptcha/mCaptcha/blob/master/config/default.toml), [defense.rs](https://github.com/mCaptcha/libmcaptcha/blob/master/src/defense.rs) |
| Friendly Captcha | blake2b, n solutions at threshold `T=2^((255.999-d)/8)`; dashboard 2–100: "0.29 s" to "14.58 s" on a laptop (vendor) | "Smart Difficulty" on paid plans, using unspecified "additional signals"; client reports solve seconds for tuning | [friendly-pow](https://github.com/FriendlyCaptcha/friendly-pow), [support](https://support.friendlycaptcha.com/en/article/what-is-smart-difficulty-scaling-1vnirl7) |
| Anubis | `DefaultDifficulty = 4` hex zeros (16 bits, about 65k hashes, 1 puzzle); WASM sha256/hashx/argon2id (argon2 crate default 19 MiB, t=2) | request "weight" thresholds: metarefresh → fast 2 → fast 4 → fast 6 | [anubis.go](https://github.com/TecharoHQ/anubis/blob/main/anubis.go), [wasm.mdx](https://github.com/TecharoHQ/anubis/blob/main/docs/docs/admin/configuration/challenges/wasm.mdx) |
| Private Captcha | blake2b, 24 solutions; levels Small 152 / Medium 168 / High 184; each +8 doubles the work; benchmark 0.28 / 1.05 / 4.0 s | leaky buckets per user and per property, log-space model (below); growth slow/medium/fast = 0.5/1/1.5 | [difficulty.go](https://github.com/PrivateCaptcha/PrivateCaptcha/blob/main/pkg/common/difficulty.go), [algorithm.go](https://github.com/PrivateCaptcha/PrivateCaptcha/blob/main/pkg/difficulty/algorithm.go), [verifier.go](https://github.com/PrivateCaptcha/PrivateCaptcha/blob/main/pkg/puzzle/verifier.go) |
| go-away | `js-pow-sha256` difficulty 20 bits (about 1M hashes, 1 puzzle); prefers non-JS challenges first | rule-based | [repo](https://git.gammaspectra.live/git/go-away) |

Private Captcha also rejects solves faster than the benchmarked minimum. This is a cheap check against "solved elsewhere, too fast".

## Hash rates
**Measured here** (Ryzen 7 5700X, 8C/16T; scratch benchmarks, Go 1.x and Node 22):
| Path | SHA-256 | scrypt N=1024,r=8,p=1 |
|---|---|---|
| SweetCaptcha JS, 1 core | 1.0 MH/s | 47 H/s |
| WebCrypto `digest` (async, batched 1k) | 0.07 MH/s (unusable for PoW) | — |
| Node native, per call | 0.29 MH/s (call overhead) | 259 H/s |
| Go native, 1 core | 11.2 MH/s (SHA-NI) | 408 H/s |
| Go native, 16 threads | 89.5 MH/s | 1,844 H/s |

**Reported:**
- RTX 4090, hashcat: SHA-256 **21,976 MH/s**; scrypt (N=16384, r=8) **7,126 H/s** ([gist](https://gist.github.com/Chick3nman/32e662a5bb63bc4f51b847bb422222fd)). Scaled to N=1024 that is about 110k H/s (my linear extrapolation).
- GPU/CPU ratio: SHA-256 about 150×, HashWX about 2× (tevador's CUDA figures, per [Cap](https://github.com/tiagozip/cap/blob/main/docs/guide/hashwx.md)). From my numbers: SHA-256 about 250× per 16-thread CPU, and scrypt-1MiB about 60× (estimate).
- **Device spread** (Cap, HashWX WASM, all cores): M3 Chrome 2,050 KH/s; Galaxy S24 1,238; Pixel 6 746; iPhone 12 620; Redmi Note 11 456; Vivo Y21 316. Median solve times: 0.49 s on desktop, 1.1–2.4 s on mid phones, **5.9 s on the Vivo Y21 (11 s slowest)**. Safari reaches about 70% of Chrome. Cold pages run 24–29% slower than warm ones.
- **Rule of thumb:** low-end Android is about **6–10×** slower than a desktop (about 3× for a median phone). Laurie & Clayton already noted "10 seconds on a 3GHz Pentium … an hour or more on a Palm Pilot", and that memory-bound puzzles narrow the spread to about 4×.
- WASM SHA-256 (no SHA-NI) is probably 1.5–3× faster than our JS. This is unmeasured; mCaptcha's "3M ≈ 1.5 s" claim implies about 2 MH/s. Benchmark it in `lab/` before switching.

## Economics: attacker cost per 1,000 solves (SHA-256)
Assumptions: native 11 MH/s per vCPU at **$0.035/vCPU-h** (Hetzner CCX13 after the June 2026 increase, [spendark](https://spendark.com/instances/ccx13/)); 4090 at 22 GH/s for **$0.34/h** (RunPod community, [amcompute](https://www.amcompute.com/gpu-cloud-prices/rtx-4090)).
| Work per solve | CPU $ / 1k | GPU $ / 1k |
|---|---|---|
| 328k (current base) | 0.0003 | 0.0000014 |
| 1.05M | 0.0009 | 0.0000045 |
| 4.2M (current step-up) | 0.0037 | 0.000018 |
| 50M (current wait) | 0.044 | 0.00022 |
| scrypt 128 hashes (proposed wait) | 0.0003 | 0.000004 (estimate) |

- [Ormandy](https://lock.cmpxchg8b.com/anubis.html): the Anubis default takes **0.017 s** with a native C solver. Tokens for all 11,508 "deployments" take about 6 minutes, so the "cost … is approximately $0". A low-authority source reports that scrapers were solving Codeberg's Anubis by August 2025 ([wiki](https://github.com/feder-cr/invisible_playwright/wiki/anubis-proof-of-work-explained)).
- [Laurie & Clayton 2004](https://www.cl.cam.ac.uk/~rnc1/proofwork2.pdf): stopping spam needs **346 s per message** once botnets are counted. The headroom between legitimate and abusive volume is only 4–8×, so hourly limits would hit **5–13% of legitimate users**.
- Cap's case for HashWX ([hashwx.md](https://github.com/tiagozip/cap/blob/main/docs/guide/hashwx.md)): what matters is "challenges an attacker clears per hour". RSW time-lock puzzles failed because GPUs run many puzzles side by side. HashWX generates a fresh function per nonce block, which leaves a GPU about 2× faster than a CPU instead of about 150×. Even so, it does not stop paid humans, so pair it with signals.
- **Takeaway:** PoW makes bulk abuse cost something only for unsophisticated or browser-bound bots. Its real value is forcing a real JS runtime, rate shaping, and binding single-use, short-expiry tokens. Do not raise base difficulty hoping to deter; target risky traffic instead.

## Design guidance
- **Variance:** with c sub-puzzles of b bits, the coefficient of variation is about 1/√c for SHA-256, and √((1−2⁻ᵇ)/c) for low-bit memory-hard puzzles. At c=10 it is 32%; at c=32–48 it is 14–18%. Cap's numbers: 1 puzzle gives p90 1,447 ms against 778 ms for 4 sub-puzzles at the same median. Smaller sub-puzzles also give a smooth progress bar.
- **Multithreading:** split sub-puzzle indices across a **fixed 4 workers** (i mod 4). `worker.ts` must not read device properties, and a fixed count avoids reading `hardwareConcurrency`. Oversubscribing a 2-core device costs little. Expect about 3–4× more throughput.
- **Fixed vs time-based:** never trust a client benchmark. Keep server-chosen work, but calibrate it from client-reported solve times where privacy allows (Friendly diagnostics; Private Captcha minimum-time check). Sequential time-lock puzzles do not help (Cap deprecated RSW).
- **"Wait" level:** prefer a modest PoW plus a server-enforced `notBefore` (token valid only after X s). That costs the attacker concurrency and wall time equally on every device, rather than punishing slow phones.
- **Memory-hard functions:** our scrypt uses 1 MiB, so it is GPU-resistant only by about 10× relative to SHA-256. Argon2id WASM: argon2-browser reports 1 MiB × 100 passes in 119–225 ms on desktop ([repo](https://github.com/antelle/argon2-browser)), which puts 19 MiB/t=2 at about 45–85 ms per hash on desktop and about 0.2–0.7 s on phones (estimate). That allows only a few hashes per solve. Use 1–2 workers to stay under about 40 MiB on 2 GB phones.
- **UX:** start the solve on page load or first form focus so it finishes before submit. Use a determinate progress bar (`role="progressbar"`, `aria-live="polite"` status, respect `prefers-reduced-motion`). Never time out the human (WCAG 2.2.1); Cap uses a 10 min expiry and ALTCHA a 90 s solve timeout. Prefetch the challenge. Energy: about 1 s at about 3 W on a phone is about 3 J, under 0.01% of a 15 Wh battery (estimate). Avoid repeat solves by reusing tokens for the session.

## Recommendation
**Defaults for today's single-threaded JS solver** (times use 1.0 / 0.33 / 0.12 MH/s for desktop / median phone / low-end):
| Level | SHA-256 bits × count | Expected hashes | Desktop | Median phone | Low-end | scrypt alternative |
|---|---|---|---|---|---|---|
| base | **13 × 40** | 328k (same work, CV 16%) | 0.33 s | 1.0 s | 2.7 s | 1 × 8 (16 h, 0.34 s desktop) |
| elevated | **15 × 32** | 1.05M | 1.0 s | 3.2 s | 8.7 s | 2 × 12 (48 h, 1.0 s) |
| wait | **16 × 48** | 3.1M, plus `notBefore` 5–10 s | 3.1 s | 9.5 s | 26 s | 3 × 16 (128 h, 2.7 s) |

**After the 4-worker solver** (about 3× effective on phones): base **14 × 48** (786k), elevated **16 × 48** (3.1M), wait **18 × 48** (12.6M). These give the same target times and match mCaptcha and Cap SHA-256 scales. Use scrypt (or HashWX/HashX via WASM) at elevated and wait.

**Adaptive formula** (log-space, after Private Captcha):
```
Δ = min(Δmax, g·[ log2(1 + u/8) + log2(1 + max(0, s − ŝ)/(4·ŝ) + v) ] + 2·risk)
W = W_base · 2^Δ ;  bits = clamp(round(log2(W/40)), 10, 22) ;  count = clamp(round(W / 2^bits), 16, 64)
```
- u = per-client leaky bucket (IPv4 /32 or /24, IPv6 /56): challenges above a leak of 1 per 30 s.
- s = site challenge rate per minute, with ŝ an EWMA baseline floored at about 15 per minute.
- v = min(max(issued/verified, verified/issued), 8) − 1.
- risk ∈ [0, 1] from SweetCaptcha's signal score; g ∈ {0.5, 1, 1.5}; Δmax = 4 (16×, enough to reach wait from base).
- Alternatively snap to levels: Δ<1 → base, 1≤Δ<3 → elevated, otherwise wait. Use a 30 s cooldown and hysteresis.

**Target median solve time (warm, solve only):**
| Device class | base | elevated | wait (hard ceiling) |
|---|---|---|---|
| Desktop or laptop | ≤ 0.35 s | ≈ 1 s | ≈ 3–4 s |
| Median phone (Pixel 6, iPhone 12, Redmi Note 11) | ≤ 1 s | ≈ 3 s | ≈ 10 s |
| Low-end Android (Helio P35 class) | ≤ 3 s | ≤ 10 s | ≤ 30 s |

Check targets at **p90 on real low-end phones** in `lab/` with cold pages and Safari, and re-tune from client-reported solve-time telemetry.
