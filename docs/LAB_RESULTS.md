# Lab results

Run on 2026-11-07 against Chromium 156, by `npm run lab` in `lab/`. This file is generated.

These are outcomes against one browser on one machine. They show how the rules behave against each tool, not how often real attacks succeed, and they contain no test with real people. See the limits in the README.

| Scenario | Tier | Outcome | Expected | Reason codes |
|---|---|---|---|---|
| HTTP client naming itself | HTTP client | deny | deny |  |
| HTTP client claiming Chrome, no signals | HTTP client | puzzle | puzzle |  |
| HTTP client with a fully forged signal document | Forged protocol | pass (silent, score 0.97) | pass | `beh_natural_typing` `beh_rich_motion` |
| Same forgery, native TLS: handshake exposes it | Forged protocol | stepup | stepup |  |
| Stock Playwright, headless | Stock automation | deny | deny |  |
| Automation flag hidden, UA spoofed, agent-style input | Default agent | puzzle | puzzle |  |
| Script patches webdriver and languages | JS-patched stealth | puzzle | puzzle or stepup-pass |  |
| Flag hidden, UA spoofed, humanised pointer and typing | Humanised browser | pass (silent, score 0.69) | pass | `env_software_gpu` `obs_cdp` |
| Strict mode: no device reads, storage, or third parties | Privacy | clean | clean |  |
| Audit control: the same audit does find reads on a standard site | Privacy | violation | violation |  |
| Strict mode: all four provider form flows | Compatibility | pass | pass |  |
| reCAPTCHA v3, Turnstile and hCaptcha JavaScript APIs | Compatibility | pass | pass |  |
| Browser scrypt verified by the server | Mechanics | pass (stepup, score 0.91) | pass | `beh_rich_motion` `env_software_gpu` `obs_cdp` |
| Puzzle interface, then the wait path | Mechanics | pass (wait, score 0.86) | pass | `env_software_gpu` `obs_cdp` |
| Frame refuses a host not on the allow list | Mechanics | blocked | blocked |  |
| Real browser TLS handshake is not flagged | Mechanics | clean (silent, score 0.86) | clean | `beh_rich_motion` `env_software_gpu` `obs_cdp` |
