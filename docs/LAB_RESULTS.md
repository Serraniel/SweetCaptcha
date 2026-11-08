# Lab results

Run on 2026-11-08 against Chromium 156, by `npm run lab` in `lab/`. This file is generated.

These are outcomes against one browser on one machine. They show how the rules behave against each tool, not how often real attacks succeed, and they contain no test with real people. See the limits in the README.

| Scenario | Tier | Outcome | Expected | Reason codes |
|---|---|---|---|---|
| HTTP client naming itself | HTTP client | deny | deny |  |
| HTTP client claiming Chrome, no signals | HTTP client | puzzle | puzzle |  |
| HTTP client with a fully forged signal document | Forged protocol | pass (silent, score 0.97) | pass | `beh_natural_typing` `beh_rich_motion` |
| Same forgery, native TLS: handshake exposes it | Forged protocol | interact | interact |  |
| Stock Playwright, headless | Stock automation | deny | deny |  |
| Automation flag hidden, UA spoofed, agent-style input | Default agent | puzzle | puzzle |  |
| Script patches webdriver and languages | JS-patched stealth | puzzle | puzzle or deny |  |
| Flag hidden, UA spoofed, humanised pointer and typing | Humanised browser | pass (silent, score 0.69) | pass or checkbox-pass | `env_software_gpu` `obs_cdp` |
| Agent waits, then clicks the checkbox directly | Default agent | puzzle | puzzle |  |
| Visitor who does not move, then ticks the checkbox | Humanised browser | checkbox-pass (checkbox, score 0.71) | checkbox-pass | `beh_no_interaction` `env_software_gpu` `obs_cdp` |
| Strict mode: no device reads, storage, or third parties | Privacy | clean | clean |  |
| Audit control: the same audit does find reads on a standard site | Privacy | violation | violation |  |
| Strict mode: all four provider form flows | Compatibility | pass | pass |  |
| Base proof of work: time to token in strict mode, this machine | Mechanics | fast | fast | `median 261 ms` `max 346 ms` |
| reCAPTCHA v3, Turnstile and hCaptcha JavaScript APIs | Compatibility | pass | pass |  |
| Checkbox step, with scrypt proof of work in the browser | Mechanics | pass (checkbox, score 0.79) | pass | `env_software_gpu` `obs_cdp` |
| Puzzle interface, then the wait path | Mechanics | pass (wait, score 0.86) | pass | `env_software_gpu` `obs_cdp` |
| Frame refuses a host not on the allow list | Mechanics | blocked | blocked |  |
| Real browser TLS handshake is not flagged | Mechanics | clean (silent, score 0.69) | clean | `env_software_gpu` `obs_cdp` |
