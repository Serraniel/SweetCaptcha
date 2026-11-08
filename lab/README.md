# Lab

These scripts run the real binary against real Chromium. None involves real people, so none says anything about false positives on people.

| Script | Purpose | Fails on |
|---|---|---|
| `npm run lab` | Regression suite: one scenario per attacker tier and mechanism, with expected outcomes. Runs in CI on every change. | Any outcome that differs from the expectation |
| `npm run bench` | Proof-of-work solve times: the browser widget against a native solver, per level. Writes `docs/BENCHMARKS.md` with `LAB_REPORT`. | Never; it measures |
| `npm run adversarial` | Maintained evasion tools (Patchright, rebrowser-playwright, puppeteer-extra stealth) with agent-style and humanised input. Runs weekly in CI. | Only a crash: outcomes are reported, not asserted |

Set `LAB_CHROMIUM` to a Chromium binary, or install one with `npx playwright-core install chromium`. Set `LAB_REPORT` to write the results somewhere other than `out/`.

## Testing with AI agents

AI browser agents need a model API key and cost money per run, so they are not automated here. To test one by hand:

1. Start the lab server: `go run ./cmd/sweetcaptcha serve --config lab/config.yaml` from the repository root.
2. Point the agent at `http://localhost:18080/demo/?k=lab_standard` with a task such as "Enter a name and send the form".
3. Read the outcome on the result page: `via` and `reasons` show how it was judged.

Record the agent, model, version and date with the result. Agents change quickly, so results without a date are not worth keeping.

## Compatibility matrix

Setups where real people are most often locked out. Automated rows run in `npm run lab`; manual rows need a person, and each needs a date and a result.

| Setup | How it is tested | Expected | Last result |
|---|---|---|---|
| Chromium with JIT disabled | Automated | Pass, or checkbox then pass | Passes |
| User-agent switcher (Chromium claiming Firefox) | Automated | A task; the help page advises turning the switcher off | Task |
| Firefox desktop, default settings | Manual | Pass | Verified by the project owner on 2026-11-07 |
| Firefox with `privacy.resistFingerprinting` | Manual | Pass or checkbox | Not tested yet |
| Tor Browser | Manual | Checkbox or task, never a denial | Not tested yet |
| Brave with shields up | Manual | Pass or checkbox | Not tested yet |
| Safari on iOS | Manual | Pass | Not tested yet |
| Anti-fingerprinting extensions (JShelter, CanvasBlocker) | Manual | Pass or checkbox | Not tested yet |
| Keyboard only | Manual | Pass, or checkbox by keyboard | Not tested yet |
| Screen reader (NVDA, VoiceOver) | Manual | Pass, or the wait path | Not tested yet |
| Older or niche browsers (Pale Moon, 32-bit builds) | Manual | Pass or checkbox | Not tested yet |

Visitors who get stuck see a Help link in the widget's error states. It leads to `/v1/help`, which gives practical steps in English or German, without describing what the detection looks at.

## Testing with people

No script can stand in for this. Before enforcing, run a site in shadow mode, and test with keyboard-only navigation, a screen reader, voice control, a VPN, Tor, and the slowest phone you can find.
