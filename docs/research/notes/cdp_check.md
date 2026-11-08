# The console-serialization "CDP" check

Tested on 2026-11-08 with Chromium 156 and Firefox on one Linux machine. The outcome closed issue #31.

## The check

The collector logged an `Error` whose `name` property had a getter, using `console.debug`. If something serialized console arguments, the getter ran. Automation that enables the DevTools protocol's `Runtime` domain serializes them, so the getter running was taken as a hint of automation. The 2025 research already noted that DevTools users trigger it as well, and that V8 changes in May 2025 had broken the original variant. It was observed only, with weight 0.

## What the adversarial lab suggested

It fired in every automation tool, including Patchright and rebrowser-playwright, which are built to avoid that leak. That raised the idea of giving it weight.

## The control experiment

Each browser opened the standard demo site three times. The server's `rule_obs_cdp` counter was read before and after.

| Browser | Started how | Runs | Check fired |
|---|---|---|---|
| Chromium 156, headless | Plain process, no automation protocol | 3 | 3 |
| Chromium 156, visible window, no DevTools | Plain process, no automation protocol | 3 | **3** |
| Firefox, headless | Plain process | 3 | 0 |
| Chromium 156, headless | Playwright (control) | 3 | 3 |

## Conclusion

On current Chromium, the getter runs for an ordinary visible window with no DevTools and no automation. Chromium serializes console arguments regardless, so the check separates Chromium from Firefox, not automation from people. Weighting it would have penalized every Chrome visitor. It was removed from the collector and the rule register. The samples are small, but a single ordinary window firing is enough to rule the check out.
