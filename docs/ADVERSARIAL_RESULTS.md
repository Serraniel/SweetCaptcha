# Adversarial results

Run on 2026-11-08 by `npm run adversarial` in `lab/`. This file is generated.

Maintained evasion tools against the standard site, headless on one machine, with a spoofed user agent. These are observations, not expectations: the tools change often. "Pass" means the tool got a token without a task.

| Tool and input | Tier | Outcome | Reason codes |
|---|---|---|---|
| Patchright, agent-style input | Maintained stealth fork | puzzle |  |
| rebrowser-playwright, agent-style input | Maintained stealth fork | puzzle |  |
| puppeteer-extra stealth, agent-style input | Classic stealth plugin | puzzle |  |
| Patchright, humanised input | Maintained stealth fork | pass (silent, score 0.69) | `env_software_gpu` `obs_cdp` |
| rebrowser-playwright, humanised input | Maintained stealth fork | pass (silent, score 0.69) | `env_software_gpu` `obs_cdp` |
| puppeteer-extra stealth, humanised input | Classic stealth plugin | puzzle |  |
