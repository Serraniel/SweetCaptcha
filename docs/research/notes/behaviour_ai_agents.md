# Behavioural biometrics signals and the AI-agent threat for CAPTCHA design

Evidence caveat for the report writer: almost all 2025-2026 agent numbers come from preprints, vendor blogs, or the authors of the challenge being evaluated. I found no independent replication of any of them. Thresholds and weights in this file are my own unvalidated proposals. They appear only under "Inferences".

## Mouse dynamics: which features discriminate, on which datasets, and how well generative trajectories defeat them

### Takeaway
Against classic scripted bots, single-trajectory kinematic classifiers report 93-99% in lab conditions. Today's LLM agents mostly fail earlier, because they produce almost no pointer movement at all. The primary mouse signal is therefore "a click with no approach path", and fine kinematics are a second layer that matters only against humanised cursors.

### Cited Findings
**Lab accuracy against synthetic trajectories**
- BeCAPTCHA-Mouse (Acien et al., Pattern Recognition 2022) reports about 93% average accuracy on high-realism bot trajectories from one trajectory, and a relative gain above 36% when fused with existing mouse features — [arXiv abstract](https://arxiv.org/abs/2005.00890).
- Features: 37 neuromotor (Sigma-Lognormal) and 66 global (duration, distance, displacement, angle, velocity, move efficiency). Random Forest performed best, ahead of SVM, KNN, MLP, LSTM and GRU; recurrent models on raw coordinates needed about 2,000 samples to match them — [full text](https://ar5iv.labs.arxiv.org/html/2005.00890).
- Per-attack results (Random Forest, one trajectory, 70/30 split repeated 5 times, 200 Hz sampling, about 55K human trajectories from 58 users, about 10K synthetic): neuromotor 95.2-99.3%, global 95.3-99.8%, combined 98.0-99.9%. GAN samples reached 96.9% on one trajectory. Logarithmic shapes were weakest, the acceleration-plus-final-deceleration velocity profile fooled the classifier up to 17% of the time, and shorter trajectories were harder — [full text](https://ar5iv.labs.arxiv.org/html/2005.00890).
- Internal inconsistency: the abstract's 93% and about 15,000-trajectory benchmark do not match the body's table values and sample counts — [abstract](https://arxiv.org/abs/2005.00890) vs [full text](https://ar5iv.labs.arxiv.org/html/2005.00890). Cite "93-99%, lab only".

**Generative mouse tools**
- SapiAgent (Antal, Buza, Fejer, IEEE Access 2021) generates trajectories with deep autoencoders, trained on SapiMouse (120 subjects), and is reported as more realistic than Bezier curves and conventional autoencoders — [record](https://libmast.utm.my/Record/doaj.art-e6857df127af459a9d7def2db945fbf3). The repository includes Bezier baselines and PyOD anomaly-detector evaluation — [GitHub](https://github.com/margitantal68/sapiagent).
- A follow-up found Local Outlier Factor the best anomaly detector and convolutional-autoencoder trajectories the most human-like. I saw no AUC values in the text I retrieved — [Kovacs and Antal](https://ojs.emt.ro/enelko-szamokt/article/view/1014).
- ghost-cursor uses Bezier paths with randomised control points, Fitts's-law point counts, overshoot and readjustment beyond a distance threshold, and random in-element click points — [README](https://raw.githubusercontent.com/Xetera/ghost-cursor/master/README.md).

**Datasets**
- Balabit (2016) has cursor position and timing for 10 users and was built for user authentication, not bot detection. SapiMouse is described as usable for both authentication and bot detection. DFL appeared in my results only as a transfer-learning set — [search snippet, exact page attribution unverified](https://arxiv.org/pdf/2312.10273); [SapiMouse](https://ieeexplore.ieee.org/document/9465583/).
- ReMouse (Sadeghpour and Vlajic, 2023) has 100 users with repeat sessions and targets session-replay bots — [DOAJ record](https://doaj.org/article/7ad2dc9734db4662afd4ec66e5040055).

**Real LLM agents**
- FP-Agent: all seven tested agents emitted a single mousemove followed by mousedown and mouseup at the click point, so the cursor effectively teleports. The paper used curvature, direction and a 250 ms idle threshold as resolution-agnostic features — [FP-Agent](https://arxiv.org/html/2605.01247v1).
- Akamai telemetry for Comet, Atlas and the Claude Chrome extension: 63.2% of agentic requests had 0 mouse events, 35.8% were below the evaluation minimum, and 1.0% were evaluable. Its existing mouse model flagged under 1% of agentic requests, mainly because it could not run on sparse sessions — [Akamai, 2026-08-19](https://www.akamai.com/blog/security-research/identifying-agentic-automation-behavioral-telemetry).
- Akamai's sequence model on sparse events (2,190 agentic sequences, about 85 human sessions per agentic session) reached ROC-AUC 0.981 and PR-AUC 0.661, proof of concept only — [Akamai](https://www.akamai.com/blog/security-research/identifying-agentic-automation-behavioral-telemetry).

**isTrusted and coalesced events**
- Mouse events from CDP `Input.dispatchMouseEvent` enter the browser's input pipeline and report `isTrusted: true`, so isTrusted catches only script-dispatched events — [Clearcote](https://www.clearcotelabs.com/audit/checks/event-istrusted-provenance); [Browser4 PR](https://github.com/platonai/Browser4/pull/600).
- One blog claims CDP mouse input yields empty or trivial `getCoalescedEvents()` lists. I found no Chromium documentation or independent test — [Crawlex, unverified](https://blog.crawlex.net/blog/synthesizing-human-input-events/).

### Inferences
- Order mouse features by evidence and cost: (1) untrusted events, (2) click without approach path, (3) timing regularity and pause structure, (4) kinematics (speed profile, curvature, jerk, overshoot, Fitts's-law fit). Layer 4 needs enough movement to compute, which Akamai shows real agents rarely supply.
- A kinematic model cannot be the sole gate: Akamai's model passed agents because it had too little data to run. A "not enough data" result must feed the score, not pass silently.
- Agent frameworks could adopt ghost-cursor-style movement with little effort, so the teleport signal should be treated as perishable. Its durability is unmeasured.
- BeCAPTCHA data was sampled at 200 Hz from a controlled 8-button task. Web event rates and free-form use differ, so lab accuracy should not be quoted as field performance.

### Gaps
- I found no measured evaluation of ghost-cursor or HumanCursor against any published detector, and I retrieved no source on HumanCursor at all. Their defeat rate is unknown.
- I did not retrieve SapiAgent's or Kovacs and Antal's numeric AUCs, because the primary pages were blocked or lacked the figures.
- I found no study isolating jerk, Fitts's-law conformity or overshoot as individual discriminators in web conditions.
- Coalesced-event behaviour under CDP is unverified. It can be tested directly with a local page and a CDP-driven browser before relying on it.

## Keyboard, touch, scroll, sensors and focus; false-positive risk and accessibility obligations

### Takeaway
Keystroke and scroll signals separate current agents very well, but touch, sensor and focus evidence for agents is thin. Keyboard-only, screen-reader and motor-impaired users overlap with agent-like signals (no pointer path, odd click properties), so behaviour must never be a sole denial reason, and a non-behavioural path is required.

### Cited Findings
**Keyboard and scroll artefacts (agent-specific; 1,000 trials per agent)**
- Browser Use: 5.31 ms inter-key, 10.19 ms hold, about double the change events from clearing fields. Manus: about 1.39 ms inter-key, 52.92 ms hold, instant scroll-into-view, delete before fill. Claude: fills via change events by default; keystroke mode has latencies below 1 ms. ChatGPT Agent: about 66.58 ms hold, Ctrl+V even when reporting MacIntel, larger scroll distance and duration. Skyvern: programmatic fill except the last 20 characters at 10 ms intervals. Atlas and Comet: paste events — [FP-Agent](https://arxiv.org/html/2605.01247v1).
- A vendor describes human scrolling as short bursts with a natural velocity profile and scripted scrolling as flat or step-function velocity, without published thresholds — [cside, vendor claim](https://cside.com/blog/catching-ai-agents-behavioral-signals).

**Touch and sensors**
- BeCAPTCHA (touch) decides human versus bot from one drag-and-drop using touchscreen and accelerometer data, tested against GAN and handcrafted fakes. HuMIdb has 14 sensors and 600 users. The abstract gives no accuracy figure — [arXiv](https://arxiv.org/abs/2005.13655).

**WCAG obligations**
- SC 3.3.8 (AA): no cognitive function test in any authentication step unless there is an alternative, an assistive mechanism, object recognition, or personal content. A cognitive function test means remembering, manipulating or transcribing information, and puzzles are listed. Visual logic puzzles and math CAPTCHAs are not excepted, and transcribing audio CAPTCHAs cannot serve as the alternative — [W3C Understanding 3.3.8](https://www.w3.org/WAI/WCAG22/Understanding/accessible-authentication.html).
- The criterion applies even when a CAPTCHA is only triggered in some scenarios. It focuses on authenticating existing users, though the page's boundary around registration is not fully clear — [W3C Understanding 3.3.8](https://www.w3.org/WAI/WCAG22/Understanding/accessible-authentication.html).
- SC 2.2.1 (A) requires a time limit to be removable, adjustable to at least 10x, or extendable (20-second warning, at least 10 extensions), unless real-time, essential or over 20 hours. "Essential" is narrow — [W3C 2.2.1](https://www.w3.org/WAI/WCAG22/Understanding/timing-adjustable.html).
- SC 2.1.1 (A) requires keyboard operation without specific keystroke timings, except for input depending on the path of movement. Dragging to a location where the route does not matter is not path-dependent — [W3C 2.1.1](https://www.w3.org/WAI/WCAG22/Understanding/keyboard.html).
- SC 2.5.7 (AA) requires dragging functionality to be achievable by a single pointer without dragging, unless essential — [W3C 2.5.7](https://www.w3.org/WAI/WCAG22/Understanding/dragging-movements.html).
- The W3C note on CAPTCHA inaccessibility (2021 draft) welcomes non-interactive checks because they pose no accessibility challenge, warns of privacy exposure including disability disclosure, and says ambiguous-score fallbacks can reintroduce barriers. It recommends the least intrusive check, a variety of challenge types, and options such as WebAuthn attestation or Privacy Pass — [W3C Note](https://www.w3.org/TR/turingtest/).

**Assistive-technology false positives**
- Screen readers can send synthetic mouse events. Angular CDK treats `buttons === 0` or `detail === 0` as possibly fake, with Chrome and Firefox differing. NVDA reports show `detail` 0 from keyboard activation, and script `element.click()` also gives 0 — [Angular CDK](https://app.unpkg.com/@angular/cdk@21.2.4/files/fesm2022/_fake-event-detection-chunk.mjs.map); [Stack Overflow mirror](https://kiwix.lema.org/stackoverflow.com_en_all_2023-11/questions/52914854/distinguish-the-keypress-and-click-in-mozilla-when-nvda-is-on); [WPT](https://searchfox.org/firefox-main/source/testing/web-platform/tests/uievents/interface/click-event.htm).
- Reader modes, accessibility extensions and capture tools can expose hidden honeypots, and behavioural tracking may disadvantage assistive-technology users — [Rilla et al.](https://arxiv.org/html/2508.01390).

### Inferences
- Treat "keyboard-only" as a valid mode: Tab-order focus transitions with keydown-originated activation are consistent with a keyboard user. Score those sessions by other signals, not by missing pointer data.
- Sustained sub-15 ms inter-key intervals are a strong signal (proposal, not a validated threshold). A single paste is not, since password managers and autofill also skip keystrokes.
- A pure behavioural check involves no cognitive test, so it should not engage SC 3.3.8. The obligations arrive at the fallback challenge, which needs a compliant path when used in authentication.
- Tremor, slow movement and switch or eye-tracking input can resemble "abnormal" kinematics, so kinematic outliers should escalate to a gentler check, never to an outright block.

### Gaps
- I found no measured false-positive rates for keyboard-only, screen-reader, switch, eye-tracking or tremor users on any behavioural classifier. This is the largest gap, and SweetCaptcha would need its own testing with disabled users.
- I found no 2023-2026 evidence on touch force, radius or tilt, or on device-motion and focus/visibility patterns, for human-versus-agent discrimination. HuMIdb accuracy figures were not retrieved.
- I did not research jurisdiction-specific law (for example EAA or ADA) on CAPTCHA obligations.

## How AI agents operate, which artefacts they produce, and what detection research exists

### Takeaway
Agents run an observe-decide-act loop through CDP, extensions or OS-level input. This yields teleporting clicks, burst typing or paste, and irregular multi-second pauses. Passive detection works well in closed-world tests today, but it degrades on unseen tasks and agents, and signed identity solves only the cooperative case.

### Cited Findings
**Operating model**
- Anthropic computer use is a client-executed loop: the model returns actions (screenshot, click, `mouse_move`, `left_click_drag`, type, scroll, wait), the application runs them and returns results. Multiple actions can be batched in a turn, and the docs suggest about 0.5 s delay after actions — [Anthropic docs](https://platform.claude.com/docs/en/agents-and-tools/tool-use/computer-use-tool).
- Stagehand drives the browser over CDP, with `act`, `extract` and `observe` primitives — [Stagehand docs](https://docs.stagehand.dev/).
- Browser Use types through CDP `Input.dispatchKeyEvent`. FP-Agent infers vision versus DOM execution from scroll patterns only — [FP-Agent](https://arxiv.org/html/2605.01247v1).
- Vendor-reported latency: screenshot agents 2-5 s or 2-7 s per action, DOM agents under 500 ms or 20-100 ms — [rtrvr](https://rtrvr.ai/rover/blog/dom-native-vs-screenshot-agents); [DEV post](https://dev.to/m13v/how-ai-agents-actually-see-your-screen-dom-control-vs-screenshots-explained-41). These sources have a commercial stake and are not measured benchmarks.

**Per-agent fingerprints**
- Operator (2025): looked like headful Chrome with no `navigator.webdriver` or CDP artefacts, one platform mismatch between main thread and worker, and signed headers. Browserbase: `window.playwright__binding`, UTC timezone, CDP leak. Skyvern: claimed Edge on Ubuntu, SwiftShader renderer, residential or ISP proxies. Comet: no identifying headers, content-script and injected-button side effects, clicks without mousemove — [Castle, 2025-08-05](https://blog.castle.io/from-detection-to-trust-the-evolving-challenge-of-ai-bot-authentication/).
- Local agents can switch from human to automated mid-session on the same browser, which complicates intent judgement — [Castle](https://blog.castle.io/from-detection-to-trust-the-evolving-challenge-of-ai-bot-authentication/).
- Agents' pauses are long and irregular, sometimes several seconds between clicks — [Akamai](https://www.akamai.com/blog/security-research/identifying-agentic-automation-behavioral-telemetry).

**Detection research**
- FP-Agent: 7 agents (Atlas, Claude for Chrome, Comet, ChatGPT Agent, Manus, Browser Use 0.9.2, Skyvern 0.2.23; Mariner excluded), 1,000 trials each, 56 undergraduates, 3 honey-site tasks, XGBoost, 80/20 split. Behavioural F1 0.9994 (50 features), browser fingerprint F1 0.8223 (418 features), combined 1.0000 — [FP-Agent](https://arxiv.org/html/2605.01247v1).
- FP-Agent limits: closed-world; the same multi-class model covers human and attribution with no binary score; 546 reported human instances versus 504 expected; no evasion experiments; agents "do not actively evade detection out of the box". On a held-out task, behavioural-only F1 fell to about 0.63-0.80 and combined stayed about 0.93-0.97. Behavioural F1 plateaued after about 3 minutes and combined after about 1 minute. Cloudflare's free tier fully blocked only Manus — [FP-Agent](https://arxiv.org/html/2605.01247v1).
- Known By Their Actions (Oxford, May 2026): 14 LLMs on one Midscene.js vision harness, 1,050 task instances across 4 web environments, up to 96% F1 for model attribution (given the client is already known to be an agent). Timing dominates: click inter-event mean and first-action latency. Open-set AUROC is mostly above 0.60, best 0.84, with Seed-2-lite below chance on three of four sets — [arXiv 2605.14786](https://arxiv.org/pdf/2605.14786).
- Injected uniform delays cut unadapted macro-F1 from about 0.8 to about 0.2-0.3 at 5 s, while retraining recovers about 0.67-0.7 using click dispersion, key ratios and link-click ratio (values read from Figure 5, approximate). Macro-F1 rises sharply within the first 40% of actions — [arXiv 2605.14786](https://arxiv.org/pdf/2605.14786).
- Vendor claims: cside reports 98.2% recall on raw Playwright, 100% on stealth Browserless and under 1% false positives, with no sample sizes or versions — [cside](https://cside.com/blog/catching-ai-agents-behavioral-signals). DataDome says simple bot signals miss agentic browsers and reports 17.7 billion agent requests in Q2 2026 (from a search snippet of a DataDome page; I did not open the primary page, and the methodology is not shown) — [DataDome report](https://datadome.co/threat-research/ai-traffic-report/); [Q2 roundup](https://datadome.co/changelog/datadome-product-roundup-q2-2026/).

**Signed agents**
- Web Bot Auth profiles RFC 9421. Requests carry `Signature-Input`, `Signature` and `Signature-Agent`, with `tag="web-bot-auth"`, an Ed25519 JWK-thumbprint `keyid`, `created` and `expires`, covering at least `@authority`. Keys live at `/.well-known/http-message-signatures-directory`. `nonce` is recommended but not validated by Cloudflare — [Cloudflare docs](https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth).
- First signed-agent cohort: ChatGPT agent, Goose, Browserbase, Anchor Browser — [Cloudflare, 2025-08-28](https://blog.cloudflare.com/signed-agents/).
- The IETF webbotauth charter excludes bot intents, reputation tracking and detection of non-participating bots. Its milestones targeted IESG submission in April and August 2026, but I did not confirm whether these were met — [IETF](https://datatracker.ietf.org/wg/webbotauth/about/).
- A signature tells who, not why, and OpenAI was the only tested agent supporting it in August 2025 — [Castle](https://blog.castle.io/from-detection-to-trust-the-evolving-challenge-of-ai-bot-authentication/).

**Honeypots and prompt-injection canaries**
- Reworr et al. paired prompt-injection tests with a response window of about 1.5 s on a terminal honeypot: 7 potential agents and 1 confirmed in the wild. This is not a browser setting — [arXiv 2410.13919](https://arxiv.org/abs/2410.13919); [Apart summary](https://apartresearch.com/news/ai-hackers-in-the-wild-llm-agent-honeypot).
- Rilla et al. catalogue form traps (1px text, negative z-index, off-screen, hidden checkbox, injected canaries). They advise against `opacity: 0`, note that advanced pipelines filter suspicious styling, and say results should be probabilistic filters. Their "hazelnut" illustration (1.6% tripped) is a case study they say is not new empirical data — [Rilla et al.](https://arxiv.org/html/2508.01390).

### Inferences
- Treat signed agents as a separate policy class: verify, then apply site policy. A valid signature should not count as "human", and its absence should not count as "bot".
- Layered hidden traps are cheap and worth a modest weight, with their results kept probabilistic. Use only benign canaries (for example, a harmless token) and never instructions that would harm or manipulate a user's agent.
- Timing randomisation is an obvious agent countermeasure, and the Oxford result suggests action-structure features should be kept alongside timing. Its attribution setting does not directly measure human-versus-agent separation.
- Model-attribution fingerprinting has limited value for a CAPTCHA, and the Oxford authors frame it as an attack surface. SweetCaptcha needs only human/automation, so it should avoid retaining per-model fingerprints.

### Gaps
- I retrieved no primary documentation on Google Mariner, Skyvern's or browser-use's perception pipelines, or OpenAI's current product behaviour. Akamai says Atlas was discontinued after its research, which I did not independently confirm — [Akamai](https://www.akamai.com/blog/security-research/identifying-agentic-automation-behavioral-telemetry).
- I found no measured study of browser agents interacting with hidden DOM elements, or of accessibility-snapshot use as a detectable signal.
- HUMAN's traffic figures were available only via secondary coverage, so I omit them. Akamai's announced part two (request- and session-level metrics) was not retrieved.

## Which challenges resist LLM agents, and is a time-pressured interactive challenge viable and accessible

### Takeaway
Static recognition and logic puzzles are largely broken, while interactive, multi-step, perception-to-action tasks still hold in published benchmarks (single digits to about 40% for the best agents). Those margins are fragile and the most resistant puzzle families are the least accessible, so a challenge should be an escalation step rather than the core defence. Hard time pressure conflicts with WCAG 2.2.1 and is a poor primary design.

### Cited Findings
| Challenge / study | Best machine | Humans | Conditions |
|---|---|---|---|
| Halligan, generalised visual solver ([USENIX Sec 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/teoh)) | 60.7%; 70.6% on unseen in-the-wild challenges | not stated in abstract | 2,600 challenges, 26 types; 30-day in-the-wild run |
| Logic families "Select Animal", "Bingo" ([Next-Gen](https://arxiv.org/html/2602.09012v1)) | 100%; 80-90% | - | Gemini-3-Pro, GPT-5.2; reported from prior work |
| Open CaptchaWorld, interactive ([arXiv 2505.24878](https://arxiv.org/abs/2505.24878)) | 40.0% (Browser-Use, o3) | 93.3% | 20 types, 225 puzzles |
| Spatial CAPTCHA ([arXiv 2510.03863](https://arxiv.org/abs/2510.03863)) | 31.0% Pass@1 | "vastly outperform", no figure retrieved | 10 models |
| IllusionCAPTCHA ([arXiv 2502.05461](https://arxiv.org/abs/2502.05461)) | 100% deception, i.e. about 0% | 86.95% first attempt | sample sizes not in abstract; models reported as GPT-4o and Gemini generation ([review](https://www.themoonlight.io/review/illusioncaptcha-a-captcha-based-on-visual-illusion)) |
| Next-Gen CAPTCHAs ([arXiv 2602.09012](https://arxiv.org/html/2602.09012v1)) | 5.9% Pass@1 (GPT-5.2 xHigh) | 98.8%, about 31 s per puzzle | 27 families, 519 puzzles; GPT-5.2 and Claude on a 135-puzzle subset; human N not stated |

- Next-Gen per-family peaks: Static_Jigsaw 60% (Claude Opus 4.5), Color_Counting 40% (GPT-5.2), Red_Dot 20%, Mirror 18.2%, most others near 0%. Framework matters: on the same model, CrewAI 0%, Browser-Use 1.48%, Claude Cowork 4.44% — [Next-Gen](https://arxiv.org/html/2602.09012v1).
- Next-Gen design principles: interactive grounding, correct action primitive, non-local dependence between actions, informative non-leaking feedback, human-feasible effort. Gap categories include temporal integration, latent-state tracking and perception-to-action alignment — [Next-Gen](https://arxiv.org/html/2602.09012v1).
- Next-Gen reports total cost of $3,122.3 for GPT-5.2 xHigh, $224 for Claude Opus 4.5 and $6.5 for Gemini-3 Flash; high-reasoning models take about 16-77 minutes on complex puzzles. It raises dual-use concerns and reports no accessibility testing — [Next-Gen](https://arxiv.org/html/2602.09012v1).
- Audio: a W3C note cites 90% solver success against audio reCAPTCHA (dated evidence) and describes audio barriers, including for deaf-blind users — [W3C Note](https://www.w3.org/TR/turingtest/).
- Halligan's authors suggest puzzle-less anti-bot alternatives — [USENIX](https://www.usenix.org/conference/usenixsecurity25/presentation/teoh).

### Inferences
- Approximate cost per successful solve, assuming costs divide evenly over the puzzles run: GPT-5.2 about $23 per puzzle and about $390 per success; Claude about $1.66 and $55; Gemini-3 Flash about $0.0125 and about $0.39. The cheap fast model is the realistic economic threat, not the slowest and most accurate one.
- Time pressure works mainly against slow, high-reasoning loops. A 10x extension of a 31-second puzzle is about 5 minutes, still far below 16-77 minutes, but Gemini-3 Flash-class speed and purpose-built solvers would not be stopped. A reactive task can also be delegated to conventional vision code rather than an LLM loop (Halligan shows the search-based approach generalises), so timing is not a durable moat.
- A compliant design is possible if latency is a scored signal and not a hard limit. Without a set limit that fails the user, SC 2.2.1 should not bite. If a limit is used, implement "turn off" or "10x extend" from the start and do not rely on the narrow essential exception.
- Pointer tracing and drag puzzles need keyboard and single-pointer equivalents (SC 2.1.1, 2.5.7). Any equivalent path may be easier for agents, since agents have `type`, `key` and click tools. Equivalence therefore limits the security uplift of motion-based challenges, and rate limits or proof of work should sit behind the accessible path.
- SC 3.3.8 excludes most resistant families for login use without an alternative (spatial, illusion and logic puzzles). Object recognition is excepted at AA, but recognition is also where solvers are strongest. An alternative method (WebAuthn, email link, or similar) is the honest resolution.
- Treat every solve-rate figure as a dated snapshot. Earlier benchmarks showed 40% on interactive puzzles, and family-level variance (0-60%) suggests attackers will concentrate on the weak families, so rotate and retire families using observed pass data.

### Gaps
- I found no study directly measuring a time-limited reactive challenge against LLM agents and disabled users. Next-Gen does not state its wall-clock limits. Viability is inferred, not measured.
- Human sample sizes are missing or small across these papers, and none reports results for disabled participants. All new-challenge results are authors' own and I found no independent replication.
- I could not extract Spatial CAPTCHA's human rates, because the PDF was not readable through my tools and the abstract omits them. "CAPTCHA in the age of LLMs" as a specific title was not located.
- I found no evidence on physical-interaction challenges or current audio CAPTCHA solving by 2025-2026 models.

## Client-side versus server-side evaluation and replay defences

### Takeaway
Client code should collect and optionally pre-summarise events, but all decisions must be made server-side from raw or re-derivable data bound to a single-use challenge. Published work offers little here, so this section is mostly engineering reasoning rather than measured evidence.

### Cited Findings
- Session-replay bots are an established threat class: they record real visitors' trajectories and replay them. ReMouse supports similarity analysis, reporting that different users on the same task and one user's repeat sessions were not near-identical. This is my reading of the abstract; I could not access the full paper for figures — [DOAJ](https://doaj.org/article/7ad2dc9734db4662afd4ec66e5040055); [ReMouse](https://www.mdpi.com/2624-800X/3/1/7).
- `isTrusted` and similar client values can be true under CDP, so they carry limited weight — [Clearcote](https://www.clearcotelabs.com/audit/checks/event-istrusted-provenance).
- Client-observable inconsistency has value: platform mismatches between main thread and worker were a noted tell for Operator and Browserbase, and Skyvern overrode resolution and timezone — [Castle](https://blog.castle.io/from-detection-to-trust-the-evolving-challenge-of-ai-bot-authentication/); [FP-Agent](https://arxiv.org/html/2605.01247v1).
- Web Bot Auth's short `expires` ("a minute is often sufficient") is one model for freshness, though Cloudflare does not validate `nonce` — [Cloudflare docs](https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth).
- FP-Agent's held-out-task drop shows behaviour features are task-dependent, which supports binding evaluation to the known widget layout — [FP-Agent](https://arxiv.org/html/2605.01247v1).

### Inferences
All of the following is reasoning, not measured evidence.
- **Never trust from the client:** a verdict, a score, any computed feature, `isTrusted`, timestamps, `navigator.*`, or a "challenge passed" flag. An attacker controls the code and can forge any payload. Client-local evaluation can only serve UX and data minimisation (for example, computing summaries to avoid sending raw paths), and any summary must be treated as an unverified claim.
- **Server-only inputs:** token issue and redeem times, solve answer and server-side state, IP/ASN, TLS and HTTP data, Web Bot Auth verification, nonce consumption and per-site rate limits.
- **Replay defences:**
  - Issue a server nonce, random widget layout and target positions per challenge, and require the event stream to land on those targets. A replayed trajectory then misses them.
  - Make the nonce single-use, short-lived, and bound to site key, origin and action.
  - Include a sequence counter and chained hash (each batch hash covers nonce and prior hash). This gives integrity only, since the client can compute it, but it forces forgers to regenerate rather than edit, and it adds structure checks.
  - Compare server arrival times against client timestamps to catch implausible batches.
  - Store a coarse trajectory hash or sketch per site, and flag near-duplicates across different nonces. Bound retention for privacy.
- **Attestation limits:** "event-sequence attestation" in pure JS is not real attestation. The only strong forms available are hardware or platform ones (for example WebAuthn), which the W3C note lists as an accessible option. An obfuscated client raises cost, and it does not change the trust model.
- **Open-source consequence:** a self-hosted, inspectable project should assume feature lists and weights are public. It can keep per-site calibrated distributions, nonces and challenge content secret.

### Gaps
- I found no peer-reviewed measurement of nonce-bound layouts or chained event hashes as replay defences, and no numeric replay detection results (ReMouse's full text returned HTTP 403).
- I did not research Private Access Tokens or Privacy Pass in depth, or the privacy law implications of storing raw trajectories. Those likely fall to adjacent scopes.

## Heuristic classifier design with no third-party training data, and per-site self-calibration

### Takeaway
A rule-based, evidence-weighted score with explicit abstention for missing modalities is feasible and transparent. Purely unsupervised anomaly detection performs poorly at realistic base rates, so bootstrap with self-generated positives: run open-source agents and scripts against your own widget, then calibrate human distributions per site in shadow mode.

### Cited Findings
- Akamai's comparison on the same data (about 85:1 imbalance): One-class SVM trained only on humans ROC 0.797 / PR 0.044; Isolation Forest 0.833 / 0.038, near-zero recall at useful thresholds; VAE with energy loss 0.882 / 0.410; supervised shallow MLP on embeddings 0.981 / 0.661. Its pipeline trains embeddings on about 3.5M unlabelled sequences and labels agents by running standardised prompts against instrumented sites — [Akamai](https://www.akamai.com/blog/security-research/identifying-agentic-automation-behavioral-telemetry).
- Random Forest on handcrafted features competes with or beats recurrent models on small data — [BeCAPTCHA-Mouse](https://ar5iv.labs.arxiv.org/html/2005.00890).
- Agent classifiers learn from few labels: fewer than one third of traces approach peak performance, though single-task transfer is weak — [arXiv 2605.14786](https://arxiv.org/pdf/2605.14786). That paper's corpus and harness are public, as is the [SapiAgent repo](https://github.com/margitantal68/sapiagent).
- Sources describe combining signals (more than 250 in a vendor product; desktop claim, automation surface, no typing variance and datacenter IP converging), without published weights — [cside](https://cside.com/blog/catching-ai-agents-behavioral-signals).
- W3C cautions that heuristics need careful tuning, adaptive bots can evade them, and low-burden honeypots are an option — [W3C Note](https://www.w3.org/TR/turingtest/).
- Combined features were more robust than behavioural alone on unseen tasks (0.93-0.97 versus 0.63-0.80) — [FP-Agent](https://arxiv.org/html/2605.01247v1).

### Inferences
**Proposed pipeline (all values are starting hypotheses to validate in shadow mode, not published thresholds)**

| Layer | Signal | Direction and proposed handling |
|---|---|---|
| Identity | Valid Web Bot Auth signature | Route to "signed agent" site policy; do not score as human |
| Hard automation | `isTrusted=false`, `navigator.webdriver`, framework globals, main/worker mismatch | Strong evidence; cap so that one signal alone escalates rather than blocks |
| Presence | Pointer click with 0-1 preceding moves, when not keyboard or touch activated | Strong evidence against current agents, marked perishable |
| Typing | Sustained inter-key under about 15 ms, near-zero variance, hold under about 5 ms | Strong evidence over at least 10 keystrokes; paste alone is neutral |
| Scroll | Instant jumps, even intervals, no ramp, only on wheel/touch claims | Moderate evidence |
| Tempo | Long irregular pauses followed by instant action; no pre-click dwell | Weak to moderate; humans also pause |
| Kinematics | Straightness, constant speed, missing deceleration near target, no correction, low jerk variability | Moderate; compute only with enough points (for example, at least 20 moves over at least 100 px) |
| Traps | Hidden field filled, benign canary echoed | Moderate; probabilistic because of reader modes and autofill |
| Replay | Trajectory sketch near-duplicate, missed randomised targets | Strong |
| Challenge | Solve result, attempts, solve time distribution | Moderate; a scored signal, not a timer |

**Score aggregation**
- Sum per-signal log-likelihood ratios with caps, so correlated signals cannot compound without limit. Group correlated features into one family, take the family maximum, then sum across families.
- Output three bands (allow, escalate to an interactive or alternative method, deny), with deny reserved for hard evidence plus rate or reputation evidence, never from kinematics alone.
- Expose per-reason codes, because rule-based scoring is an advantage for operators debugging false positives.

**Absent data**
- Distinguish three states: not applicable (touch device has no hover), abstained (too few samples, blocked events, privacy tools), and contradictory absence (mouse-capable device, pointerType "mouse", click with no moves).
- The first two contribute zero, not suspicion. Only the third is evidence. Abstention should widen uncertainty and may trigger low-friction proof of work, without lowering the score.
- Input modes should have separate models: mouse, touch, pen, keyboard-only, and unknown. Never compare a touch session to a mouse baseline.

**Self-calibration per site**
1. Ship with conservative, physically motivated hard rules plus no kinematic weight.
2. Shadow mode: log features for N sessions, scoring only. Per input mode and widget type, maintain robust quantiles (median, MAD, or streaming sketches).
3. Baseline hygiene: include only sessions with no hard signals and a successful downstream outcome (for example an authenticated user or completed checkout, if the site supplies one). Cap each IP, ASN and fingerprint's contribution, because otherwise attackers can poison the baseline by slow drift.
4. Bootstrapped positives: a local test harness runs Browser Use, Playwright, CDP and Bezier scripts against the widget, generating labels without third-party data. Re-run on framework updates, and keep the harness as a regression suite.
5. Convert features to empirical tail probabilities, fix a target human challenge rate (for example, 1-2%) and set bands from it, so operators choose friction directly. Conformal-style calibration is a candidate method, which I did not evaluate in sources.
6. Update slowly, with a sliding window, a freeze on abrupt distribution shift, and an operator alert. Very low-traffic sites should fall back to shipped priors or pooled opt-in summaries.
7. Monitor drift: agent-side changes (for example, teleport disappearing) should move a signal's weight down automatically when harness detection falls.

**Expected limits**
- This will stop commodity scripts and today's default agents. It is unlikely to hold against an adversary pairing a humanised cursor, realistic typing and a local browser, so rate limits, per-action cost and server-side abuse controls remain necessary.
- Per-site calibration can also learn from bots present during warm-up. Hygiene reduces this but does not remove it.

### Gaps
- I found no published per-site, zero-external-data calibration of a behavioural CAPTCHA with measured outcomes. The pipeline above is a design proposal requiring evaluation.
- I found no peer-reviewed published thresholds for browser-agent signals. FP-Agent's values are per-agent observations, and cside publishes none. Thresholds above need measuring against both human baselines and the harness.
- Sample sizes for shadow mode, base rates of agents on small self-hosted sites, and the PR-curve cost of an 85:1-or-rarer base rate on small sites are unknown.
