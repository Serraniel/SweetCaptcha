# AI-resistant challenge families (state as of 2026-11-08)

## Summary
- **Largest measured human-model gap: information that exists only across frames.** On SpookyBench, shapes and text are drawn as noise drifting against noise. Humans score about 98%, and every tested video-LLM scores 0%, including Gemini 2.5 Pro and a Qwen2.5-VL-7B fine-tuned on 400 videos. In Next-Gen CAPTCHAs, the motion-contrast "Spooky" families give humans 90-100% and frontier agents 0-10%.
- **Second-largest gap: static scene structure** (occlusion order, holes, overlapping outlines, ribbons, 3D viewpoint). Humans score 100% and GPT-5.2, Gemini 3 and Claude Opus 4.5 mostly score 0-20%, but per-family samples are tiny (5-20 puzzles).
- **Both gaps hold against generic agents, not dedicated pipelines.** Optical flow recovers motion-defined shapes, and adaptive solvers learn static categories in 1-2 encounters. Every family is an expiring margin, so keep rotating.
- **Shortlist:** (1) kinetic noise figures, (2) occlusion and topology counting, (3) shell-game tracking. All keyboard-operable, none non-visual, so proof of work must stay available.

## Measured results (human vs model, with n)
| Source | Task | Human | Best model | n / notes |
|---|---|---|---|---|
| [Next-Gen CAPTCHAs, ICML 2026](https://arxiv.org/html/2602.09012) | 27 procedurally generated families | 98.8% (CS group); 85.2% (8 non-CS participants, 216 trials) | GPT-5.2 xHigh 5.9%; Gemini-3 Flash 3.2%; Claude Opus 4.5 3.0%; Gemini-3 Pro 1.3% | 268 human trials (10 per family). Gemini runs use 519 puzzles; GPT-5.2 and Claude use a 135-puzzle subset (5 per family). |
| same | Spooky_Text / Shape_Grid / Circle_Grid / Circle / Size / Jigsaw (motion contrast) | 100 / 100 / 100 / 100 / 100 / 90 | 0-10% (Gemini-3 Pro, 10% on Size) | GIF payloads 3.4-9.2 MiB. Family-specific hints left Spooky families at 0-15%. |
| same | Structure_From_Motion; Temporal_Object_Continuity; Trajectory_Recovery | 90; 100; 100 | 5; 0; 0 | Animated |
| same | Hole_Counting; Illusory_Ribbons; Backmost_Layer; Occluded_Pattern_Counting; Layered_Stack; 3D_Viewpoint | 100 | 0; 0; 20; 20; 10; 0 | Static. Rotation_Match: 100 vs 20. |
| [SpookyBench / Time Blindness, CVPR 2026](https://arxiv.org/html/2505.24867v1) | Text, shapes and objects drawn as noise moving opposite to noise | 98.9 / 98.2 / 98.2%; dynamic scenes 94.3% | 0% for about 28 models (GPT-4o, Gemini 1.5/2.0/[2.5 Pro](https://timeblindness.github.io/), Qwen2/2.5-VL up to 72B, InternVL) | **Only 6 human participants**; 451 videos at 960x540 and about 47 fps. Human accuracy is 2.2% at 1 fps, 63% at 10 fps and about 96% at 20-30 fps (3 participants, 60 videos). Fine-tuning still gave 0%. |
| [Open CaptchaWorld, NeurIPS 2025](https://arxiv.org/abs/2505.24878) | 20 commercial-style types, 225 puzzles | 93.3% | Browser-Use with o3: 40%; Gemini 2.5 Pro 25% | No model solved Dice_Count, Place_Dot, Click_Order, Pick_Area, Geometry_Click or Slide_Puzzle ([HTML](https://arxiv.org/html/2505.24878v1)) |
| [COGNITION, arXiv 2512.02318](https://arxiv.org/html/2512.02318v2) | 18 real-world types, 7 MLLMs | not measured | GPT-5 about 60%, Gemini 2.5 Pro 57% | Place_Dot, Dice_Count, Click_Order, Pick_Area, Patch_Select and Rotation_Match stay below 20%, but few-shot prompting "near-breaks" Rotation_Match. **I could not confirm the USENIX Security 2026 venue.** The arXiv versions name none. |
| [Spatial CAPTCHA, ICLR 2026](https://arxiv.org/html/2510.03863v1) | Mental rotation, unfolding, perspective, occlusion | 89.5% (60 annotators, 30 s limit) | o4-mini 31.0%; Gemini 2.5 Pro 55% on reCAPTCHA-style items for comparison | Models are weakest on Unfolded (net folding) and Agent Sight (occluded multi-view) |
| [IllusionCAPTCHA, WWW 2025](https://arxiv.org/html/2502.05461v2) | Diffusion-generated illusion images plus decoy options | 86.95% pass on first attempt (n=23) | GPT-4o and Gemini 1.5: 0% | 30 CAPTCHAs; relies on models picking the longest option, easy to adapt to |
| [VLMs are blind (BlindTest), ACCV 2024](https://arxiv.org/abs/2407.06581) | Line intersections, overlapping circles, nested squares | about 100% (assumed, not measured) | Mean 58.6%; Claude 3.5 Sonnet 74% | Old models |
| [VLMs have Tunnel Vision](https://arxiv.org/html/2507.13361v2) | Circuit tracing with single-colour wires | 99.5% (authors only, 200 items) | Gemini 2.5 Pro 27% (chance 14%) | Crossings significantly hurt GPT-5 (log-odds -1.0). **This supports the current line-trace family.** |
| [MCA-Bench, AAAI 2026](https://arxiv.org/html/2506.05982v2) | 20 tasks, LoRA-fine-tuned Qwen2.5-VL-7B | n/a | above 96% on simple tasks, down to 2.5% on interactive or multi-step tasks | Attacker ceiling with a cheap fine-tune |

## Erosion: how fast margins close
- Arkose (vendor, 2024): under 1% of AI solvers passed its "AI-resistant" variants, against 92% on unaltered images ([blog](https://www.arkoselabs.com/blog/arkose-matchkey-ai-resistant-attack-innovation)). By early 2026, reasoning models pass such logic puzzles at up to 90% (Next-Gen).
- Comparable commercial types: best model went from 40% (o3, May 2025) to about 60% (GPT-5, Dec 2025), roughly 20 points a year.
- Halligan, a GPT-4o agent ([USENIX Sec 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/teoh)): 60.7% of 2,600 challenges (26 types), 70.6% of 3,000 live solver-farm tasks; weakest on continuous drag and rotate (about 29%).
- A YOLO plus VLM solver ([arXiv 2609.02393](https://arxiv.org/abs/2609.02393)) reached 85.4% on 16 classes and learns a new category after 1-2 encounters, using VLM answers as labels. It recovered from every monthly round of adversarial perturbations in a simulated year. **Recognition-style families do not survive public release.**
- Procedural generation stops memorisation, not a purpose-built solver: a re-implemented generator yields unlimited training data. What lasts is a capability gap (temporal integration, scene structure, perception tied to action) plus family rotation.
- Motion designs have fallen before: NuCaptcha to tracking ([Xu et al., USENIX Sec 2012](https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/xu_y)), its emerging-image successor later ([Gao et al., TDSC 2017](https://nsaxena.engr.tamu.edu/wp-content/uploads/sites/238/2019/12/gmsz-tdsc17.pdf)). SpookyBench's own temporal-coherence map lifts SNR from -49 dB to +7 dB, so simple optical-flow code solves what VLMs fail. This is the limit of the motion approach.

## Animation and accessibility (WCAG 2.2)
- **2.3.1 Three Flashes** ([W3C](https://www.w3.org/WAI/WCAG22/Understanding/three-flashes-or-below-threshold)): a flash is an opposing change of at least 10% relative luminance over more than 25% of any 10-degree visual field. Drifting dots at constant mean luminance, in mid-contrast grey on grey, keep each area's average steady and should stay under the threshold. Avoid full-field flicker and saturated red, and check frames with a Harding-style analyser.
- **2.2.2 Pause, Stop, Hide**: motion that starts automatically, runs longer than 5 s and sits beside other content needs a pause control. Start the animation only on the user's "Play" action, loop it for 2-3 s, and offer Pause/Replay.
- **2.3.3 (AAA)** and **prefers-reduced-motion**: vestibular-sensitive users need a non-motion path. Route them straight to a static family or to proof of work.
- **1.1.1 CAPTCHA exception** requires a text alternative stating the purpose, plus an alternative in another modality. **3.3.8 Accessible Authentication (AA)** exempts object recognition but not puzzles like mental rotation or counting. Every family here is a cognitive-function test, so the long-calculation alternative is how SweetCaptcha complies ([W3C, Inaccessibility of CAPTCHA](https://www.w3.org/TR/turingtest/)).
- Motion-defined form is invisible to some low-vision users. Allow 2-3 attempts (Next-Gen's non-CS cohort: 85%).
- No study tests audio versions of these tasks, and speech-to-text breaks audio CAPTCHAs. The non-visual path is proof of work.

## Implementation: where the answer can leak
- **Static families**: render as PNG in Go, as now with `raster.go` and data URLs. Safe.
- **Motion-in-noise**: **the client must not render from a seed.** Any client renderer needs the figure mask or velocity field, and that is the answer. The server has to send pixels. Do not use codecs that store motion vectors (GIF frame deltas, video, APNG with offsets), because the vectors spell out the mask. Send raw 1-bit frames instead, for example 160x160 pixels x 40 frames packed as bits, about 128 KB. That is far smaller than Next-Gen's 3-9 MiB GIFs. Noise barely compresses, but that does no harm.
- **Tracking families**: the server can send per-frame position lists, shuffled each frame and carrying no identities. This takes a few KB, but the answer is then one data-association step away (Hungarian matching) for a dedicated attacker. Against screenshot-driven agents it is equivalent to sending frames.
- **Agent capture**: agents screenshot every few seconds, while humans need at least 20 fps. A custom attacker can read the blob or `getImageData`, which is the known limit.

## Ranked shortlist

### 1. Kinetic noise figures (motion-defined shapes in a grid)
- **Generate**: a 3x3 grid of 96 px cells. Each cell has a 1-bit noise field of 1-2 px dots at 30-50% density, using one or two shared textures. In 2-4 target cells, a shape (ring, triangle or arrow) is filled with noise drifting in direction θ, and the background drifts at θ+180°, both at 1-2 px per frame. Decoy cells carry a shape of the same size in coherent motion of another kind (rotation, or the same direction as the background with a speed offset) or no shape. Prompt: "Select every cell with a hidden *ring*", which needs both shape and motion. Randomise θ, speed, dot lifetime (5-10 frames, which limits clean frame-pair diffs), global jitter and the frame count (36-48 at 24-30 fps). The answer space is 9 choose k with k unknown, so 2^9 guesses.
- **Why models fail**: each frame is uniform noise; VLMs sample sparsely and rely on spatial features (0% even fine-tuned, SpookyBench), and agents capture far below 20 fps.
- **Expected humans**: 90-100% at a smooth frame rate (Next-Gen n=10 per family; SpookyBench n=6). Measure your own rate on slow devices.
- **Accessibility**: keyboard with arrow keys plus Space and Enter. Must not autostart, needs Pause/Replay, and should keep grey-on-grey mean luminance. Under reduced motion, skip it. It has no non-visual form, so it needs the proof-of-work path.
- **Sketch**: Go `kinetic(r) (Public, Answer)` renders frames into a `[]byte` bitplane and stores it under the challenge ID. `Public{Family:"kinetic", Columns:3, Rows:3, Frames:n, W, H, FPS}`, with the blob at `GET /v1/puzzle/{id}/frames` (single fetch, `Cache-Control: no-store`). TypeScript `fetch().arrayBuffer()` unpacks bits into a `Uint32Array` ImageData, and `requestAnimationFrame` steps frames at the given fps. Selection sits on an overlay canvas. The server rejects a submit sooner than about 1.5 s after the frames were served.

### 2. Occlusion and topology counting (static)
- **Generate**: (a) **Backmost/stack order**: 5-7 same-colour outlined polygons drawn with painter's order, where only the outline segments in front are visible. The task is to click the shape at the very back, or enter the stacking position of a marked shape. (b) **Hole counting**: one self-overlapping single-colour ribbon, a closed spline with offset outlines, and the task is to enter how many enclosed holes it has. Compute ground truth by flood-filling the rendered mask on the server. Reject ambiguous renders with near-tangent edges (minimum gap 4 px, as in the existing `longestCloseRun` check).
- **Why models fail**: low-level vision (overlap, nesting, crossings) plus counting, where one error flips the answer. Next-Gen 0-20%; BlindTest and Tunnel Vision show the same weakness.
- **Expected humans**: 100% in Next-Gen (n=10 per family) and 85% in the non-CS cohort. Lower for complex instances, so cap at about 5 holes.
- **Accessibility**: keyboard with Tab or arrows to cycle shapes, or digit entry. No motion concerns. It is a visual cognitive test (3.3.8), so proof of work stays the alternative.
- **Erosion risk**: highest of the three, because static data is easy to generate and fine-tune on. Vary ribbon styles, textures and fills often.
- **Sketch**: extend `raster.go` with `polygonStroke` and occlusion masking (an alpha mask per layer). `Answer.Values=[index]` or `[count]`. The client reuses the existing image plus option UI.

### 3. Shell game (tracking identical objects)
- **Generate**: 4-6 identical discs. One is highlighted for 1 s, then all swap along curved paths for 3-4 s, with 3-5 crossings and partial occlusion behind 1-2 bars. The task is to click the original disc, or the one that ends in a given slot. To harden it, draw the discs as kinetic-noise figures (family 1), which makes them invisible in every frame.
- **Why models fail**: needs object identity across frames. Next-Gen Temporal_Object_Continuity and Trajectory_Recovery: humans 100%, all models 0%.
- **Expected humans**: high. Tracking 4 or fewer objects is near ceiling in the perception literature (not measured here). Keep speed moderate.
- **Accessibility**: about 4 s of user-started motion with Replay; skip under reduced motion; keyboard via numbered slots.
- **Sketch**: Go simulates paths. Cheap variant: per-frame shuffled position arrays (a few KB) drawn by the client, weak against a dedicated tracker. Strong variant: bitplanes as in family 1. `Answer.Values=[slot]`.

**Changes to existing families**: keep line-trace (single colour with crossings is measured as hard: 27% against 14% chance). Rotate-to-match is the weakest, because few-shot prompting near-breaks Rotation_Match (COGNITION) and Next-Gen measured up to 20%. Retire it first, or require a continuous 3D rotation instead.

## Gaps
No independent replication of any 2026 number. Human samples are small (6-60). No published model results on SpookyBench for GPT-5.x or Gemini 3. No measured photosensitivity or vestibular study for motion-in-noise CAPTCHAs. No hCaptcha research post found.
