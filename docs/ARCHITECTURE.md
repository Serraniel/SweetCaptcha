# Architecture

## Components

| Component | Role |
|---|---|
| `api.js` loader | Runs in the host page. Renders the frame, fills the form field, exposes the provider API. Reads no device data. |
| Frame | Runs on the captcha origin. Requests the challenge, runs proof of work in a Worker, shows status and tasks. |
| Collectors (`signals-*`) | Standard mode only. Loaded when the server asks for them. Absent from the strict-only image. |
| Go service | Issues challenges and tokens, verifies work, scores evidence, serves compatibility routes. |
| Valkey | Short-lived state only, with persistence off. Every key has a TTL. A memory store is available for one process. |
| `ipdata` sidecar | Refreshes public IP lists daily. The only service with internet access. Standard stack only. |

## Verification flow

```mermaid
sequenceDiagram
    participant P as Host page
    participant F as Frame (captcha origin)
    participant S as SweetCaptcha
    participant B as Your backend
    P->>F: start(action)
    F->>S: POST /v1/challenge
    S-->>F: sealed challenge, proof-of-work params, collector URLs
    F->>F: solve proof of work in a Worker
    Note over P,F: Standard mode waits up to 2.5 s for the visitor's first input
    P->>F: finish(interaction features)
    F->>S: POST /v1/submit (nonces, signals)
    alt no concern
        S-->>F: token
    else soft evidence, or no input
        S-->>F: checkbox; the click is scored, then token or puzzle
    else strong evidence
        S-->>F: puzzle or wait path, then token
    else definitive
        S-->>F: deny
    end
    F-->>P: token in form field
    P->>B: form submit
    B->>S: POST siteverify (secret, token)
    S-->>B: success, score, reasons
```

In standard mode, verification runs 0.6 s after the visitor's first pointer, touch or key input, or when the form is sent, whichever comes first. With no input for 2.5 s, the server asks for the checkbox, so that there is an interaction to judge. Focusing a field doesn't count as input, because drivers fill fields without any.

This means a visitor who moves the pointer and later clicks Send is judged on the movement only. The click on Send is no longer part of the evidence, which makes agents that move first and act later harder to catch than with submit-time verification. The checkbox step closes part of that gap: a click with no pointer path to it, or one made by script, leads to a puzzle.

## What is trusted

The client is never trusted. Anything it sends can be fabricated, and the source is public.

| Concern | Client | Server |
|---|---|---|
| Verdict | Shows status only | Computed from server-held policy |
| Proof of work | Solves | Sets the parameters, verifies, consumes once |
| Signals | Reduces to coarse values | Cross-checks against headers and TLS, and assumes they may be forged |
| Secrets | Holds none | Holds all keys |

Signals only ever add suspicion through contradiction. Their absence counts only when it is itself a contradiction: the collector not running, or a mouse click with no approach path.

## Tokens and challenges

- All values handed to clients are AES-256-GCM sealed, using keys derived by HKDF from the master key with separate purposes. A challenge can't be used as a token, and clients can't read scores or reasons.
- Challenges last 2 minutes and are consumed once.
- Tokens last 5 minutes by default, and redemption is an atomic `SET NX`. If the store is unavailable, verification **fails closed**.
- Site verification enforces the secret's ownership of the token, hostname and action allow lists, expiry and single use, on every API flavour. Hosted providers leave hostname and action checks to the integrator.
- Hostnames reported by clients can be spoofed outside a browser. In browsers, `frame-ancestors` enforces the allow list.

## Scoring

The engine starts from a prior log-odds of −2, about 12%, and adds capped per-group log-likelihood ratios. Grouping keeps correlated signals from one root cause from counting several times.

| Band (default) | Response |
|---|---|
| p < 0.5 | Pass |
| 0.5 ≤ p < 0.8, or no input | Checkbox, with harder proof of work behind it |
| p ≥ 0.8 | Puzzle or wait path |
| p ≥ 0.995, with hard and network evidence | Deny |
| Explicit automation marker | Deny (`policy.on_definitive`) |

Behaviour can never cause a deny on its own: at realistic base rates it can't be precise enough. Passing a step lowers suspicion, but the reported score stays below that of a silent pass.

## Interactive tasks

Tasks open in a dialog that closes with its button, Escape, or a click outside it. Closing returns the widget to the checkbox, cancels a held form submission, and ticking it again reopens the same task while it is valid.

Image recognition grids are not used, because they are cheaply solved. The families target what current AI models are measured to be bad at ([research notes](research/notes/ai_resistant_challenges.md)):

| Family | Task | Why it is hard for AI |
|---|---|---|
| `kinetic` | Press Play, then select every cell where a moving ring appears | The shapes exist only in motion: every frame is plain noise. Vision models scored near 0% on such stimuli, and agents act on screenshots. |
| `stack-order` | Name the shapes at the very back and the very front of an overlapping ring of six | Overlap and depth judgements: models 0-20%, people about 100% |
| `line-trace` | Follow two lines through crossings of one colour | Line following: about 27% for a strong model against 14% chance |
| `gap-rings` | Select every ring with a gap | Fine localisation |
| `rotate-match` | Turn shapes to match | Weakest against few-shot prompting; off by default |

These measurements come from small samples, and the margins erode. All of them help against general AI agents, not against a solver built for one family: the kinetic shapes can be recovered by comparing frames. Families can be rotated per site with `puzzles`.

The kinetic frames are rendered on the server, because a client renderer would need the shapes, which are the answer. They arrive as one PNG sprite sheet of whole frames, so there are no motion vectors to read, and CSS steps through it, so no script draws anything. Motion never starts by itself; it runs after Play and can be paused. Mean brightness is constant, to stay clear of flash thresholds, and people who prefer reduced motion are pointed to the alternative.

Each family has a keyboard path, answers stay on the server, and each puzzle allows one answer. Answers sooner than 1.2 s after a task appears count as wrong, since a person can't read and answer that fast.

None of them suits everyone, so the **wait path** offers a longer computation instead. It is a trade-off: a bot that reaches it can pay with CPU, which a task would not allow. To limit that, it is closed to any client with contradictions or automation markers, capped per address, and reported as `via: wait` with a lower score. Sites with high-value actions can reject `via: wait` or set `wait_fallback: false`, and should then offer another accessible route. A site can also show a support link.

## Editions

The `strictonly` build tag removes `internal/risk`, `internal/tlsfp`, `internal/ipdata`, `internal/puzzle` and the collector bundles from the binary. CI checks both the Go dependency graph and the contents of the image. Configuration asking for standard mode is refused at startup.

## Not implemented

These appear in the research but are not built yet: HTTP/2 and header-order fingerprints, Web Bot Auth for signed agents, timezone against IP-country checks, Private Access Tokens, rotating or obfuscated collectors, and automatic per-site threshold tuning. The admin page gives a read-only threshold suggestion instead, since self-tuning could be poisoned.
