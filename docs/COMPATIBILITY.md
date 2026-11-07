# API compatibility

The compatibility layer follows public documentation. It has been tested with this project's own lab and tests, and **not against real third-party plugins**, so test your integration before relying on it.

## Routes

| | reCAPTCHA v2 and v3 | hCaptcha | Turnstile | Native |
|---|---|---|---|---|
| Script | `/recaptcha/api.js` | `/1/api.js` | `/turnstile/v0/api.js` | `/v1/api.js` |
| Verify | `/recaptcha/api/siteverify` | `/siteverify` | `/turnstile/v0/siteverify` | `/v1/siteverify` |
| Class | `g-recaptcha` | `h-captcha` | `cf-turnstile` | `sweetcaptcha` |
| Field | `g-recaptcha-response` | `h-captcha-response`, plus `g-recaptcha-response` | `cf-turnstile-response` | `sc-response` |
| Global | `grecaptcha` | `hcaptcha` | `turnstile` | `sweetcaptcha` |

Verify endpoints accept form-encoded and JSON bodies. reCAPTCHA's also accepts GET.

## Differences that matter

- **Scores follow each provider's direction.** On the reCAPTCHA route 1.0 means human. On the hCaptcha route 1.0 means threat. Turnstile has no top-level score.
- **Replay errors differ.** `timeout-or-duplicate` on reCAPTCHA and Turnstile; `already-seen-response` or `expired-input-response` on hCaptcha.
- **Token lifetime is 5 minutes by default on all routes.** Providers use 2 minutes on reCAPTCHA and hCaptcha. Set `token_ttl` if you depend on that.
- **Hostname and action are enforced at verify**, from site configuration. A token for an action not on the list fails.
- **Extension field.** Successful responses on compatibility routes carry a `sweetcaptcha` object with `mode`, `via`, `score` and `reasons`.
- **Strict mode returns a fixed score of 0.9** so that integrations with thresholds keep working. It carries no information about humanity, and `sweetcaptcha.mode` says `strict`.
- **`remoteip` is accepted and ignored.**

## JavaScript APIs

| API | Covered |
|---|---|
| reCAPTCHA | `render`, `reset`, `getResponse`, `ready`, `execute` (v2 widget ID, and v3 `execute(sitekey, {action})`), `render=<sitekey>`, `render=explicit`, `onload`, `hl`, invisible, `data-*` callbacks, button binding |
| hCaptcha | `render`, `reset`, `getResponse`, `remove`, `execute` including `{async: true}`, invisible |
| Turnstile | `render`, `execute`, `reset`, `remove`, `getResponse`, `isExpired`, `ready`, `action`, `cData`, `execution`, `appearance`, `response-field`, `response-field-name`, `refresh-expired`, `size`, `theme`, `language` |

## Not covered

- `grecaptcha.enterprise` and the reCAPTCHA Enterprise assessment API
- Friendly Captcha's API
- Android `apk_package_name`
- hCaptcha `setData`, `data-orientation`, and its open and close callbacks
- Turnstile's `before-interactive`, `after-interactive`, `unsupported` and `retry` options, and `feedback-enabled`
- Provider test keys: use `test_mode` on a site instead
- reCAPTCHA `isolated` and `inherit`

## Which applications can use it

From the research, read from each project's source or documentation. Versions may have changed.

| Application or library | Custom endpoint |
|---|---|
| Gitea (`RECAPTCHA_URL`) | Full URL |
| Ruby `recaptcha` gem | Full URL |
| `google/recaptcha` (PHP) | Full URL |
| `django-recaptcha` | Domain, so mirrored paths apply |
| Keycloak, Contact Form 7, `react-google-recaptcha` | Only a switch to `recaptcha.net`: need a code change or plugin |

DNS overrides aren't a general route, since browsers need valid certificates for the provider's hostnames.
