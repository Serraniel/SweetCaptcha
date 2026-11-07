# Contributing

Commits follow [Conventional Commits](https://www.conventionalcommits.org). Release Please reads them to pick the next [semantic version](https://semver.org) and write `CHANGELOG.md`, so don't edit the changelog or version by hand.

| Prefix | Effect |
|---|---|
| `feat:` | Minor version |
| `fix:` | Patch version |
| `feat!:` or a `BREAKING CHANGE:` footer | Major version (minor before 1.0) |
| `docs:`, `chore:`, `ci:`, `test:` | No release on their own |

## Local checks

```sh
(cd web && npm ci && npm run typecheck && npm run build && npm test)
go vet ./... && go test ./...
go test -tags strictonly ./internal/server ./internal/config
(cd lab && npm ci && LAB_CHROMIUM=/path/to/chromium npm run lab)
```

## Rules for detection changes

- Add each new signal to `risk.Rules` or `risk.ClientReads`, then regenerate the register: `go run ./cmd/sweetcaptcha signals > docs/SIGNALS.md`.
- Nothing may enter `web/src/loader`, `web/src/frame`, `web/src/worker.ts` or `web/src/shared` that reads a device property, uses storage or records interaction. Those files ship in strict mode. Detection code belongs in `web/src/signals`.
- Absence of a signal is not evidence, unless the absence is itself a contradiction. Privacy tools must not be treated as bot evidence.
- Behaviour alone may escalate, but it must never deny.
- Add a lab scenario when you add a rule for a new attacker tier.
