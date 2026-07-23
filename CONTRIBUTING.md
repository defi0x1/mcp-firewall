# Contributing to mcp-firewall

Thanks for your interest! This is a young project and contributions are welcome.

## Development setup

```bash
git clone <your-fork>
cd mcp-firewall
pnpm install
pnpm test        # run the suite
pnpm typecheck   # type-check without emitting
pnpm dev --help  # run the CLI from source (via tsx)
```

Node 20+ and pnpm are required.

## Project layout

| Path | What |
|---|---|
| `src/proxy.ts` | The transparent MCP proxy (bridges two stdio transports) |
| `src/interceptor.ts` | Audit + policy + detector orchestration |
| `src/policy/` | YAML policy engine and matchers |
| `src/detectors/` | Pure secret detectors + result scanning/redaction |
| `src/approval/` | Local web-UI approval server |
| `test-support/` | A mock MCP server used as a test fixture |
| `docs/` | Architecture, design decisions, integration guide |

Start with `docs/ARCHITECTURE.md`, then `docs/DESIGN.md` for the *why* behind
key choices.

## Conventions

- **Detectors are pure functions** `(text) => Finding[]` — no I/O, no state. All
  side effects live in the interceptor.
- **Security-relevant code gets a test**, ideally written alongside it. Policy
  matchers and detectors especially.
- **Keep the dependency list small.** This is a security tool; every dependency
  is attack surface. Justify new deps in the PR.
- **The audit log must never contain raw secrets** (see DESIGN D9). If you touch
  the record-writing path, preserve that invariant.
- ESM throughout (`"type": "module"`) — use `import.meta.url`, not `__dirname`.

## Adding a detector

1. Write a pure `detectX(text: string): Finding[]` in `src/detectors/`.
2. Wire it into `detectAll()` in `src/detectors/scan.ts`.
3. Add unit tests covering true positives *and* false positives.

That's it — the interceptor already runs `detectAll` on every result.

## Submitting changes

1. Branch from `main`.
2. `pnpm typecheck && pnpm test` must pass.
3. Open a PR describing the change and the reasoning. For a new dependency or a
   change to the security model, explain the tradeoff.
