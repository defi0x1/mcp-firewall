# Changelog

## 0.4.1

- Warnings about paste, webhook and tunnel sites no longer suggest whitelisting them.

## 0.4.0

- Release archives carry a build provenance attestation: `gh attestation verify <archive> --repo defi0x1/agent-guard`.
- Light-mode bypasses are now reported in public with a bypass issue template, and go into the attack corpus.
  Hardened-mode and self-protection bypasses stay private (see SECURITY.md).
- `scripts/bench-hook.sh` measures the hook's time per call on your machine.
- `examples/injected-repo`: a safe prompt-injection demo to try the guard on.
- README: recorded demo, install by reading the script first, the attack corpus, light vs hardened, strictness.

## 0.3.2

- `guard top`: quiet stretches of the call chart are dim; the explain window lists each earlier call once.

## 0.3.1

- `guard top` in Dracula (dark) and Alucard (light) colors, picked from your terminal or `--theme`.
- `w` in `guard top` whitelists the selected call's host.
- Fewer false reds: a `sed` regex like `.*` or a path in a `grep` pattern is not a credential read.
- A project's `.vscode`, `.cursor` and virtualenv files warn instead of asking; editor MCP configs still ask.
- Caught now: `cat ~/.ssh/*`, `gh auth token`, `aws secretsmanager`, `~/.ssh/authorized_keys`, uploads to raw IPs,
  and a shell variable holding the guard binary.

## 0.3.0

- Hardened mode: `sudo guard install --hardened` puts hooks, the sandbox and deny rules into root-owned managed
  settings.
- `guard whitelist <domain>`, `guard on`, `guard off`. `pause`, `resume` and `net-proxy` are gone.
- The status line says `agent guard: On` or `Off`, light or hardened, and keeps your own status line below it.
- `guard top` shows one live row per tool call, with a call-rate chart and an Alerts tab.
- Every finding from the security review and pentest is fixed. Tool results that can't be checked are blocked.
- An attack corpus (`tests/bypass.rs`) runs every case through the hook binary in CI.

## 0.2.0

- First public release: hooks, `guard top`, `guard doctor`, `guard scan`, `guard proxy`, keychain secrets.
