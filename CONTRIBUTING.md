# Contributing

Issues and pull requests are welcome. For anything bigger than a small fix, open an issue first.

Before a pull request, run what CI runs:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

A new or changed check needs two tests: one for the risky call it catches, and one for a similar
everyday call it must leave alone. False positives make people turn security tools off.

Rules live in `src/checks/`. Each rule has an id (`net.exfil_service`), a level per preset, and a
one-sentence explanation in the module's `RULES` list, which `guard explain` prints.

Commit subjects are short and lowercase with a type prefix, for example
`fix: ignore public keys under ~/.ssh`.

Found a way past a check? In light mode, open a [bypass report](../../issues/new?template=bypass.md) and, if you
can, a pull request that adds the case to `tests/bypass.rs`. Anything that gets past hardened mode or touches the
guard itself goes privately, as [SECURITY.md](SECURITY.md) describes.
