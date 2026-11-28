# Security policy

Agent Guard is a security boundary. Where you report a weakness depends on which side of it you found it.

## Report privately

Use the **Security** tab of this repository, then **Report a vulnerability**, for:

- a way past **hardened mode** (the sandbox, the deny rules, or root-owned settings),
- a way for an agent to turn the guard off, pause it, or change its files or binary,
- a secret that reaches a log, a hook answer or `guard top`,
- anything in the release or install path (`install.sh`, release archives, attestations).

Include the hook input or command, what you expected, and `guard --version`. You should hear back within a week.

## Report in public

A shell command that dodges the parser in **light mode** is a known limit
([THREAT_MODEL.md](THREAT_MODEL.md)), so it isn't a secret. Open a
[bypass report](../../issues/new?template=bypass.md): it goes into the attack corpus with credit to you. Use fake
keys only.

## Known limits

The limits in the README's [Good to know](README.md#good-to-know) section and in
[THREAT_MODEL.md](THREAT_MODEL.md#out-of-scope) are known. Ideas for closing them are welcome as issues.
