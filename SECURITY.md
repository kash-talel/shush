# Security policy

shush stores the most sensitive data people have. Security reports are welcome and taken seriously.

## Reporting a vulnerability

**Please do not open a public issue for vulnerabilities.** Use GitHub's
[private vulnerability reporting](https://github.com/kash-talel/shush/security/advisories/new)
instead. Include:

- what an attacker can do and what they need (local user, file access, network position…),
- steps or a proof of concept against the latest `main`,
- the shush version / commit and your Windows version.

You will get an acknowledgement, and a fix or a documented decision, before anything is disclosed.

## Scope

In scope: the vault, backup and attachment formats ([`docs/FORMAT.md`](docs/FORMAT.md)), the
cryptography, the Rust core's handling of secrets, the Tauri command surface, and the Win32
integration (clipboard, auto-lock, Quick search).

Known limitations that are **already documented** (see the README's *Security model* and issue #6),
such as strings inside WebView2 and memory in hibernation files, are not new findings, but ideas to
reduce them are very welcome.

## Supported versions

shush is alpha. Only the latest commit on `main` receives fixes.
