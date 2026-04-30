# Security Policy

`tibread` is a **read-only** tool for inspecting Acronis `.tib` backup files.
It does not write to backups, run as a service, or expose a network surface,
so there is no traditional attack surface for vulnerabilities.

That said, bugs that crash the reader on malformed or maliciously-crafted
`.tib` input are still bugs we'd like to fix (e.g. unbounded reads, integer
overflows in length fields, infinite loops on corrupt offsets). Please report
them on the public issue tracker.

## Reporting

Open a normal issue at the GitHub issue tracker. If you'd prefer to disclose
privately first, mention so in a minimal issue and we can move to email.

## Scope

In scope:

- Crashes, hangs, or excessive resource use on malformed `.tib` files
- Path traversal or unsafe writes during extraction

Out of scope:

- Parsing of `.tibx` files (not supported; see README)
- Parsing of encrypted `.tib` files (not supported)
- Anything requiring the user to run a modified `tibread` build

## Response

This is a small, best-effort open-source project. There is **no SLA** on
response or fix time. We'll get to reports as we can.
