---
name: Bug report
about: Report a bug in tibread
labels: bug
---

## Describe the bug

A clear and concise description of what the bug is.

## To Reproduce

```
$ tib --version
<paste output here>

$ <the failing command>
<paste output / traceback here>
```

## Expected behavior

What did you expect to happen?

## Sample file

If possible, attach or link a small sample `.tib` file that reproduces the issue.

> **Warning:** `.tib` backup files may contain sensitive data (filenames, partition contents, hostnames, etc.).
> Do **not** share `.tib` files publicly without checking. Consider sharing only the first few KB
> (`head -c 4096 sample.tib > sample-header.bin`) or sending privately.

## Environment

- OS: (e.g. Ubuntu 24.04, Windows 11, macOS 14)
- Python version: (`python --version`)
- tibread version: (`tib --version`)
- Install method: (pip, source, etc.)
