---
name: Format support request
about: Request support for a .tib variant tibread doesn't currently parse
labels: format-support
---

Most issues turn out to be format-support questions. Please fill in as much as you can.

## Format generation

Which variant is this? Check all that apply:

- [ ] `.tibx` (newer Acronis format)
- [ ] Older `.tib` (pre-2014-ish)
- [ ] Encrypted `.tib`
- [ ] Filesystem-mode / file-level backup (not disk image)
- [ ] Incremental / differential chain
- [ ] Other / unsure

## Hex dump of first 64 bytes

```
$ xxd -l 64 yourfile.tib
<paste output>
```

## File size

Total size in bytes (e.g. `ls -l yourfile.tib`).

## Acronis version that created it

(e.g. True Image 2021, Cyber Protect Home Office 2024, etc.)

## Why current detection fails

What error / output does `tib` produce on this file?

```
<paste error or unexpected output>
```
