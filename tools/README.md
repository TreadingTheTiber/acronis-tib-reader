# tools/

Standalone helper scripts that complement the `tib` CLI.

## tibwinmount.py — Windows WinFsp mount

Mount a `.tib` as a Windows drive letter. Requires:
- WinFsp installed: https://winfsp.dev/
- Python wrapper: `pip install winfspy`

Usage (from an admin PowerShell or cmd prompt):

```cmd
python tools\tibwinmount.py "C:\backups\my_backup_full_b1_s1_v1.tib" "C:\backups\blocks.idx" H:
```

After the script starts, the contents appear at `H:\` and you can browse with
Explorer, `dir`, robocopy, etc.

The current script still expects a pre-built `blocks.idx` next to the `.tib`.
Future versions will use the `tib index` command's auto-build instead.

For bulk extraction over the mounted drive, the recommended robocopy
invocation is:

```cmd
robocopy "\\?\H:\" "\\?\D:\restored" /E /R:0 /W:0 /XJ /MT:8 /COPY:DAT /DCOPY:T /TEE /UNILOG:C:\rc.log
```

`/XJ` excludes junction/reparse points (e.g., the Iomega `TheVolumeSettingsFolder`
metadata directories that don't enumerate). `\\?\` lifts the 260-char path-length
limit for both source and destination. For a NAS destination, use the UNC form:
`\\?\UNC\<server>\<share>\<dest>`.

## Future tools

- **tibmount.sh** — convenience wrapper for the Linux FUSE mount that handles
  unmount cleanup and stale-mount detection.
- **tib-recover** — guided recovery wizard that builds the index, mounts, and
  invokes robocopy with sensible defaults.
- **tib-fsck** — consistency checker: verify Adler32, walk every block's zlib
  Adler32, recompute MD5 manifest entries.
