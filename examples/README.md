# tibread examples

Short, runnable scripts that demonstrate the `tibread` Python API. They are
intended both as a quick reference and as informal documentation for common
tasks.

All examples assume the package is installed (e.g. `pip install -e .` from
the repo root) and each takes a path to a `.tib` file as its first argument.

| Script | Description |
| --- | --- |
| [`inspect_format.py`](inspect_format.py) | Print format era, chunk-map location, partition geometry, and file count. |
| [`walk_directory.py`](walk_directory.py) | Recursively list every file in the backup with its size. |
| [`extract_by_extension.py`](extract_by_extension.py) | Extract every file whose path matches a glob pattern (e.g. `*.log`) to a target directory. |

## Usage

```sh
python examples/inspect_format.py /path/to/backup_full_b1_s1_v1.tib
python examples/walk_directory.py /path/to/backup_full_b1_s1_v1.tib
python examples/extract_by_extension.py /path/to/backup_full_b1_s1_v1.tib '*.log' ./out
```
