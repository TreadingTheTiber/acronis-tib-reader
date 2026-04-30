# Release process

This document describes how to push `tibread` to GitHub. Maintainer-only;
end users can ignore it.

## One-time: create the GitHub repository

Suggested repo name: **`tibread`** (matches the package name; canonical
clone path becomes `https://github.com/<user>/tibread`).

You can create it via the `gh` CLI in one command (recommended), or via
the GitHub web UI.

### Option A — `gh` CLI (recommended)

```bash
cd /home/colin/tibread/dist

# Create the repo on GitHub and add it as a remote in one shot.
# Use --public for an open-source release, or --private for a private repo.
gh repo create tibread \
    --public \
    --source=. \
    --remote=origin \
    --description "Pure-Python read-only access to Acronis True Image .tib backups" \
    --push=false
```

`--push=false` is intentional — we want to push tags + branch in a
controlled second step (next section).

### Option B — GitHub web UI

1. Go to <https://github.com/new>.
2. Name: `tibread`. Visibility: public (or private). **Do not** initialize
   with a README, .gitignore, or license — the repo already has those.
3. From the local clone:
   ```bash
   cd /home/colin/tibread/dist
   git remote add origin git@github.com:<user>/tibread.git
   ```

## Push the initial release

```bash
cd /home/colin/tibread/dist

# Push master branch and set upstream.
git push -u origin master

# Push the v0.1.0 tag.
git push origin v0.1.0
```

That's it — the repo + tag are now on GitHub.

## Optional: create a GitHub release for the tag

Turning the `v0.1.0` tag into a proper Release surfaces the changelog in
the GitHub UI and on the repo's sidebar.

```bash
cd /home/colin/tibread/dist

gh release create v0.1.0 \
    --title "tibread 0.1.0 — first release" \
    --notes-file CHANGELOG.md
```

(or use `--notes "..."` to write the notes inline.)

## Update the homepage URL

`pyproject.toml` and `CHANGELOG.md` currently reference
`https://github.com/yourname/tibread`. After creating the repo, do a
quick find-and-replace:

```bash
cd /home/colin/tibread/dist
sed -i "s|github.com/yourname/tibread|github.com/<user>/tibread|g" \
    pyproject.toml CHANGELOG.md README.md
git add pyproject.toml CHANGELOG.md README.md
git commit -m "Update repo URL for GitHub publication"
git push
```

## What is NOT in the repo (and shouldn't be)

The `.tib` test files used to validate this release are **the user's own
backup data** and live at `/mnt/e/`, not inside `/home/colin/tibread/dist/`.
They are excluded from version control by virtue of being outside the
repo tree, and the `.gitignore` further excludes the generated `*.idx`
sidecars in case anyone copies a `.tib` into the repo for testing.

**Do not push:**
- `*.tib`, `*.tibx` — backup data, often sensitive, large.
- `*.idx`, `*.idx.*` — generated sidecars, rebuildable from the `.tib`.
- `__pycache__/`, `*.egg-info/`, `build/`, `dist/`, `.venv/` — already in
  `.gitignore`.
- Any `product.bin` or other Acronis binaries — proprietary, do not
  redistribute.

If you ever want to share a `.tib` for bug-report reproduction, attach it
directly to the GitHub issue (or use a private file-share link); never
commit it.

## After publishing

- Verify the repo renders the README correctly on github.com.
- Verify the v0.1.0 tag is visible under `Releases` (or under
  `git tag` on a fresh clone).
- Smoke-test a fresh clone:
  ```bash
  cd /tmp && rm -rf tibread-smoke && \
      git clone https://github.com/<user>/tibread.git tibread-smoke && \
      cd tibread-smoke && \
      python3 -m venv .venv && \
      .venv/bin/pip install -e . && \
      .venv/bin/tib --version
  ```
  Expect: `tibread 0.1.0`.
