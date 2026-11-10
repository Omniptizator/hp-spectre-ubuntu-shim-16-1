# GitHub publication checklist

This directory is the repository root; its parent is private and must never be
added to Git. Create the GitHub repository and set its approved SSH URL only after
review. No project-specific origin URL is guessed by the scripts.

Before the first commit, verify the intended GitHub account with `ssh -T
git@github.com` (GitHub normally returns exit status 1 on success), review
`git var GIT_AUTHOR_IDENT`, `git var GIT_COMMITTER_IDENT`, and your configured
GPG identity privately. Prefer a GitHub-linked privacy-safe email if desired.
Commit names, emails and signing-key identifiers are public; scanner success does
not approve a personal address for you.

Enable the supplied pre-commit guard in the public repository with
`git config --local core.hooksPath .githooks`. It checks the working tree, complete
Git index and prior history before committing, including blobs staged earlier
that differ from the current files. It does not change global Git settings.

```bash
./cookbook test
python3 -B scripts/check_public.py
git diff --cached --check
git commit -S -m "Add model-specific staged shim cookbook"
git verify-commit HEAD
python3 -B scripts/check_public.py --history
```

The allowlist in `manifests/public-files.json` defines the complete source release.
The checker rejects unexpected files, symlinks, private-key blocks, common secret
patterns, user-home paths, identifying UUIDs, and an optional supplied local token.
It scans historical file names/content when `--history` is used. It is not a
guarantee that all conceivable personal data is detected: manually review files,
commit messages, account identity, licenses and release notes too.

For a source-only archive outside the checkout:

```bash
python3 -B scripts/check_public.py --history --export "$HOME/spectre-shim-cookbook-source.tar"
```

The exporter includes only allowlisted regular files and normalizes archive owner
metadata. It excludes `.git`, runtime files and generated binaries. It refuses
to overwrite an existing archive. Do not replace it with an archive of the parent
working directory.

After approval, set the reviewed origin, push signed commits, create a signed tag,
and share the sanitized case study with Ubuntu's issue tracker and relevant HP/Linux
forums. Describe this as a tested use of an upstream fix, not a new shim source fix.
