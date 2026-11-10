# Source publication privacy checks

This directory is the repository root; its parent is private and must never be
included in a source release. Keep generated keys, backups, logs and other local
runtime data outside the public checkout.

```bash
./cookbook test
python3 -B scripts/check_public.py
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

When sharing the sanitized case study with Ubuntu's issue tracker or HP/Linux
forums, describe this as a tested use of an upstream fix, not a new shim source fix.
