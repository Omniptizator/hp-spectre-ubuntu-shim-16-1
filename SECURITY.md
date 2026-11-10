# Security policy

This is experimental, model-specific boot-chain tooling. It is not endorsed by
HP, Microsoft, Canonical or the shim project. Do not use it as a universal installer.

Do not attach keys, firmware dumps, recovery credentials, raw local logs or entire
workspaces to issues. Share only a manually reviewed sanitized report and minimal
reproduction. If no private reporting channel is configured on the eventual GitHub
repository, ask for one without posting sensitive details publicly.

The threat model assumes a trusted local user, checkout, OS and private workspace.
Local checkpoints and manifests catch accidents, not a malicious administrator.
Never bypass hardware, signature, SBAT, revocation or reboot checks to continue.

If a signing key is compromised, stop using it and seek a reviewed revocation and
recovery procedure. Deleting a key file does not revoke its enrolled certificate.
