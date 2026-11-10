# Contributing

Keep this release specific to the documented HP model/firmware. Do not remove
guards to claim wider compatibility. Never test privileged deployment commands
on the already-working reference laptop.

```bash
./cookbook test
```

For the full read-only-input build and VM checks on the documented laptop, install
the listed dependencies first, then use a **separate** empty private directory:

```bash
./cookbook test --build-vm --state "$HOME/.local/state/spectre-shim-vm-check"
```

This generates fresh keys, uses a synthetic GRUB redirect, reads public firmware
templates and installed vendor inputs, and runs all five networkless OVMF scenarios.
It never requests sudo, writes the ESP, or updates EFI variables. It is not a
mock of shim: the VMs execute the actual newly built signed loaders. The injected
TPM-full fixture tests the error path, not a physical TPM or attestation.
If firmware no longer exposes its Default variables, add `--factory-inputs` with
your reviewed public raw ESL export directory, as explained in the procedure.
This no-sudo VM mode does not inspect a root-only installed kernel image. The
deployment path separately snapshots it with permission, checks its signature,
and rechecks the live kernel inside privileged deployment verification. VM-only
audit records are explicitly rejected by deployment.

CI runs unprivileged unit/publication checks only; hosted CI has no HP firmware
templates and must not claim hardware validation. The optional VM build is local.
Temporary test data belongs outside the checkout. Source reproducibility is
pinned; per-user keys, certificate serials, signing and toolchain differences mean
signed binaries are not promised to be bit-for-bit reproducible.

Use signed commits with a privacy-approved public identity. Git author/email and
signing-key identifiers are public metadata. See [publishing](docs/publishing.md).
