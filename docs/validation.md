# Validation scope

The original deployment's hardware result is recorded in the case study. The
public refactor is a distinct implementation; its firmware-write stages have
**not been replayed on hardware**. They must not be advertised as independently
hardware-tested merely because the original procedure worked.

## Refactor validation on 2026-11-10

- **56 local tests passed**, including the four-reboot phase sequence, deferred
  SetupMode handling, partial-write guards, existing-revocation preservation,
  conflicting BootNext, exact MOK confirmation and publication/index checks.
- A fresh private workspace generated **new test-only signing keys**, fetched
  and verified the pinned sources and Microsoft inputs, and built the loaders.
- **118 upstream shim tests passed**; production C/header sources were unchanged.
- Loader signatures, embedded Canonical trust, SBAT and PE application checks passed.
- **All five OVMF scenarios passed:** baseline dbx, updated dbx, Canonical GRUB,
  untrusted shim rejection and simulated TPM-full tolerance.
- The public source tree passed its **33-file allowlist/privacy check**.

The fresh-key VM run used the reviewed public factory ESL exports because this
firmware no longer exposed its Default variables after enrollment. It used the
existing isolated public VM-tool packages, not a new global package installation.
No existing signing key was reused. VM mode did not access the root-only running
kernel image; that verification remains in the permission-gated deployment path.
No live ESP or firmware-variable writes were performed during refactor testing.

## Repeating checks

Validation of the refactor consists of:

- Unit tests of parsers, stage/reboot prerequisites, trust-preservation logic,
  conflicting boot selection, MOK handling and publication checks.
- A fresh-key build from pinned, verified upstream inputs.
- The 118 upstream shim tests in a separate compatibility-adjusted test tree.
- Signature, embedded vendor trust, production-source and SBAT audits.
- Five isolated OVMF scenarios: baseline dbx, updated dbx, Canonical GRUB boot,
  untrusted first-stage rejection, and simulated TPM `EFI_VOLUME_FULL` tolerance.
- Publication allowlist, privacy scanning and signed-commit verification.

Run `./cookbook test` for the current unit/publication result. The optional
`test --build-vm` emits its actual scenario results into its private workspace.
Test counts are evidence of the exercised cases, not proof against every firmware
failure mode. A future hardware trial needs a prepared recovery path and must be
recorded explicitly as a trial of this refactored cookbook.
