# Maintenance obligations

- Your custom shim is not maintained by Ubuntu package upgrades. Track shim
  security advisories and suitable officially signed distribution replacements.
- Ubuntu maintains `/EFI/ubuntu`, not `/EFI/shim16-cookbook`. GRUB changes require
  deliberate revalidation of signatures, SBAT, configuration, VM tests and hardware
  boot. The deployment commands are not an update/rotation tool; do not rerun
  `prepare` against the installed configuration.
- Keep the dedicated EFI and helper keys backed up offline and private. Do not
  regenerate them while their certificates remain enrolled. There is no automated
  certificate rotation or key-compromise recovery in this release.
- HP/Microsoft retain PK/KEK authority. Your db signing key cannot authenticate
  arbitrary db/KEK/PK updates in User Mode. Replacement may need physical firmware
  interaction; plan before a certificate expires or a key is lost.
- The pinned dbx is dated 20260402, not a promise of ongoing freshness. Review
  subsequent vendor-authenticated updates for compatibility before applying them.
  Never remove known revocations to make an old loader boot.
- Firmware may reorder boot entries. `./cookbook status` is read-only; firmware's
  boot menu can select the custom path explicitly. Original Ubuntu/fallback
  files are retained but may still encounter the original failure.
- A persistent EFI-stub TPM-full warning is not proof that Secure Boot signatures
  failed. Conversely, successful Secure Boot does not establish complete TPM
  measurement logs or attestation. No warning suppression is included.
- fwupd's history may retain a stale reboot/update row. This cookbook does not
  clear it or retry firmware updates; actual variable readback is the dbx evidence.
