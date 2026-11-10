# HP Spectre TPM-log exhaustion: shim 16.1 cookbook

An executable, **source-only recovery cookbook** for the **HP Spectre x360
15-bl012dx, board 82C1, BIOS F.42**, running Ubuntu 26.04 x86_64 with its existing
NVIDIA/MOK setup. Other models, firmware versions, layouts, and module-signing
arrangements are intentionally rejected rather than guessed.

## Related HP community report

This repository aims to solve the `Could not create MokListRT: Volume Full` /
`import_mok_state() failed: Volume Full` boot failure reported by an HP Spectre
owner in [HP Community: BIOS reset](https://h30434.www3.hp.com/t5/Notebook-Boot-and-Lockup/BIOS-reset/td-p/9442525).
That report describes Windows 10 / Ubuntu 24.04 dual-boot failing after an Ubuntu
update. It has the same error messages, but does not identify the exact Spectre
model or establish TPM-log exhaustion as its cause.

**Our hardware testing was Ubuntu-only, without dual-boot.** Windows coexistence,
BitLocker behavior, and recovery on the forum poster's laptop have not been tested;
the matching symptoms are not a guarantee that this cookbook applies to it.

## What this does—and does not do

The reference laptop stopped in shim 15.8 with `import_mok_state() failed:
Volume Full` after firmware TPM logging returned `EFI_VOLUME_FULL`. Upstream
shim 16.1 tolerated that logging failure and allowed boot with Secure Boot,
kernel lockdown and NVIDIA working. No production C/header patch was needed.

**This does not fix firmware log capacity or establish complete measured-boot
logging/attestation.** A Linux EFI-stub load-options warning may remain:

```text
EFI stub: WARNING: Failed to measure data for event 1: 0x800000000000000b
```

This custom boot chain is **not Microsoft-signed, Ubuntu-supported, or maintained
automatically by Ubuntu updates**. Read [the full procedure](docs/cookbook.md),
[recovery](docs/recovery.md), and [maintenance](docs/maintenance.md) before use.
Prefer a suitable officially signed distribution release when available.

## Five commands, four manual reboots

Run as your normal user, **not with `sudo`**. The entry point requests sudo for
explicit privileged operations only. The first command's flags acknowledge
recovery readiness and the documented reconstructed-trust policy.

```bash
./cookbook prepare --install-dependencies --recovery-ready --accept-reconstructed-trust
# REBOOT 1 manually: Secure Boot disabled; select Shim16 cookbook if needed.

./cookbook enroll
# REBOOT 2 manually: Secure Boot remains disabled.

./cookbook enable
# REBOOT 3 manually: enable Secure Boot in firmware WITHOUT loading factory keys.

./cookbook finish --apply-dbx
# REBOOT 4 manually: Secure Boot remains enabled.

./cookbook verify
```

**Starting prerequisite:** Secure Boot disabled, Setup Mode active, PK absent.
If you are not already in that recovery state, stop and read the recovery guide.
The scripts never clear keys, load factory defaults, reboot, flash firmware,
change the TPM, decrypt, repartition, or overwrite Ubuntu/fallback loaders.
Do not replay this procedure against an already-working deployment.

## Certificate and privacy policy

- Each target user generates **their own self-signed EFI and helper certificates**.
- Canonical/Microsoft certificates are public vendor inputs. HP factory public
  certificates are read from the target's firmware and checked against the
  reviewed model/firmware profile. Existing MOK trust belongs to the target.
- **No author's signing certificate or private key is provided or needed.**
- No local usernames, passwords, machine UUIDs, original photos, or raw diagnostics
  are distributed here. Normal interactive sudo is used; no password is stored.
- Runtime data stays outside the checkout, by default under
  `$HOME/.local/state/spectre-shim-cookbook/` with mode 0700. Keys are mode 0600.
  This directory is private, not an uploadable release.

## Checks without deployment

```bash
./cookbook status                   # Read-only hardware/firmware summary.
./cookbook test                     # Unit tests and publication checks; no sudo.
```

For a full fresh-key build and five isolated OVMF scenarios, see
[contributing](CONTRIBUTING.md). This mode does not stage files or write EFI
variables, and its checkpoints cannot be used for deployment.

## Evidence and release status

The [case study](docs/case-study.md) describes the successfully deployed original
procedure. The refactored cookbook is validated separately; do not mistake the
original hardware result for a hardware run of this new automation. See
[validation](docs/validation.md) for the exact checks performed.

Use the [publication checker](docs/publishing.md) before every GitHub release.
Only reviewed source is shared—never locally signed EFI binaries.
