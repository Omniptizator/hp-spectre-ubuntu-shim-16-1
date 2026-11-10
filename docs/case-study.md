# Sanitized reference case

## Environment

- HP Spectre x360 15-bl012dx, board 82C1, BIOS F.42.
- Ubuntu 26.04.1, kernel 7.0.0-43-generic.
- NVIDIA 580.178.04, GeForce 940MX; existing module-signing MOK retained.

No login names, machine UUIDs, signing fingerprints, photographs, raw terminal
transcripts, or private key material are included in this record.

## Failure and recovery

Shim 15.8 completed EFI-variable writes, then TPM logging returned `EFI_VOLUME_FULL`,
ending in `import_mok_state() failed: Volume Full`. A later dbx update attempt was
reported to fail similarly, but no separate TPM trace was captured for that attempt.
Manual Secure Boot key clearing had already recovered ordinary boot before the
custom-shim work began. It is not proposed as a routine diagnostic experiment.

Stable upstream shim 16.1, commit `afc49558b34548644c1cd0ad1b6526a9470182ed`,
was built with unchanged production C/header sources and pinned gnu-efi
`dc7fd96f23d6b582416f672844362d776d175cf4`. Canonical CA/vendor revocations
were retained; matching MokManager was signed separately. A dedicated local
certificate authorized the first-stage shim via firmware db.

The original procedure passed 118 upstream tests, 13 local tests and five isolated
OVMF scenarios. Hardware validation covered the disabled-enforcement smoke test,
trust persistence, enabled Secure Boot, active kernel integrity lockdown, working
NVIDIA, BootOrder finalization, and authenticated dbx 20260402 persistence.

PK read back exactly immediately after enrollment, but SetupMode remained 1 until
the next manual reboot. Only after restart did it become 0. This is an explicit
checkpoint in the cookbook, not a reason to weaken validation.

The final dbx contained 493 unique entries: the union of 421 reconstructed-baseline
and 443 update entries. Those counts describe this reference case, not a universal
expected size for laptops retaining additional earlier entries. Original Ubuntu
and fallback loader hashes remained unchanged.

## Residual limitation

A photograph confirmed `EFI stub: WARNING: Failed to measure data for event 1:
0x800000000000000b`. This is `EFI_VOLUME_FULL` for the Linux EFI-stub load-options
measurement. Boot succeeds with signature enforcement and lockdown, but firmware
TPM log capacity remains limited. Complete measured-boot logs and attestation were
not established. No warning suppression, TPM clearing, BIOS/TPM updates, decryption,
or repartitioning was performed.

This documents use of an existing upstream fix, not a new production-source patch.
The new public automation has a separate validation record and has not been
replayed on the already-working reference laptop.
