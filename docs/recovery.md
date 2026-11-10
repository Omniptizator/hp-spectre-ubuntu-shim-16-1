# Recovery prerequisites and limits

**Prepare before firmware writes.** Have firmware-menu access, a tested bootable
recovery USB appropriate to the current revocations, backups of important data,
disk-unlock/recovery credentials, and enough time to recover without this laptop.
If you use TPM-bound unlocking or another OS, review the effect of Secure Boot
policy changes on it first. The script's flag is an acknowledgement, not a test
that your recovery USB actually boots.

Do not clear keys merely to experiment with a working installation. This cookbook
starts from an already chosen recovery state: Secure Boot disabled and PK absent
in Setup Mode. If entering it would erase unknown trust/revocations, obtain proper
backups and qualified help first. No universal HP key-clearing sequence is automated.
Do not confuse disabling Secure Boot, clearing keys, and loading factory keys.

The private `backup/` contains original Ubuntu/fallback files, a tar archive,
their hashes, boot-entry text and readable trust-database payloads. It is **not**
a complete NVRAM image and cannot recover trust already erased beforehand. Copy
it securely off the laptop before relying on it as a disaster-recovery backup.
EFI authenticated-update rules mean saved raw payloads are not necessarily
restorable in User Mode.

If boot fails, first use firmware's boot menu to select `Shim16 cookbook` explicitly.
The preserved Ubuntu shim may still fail with TPM log exhaustion; it is not a
guaranteed recovery route. Simply disabling Secure Boot may not bypass that failure.

Do not blindly restore default keys: that may remove the new local certificate.
Key clearing can remove revocations and trust, and must be a deliberate last-resort
physical recovery action, not a script fallback. Never write SetupMode directly.

No automatic rollback is supplied. Restoring ESP files or BootOrder does not undo
dbx revocations, MOK/runtime-variable effects, or SBAT policy. Do not copy older
loaders over newer ones without checking signatures and revocation compatibility.

After a partial script failure, preserve the private logs and checkpoints. Stop
and inspect the exact readback rather than deleting state or repeating firmware
writes. Do not publish the workspace as a bug-report attachment.
