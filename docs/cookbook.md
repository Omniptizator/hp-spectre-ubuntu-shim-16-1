# Procedure and trust contract

## Supported starting state

This is a model-specific recovery procedure, not a universal Secure Boot installer.
The scripts require HP Spectre x360 15-bl012dx / 82C1 / F.42, Ubuntu 26.04 x86_64,
an internal GPT NVMe ESP mounted as vfat at `/boot/efi`, the installed Canonical
shim/GRUB inputs matching the pinned embedded CA/vendor revocations, and working
NVIDIA signed with the existing enrolled local MOK at the standard Ubuntu path.
Board/model/BIOS checks are not a claim to distinguish every SKU sharing a DMI name;
confirm the physical model too. Unknown inputs stop the workflow for review.

Firmware `PKDefault`, `KEKDefault`, `dbDefault` and `dbxDefault` variables are not
always exposed after mode changes. If unavailable, `prepare` (or the optional VM
test) accepts `--factory-inputs /absolute/private/template-directory` containing
the four **public**, previously exported raw signature lists `factory-PK.esl`,
`factory-KEK.esl`, `factory-db.esl`, `factory-dbx.esl`, without efivarfs attributes.
All four must match the profile's pinned hashes; arbitrary or local signing
certificates are not accepted as substitutes. Obtain them from your own reviewed
firmware export/recovery records. Missing templates stop the procedure; never
clear keys merely to make these variables appear. No existing private key is read.

Start in Setup Mode with Secure Boot disabled and PK absent. No script creates
that state or clears trust for you. Check recovery readiness BEFORE changing
firmware configuration. A populated, already-working installation must not be
reset just to try this cookbook.

## Private workspace and consent

All commands use the same private state directory across reboots. To use another
location, pass `--state /absolute/private/directory` to **every** command. It must
be outside the source checkout, owned by you, mode 0700, without symlink ancestors.
Use protected encrypted storage and make an offline backup of the signing keys.

Keys are unencrypted PEM for the existing shim/sbsign toolchain, restricted to
0600. There is no HSM or automatic rotation. Do not print, upload, or silently
replace them. Only the new dedicated keys are read for signing, never the existing
module-signing private key. Separate EFI and helper keys are used.

`prepare --recovery-ready --accept-reconstructed-trust` explicitly acknowledges:

1. You have usable recovery media, firmware access, any disk-unlock credentials,
   and a plan for failed boot. TPM-bound unlocking may need recovery credentials.
2. Backups made now cannot recover databases already erased before the cookbook.
3. The reviewed recovery baseline combines pinned public factory templates,
   Microsoft UEFI CA 2011 and the authenticated 2023 dbx payload. It is a semantic
   reconstruction, **not a byte-identical pre-clear export or proof that unknown
   older revocations were retained**. If that is unacceptable, stop and recover
   your actual prior inventory instead; do not weaken the guards.
4. Any KEK/db/dbx still readable at the initial backup are retained as entry-set
   supersets. The existing PK must be absent. Existing MOKs are not enrolled or
   cleared by this cookbook; shim may still perform its normal runtime/SBAT work.

HP factory PK and HP/Microsoft KEK authority are retained. Adding your certificate
to db does **not** give your key authority to update db/KEK/PK in User Mode.
Future certificate replacement may require physical Setup Mode again.

The dated 20260402 Microsoft-authenticated dbx payload is a separately authorized
append, not a moving "latest" download. It does not claim to be the newest policy
at the time you read this. No newer Microsoft 2023 trust-certificate migration is
included. Review current vendor/distribution guidance independently.

Historical update signature verification uses the pinned factory Microsoft KEK
CA 2011, with certificate-time checks disabled for those legacy signed payloads.
It still verifies the cryptographic signature and exact pinned payload hash; it
does not bypass firmware authentication or make a different downloaded file valid.

## Phase details

### 1. Prepare, then reboot with Secure Boot disabled

`./cookbook prepare --install-dependencies --recovery-ready --accept-reconstructed-trust`

Installs the manifest's packages using normal APT confirmation. Without the
dependency flag, installed prerequisites are required. Captures original Ubuntu
and fallback files, current boot configuration and readable databases privately.
Refuses conflicting BootNext and detected pending capsule indications.

Fetches pinned shim 16.1 and gnu-efi, verifies the upstream tag and signer, checks
download hashes and Microsoft dbx signatures, generates dedicated keys, builds
matching shim/MokManager, runs 118 upstream tests and five VM scenarios, audits
embedded trust/signatures/SBAT, and stages four files in a separate directory:
`/boot/efi/EFI/shim16-cookbook/`. Normal build/signing runs unprivileged.

Existing Ubuntu/fallback files and BootOrder are not deliberately replaced. A new
boot entry is created with `--create-only`; BootNext schedules the smoke test.
Select `Shim16 cookbook` yourself if firmware ignores BootNext.

### 2. Enroll, then reboot with Secure Boot still disabled

`./cookbook enroll`

Requires a new boot through the staged entry, matching files and MOK/module
identity. Writes/readbacks KEK, db and baseline dbx, with PK last. Unexpected
existing contents stop the operation. The PK authenticated wrapper is valid for
Setup Mode preparation only; it is not signed by HP's private PK.

This HP deferred SetupMode's change until reboot during the original procedure.
Exact readback followed by SetupMode=1 therefore means **reboot and verify**,
not "repeat enrollment" or "write SetupMode". Partial retries accept only already
matching databases or the originally backed-up contents.

### 3. Check persistence, then manually enable Secure Boot

`./cookbook enable`

Requires another boot, exact database persistence and attributes 0x27, SetupMode=0,
and Secure Boot still disabled. Schedules the custom entry. Enter firmware settings
on the next manual restart and enable Secure Boot **without loading default keys**.

### 4. Validate enforcement, finalize and append dbx, then reboot

`./cookbook finish --apply-dbx`

Requires another boot through the custom entry with SecureBoot=1/SetupMode=0,
kernel lockdown, working NVIDIA, unchanged module identity, signed loaders/kernel,
and original-file integrity. Prepends the custom entry to BootOrder while retaining
other entries. Appends the pinned authenticated dbx update only if needed, checks
all preexisting/requested entries remain, and schedules a safe custom BootNext.

This reduces manual actions by combining finalization and the explicitly requested
update. The final reboot tests the updated chain; there is no extra default-only
reboot. BootOrder readback is checked, but BootNext scheduling does not independently
prove firmware will always honor BootOrder on later boots.

### 5. Verify the final reboot

`./cookbook verify`

Requires a new boot, custom entry first/current, BootNext absent, Secure Boot and
lockdown active, working NVIDIA, intact originals, and persisted revocation entries.
Produces a small schema-controlled `shareable-report.json` for manual review.
That report excludes account identifiers, disk IDs, local certificate fingerprints,
paths and raw logs. It does not attest to complete TPM logging.

## Failure handling

Every command stops on unexpected state. Checkpoints record boot IDs, ESP identity,
input/code hashes and partial-operation state privately. A checkpoint is never a
substitute for checking live firmware. State is locked against concurrent runs.
Do not edit checkpoints to bypass checks or pull changed code mid-deployment.

The local manifest is an integrity checkpoint, not a defense against an attacker
who can modify your checkout and state. Run only reviewed code on a trusted system.
An interrupted key-pair creation intentionally requires inspection rather than
automatically creating a replacement pair.

Until finalization, keep selecting the custom entry. Original Ubuntu shim 15.8 may
still hit the initial TPM-full failure even with signature enforcement disabled.
