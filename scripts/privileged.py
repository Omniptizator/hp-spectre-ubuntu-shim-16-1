#!/usr/bin/env python3
"""Explicit privileged operations. Never reboot, clear keys, or overwrite Ubuntu."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

from common import (Context, ESP, FILES, LABEL, LOADER, TARGET, boot_id, boot_number,
                    boot_order, digest, find_entry, next_is_safe, preflight, read_command,
                    require, variable)
from deployment import (check_manifest, current_entry, databases, final_dbx, module_identity,
                        original_files, secure_boot, staged)
from efi_formats import entry_set
from pipeline import authenticated_payload


def owned_write(ctx, relative, data):
    p = ctx.file(relative)
    p.write_bytes(data)
    os.chmod(p, 0o600)
    os.chown(p, ctx.uid, int(os.environ["SUDO_GID"]))


def snapshot(ctx):
    ctx.require_phase("preparing")
    require(variable("SecureBoot") == b"\0" and variable("SetupMode") == b"\1" and variable("PK") is None,
            "Preparation requires Secure Boot disabled, Setup Mode active, and no PK; no keys are cleared automatically")
    pending = variable("BootNext")
    known = entry(ctx)
    require(pending is None or ctx.file("backup/snapshot.json").exists() and
            known is not None and next_is_safe(pending, known), "A different BootNext operation is already pending")
    indications = variable("OsIndications")
    require(indications is None or int.from_bytes(indications, "little") == 0,
            "Firmware OS indications are pending; inspect before deployment")
    require(not any((ESP / "EFI/UpdateCapsule").glob("*")), "Firmware capsule files are pending")
    require(not any((ESP / "EFI/ubuntu/fw").glob("*")), "Ubuntu firmware capsule files are pending")
    require((ESP / "EFI/ubuntu/grub.cfg").is_file(), "Existing Ubuntu GRUB redirect is missing")
    record = ctx.file("backup/snapshot.json")
    variables = {name: (value.hex() if (value := variable(name)) is not None else None)
                 for name in ("PK", "KEK", "db", "dbx", "BootOrder")}
    if record.exists():
        existing = json.loads(record.read_text())
        require(existing["variables"] == variables, "Firmware state changed since backup")
        original_files(ctx)
        return
    originals = {}
    directories = [p for p in (ESP / "EFI/ubuntu", ESP / "EFI/BOOT") if p.exists()]
    for directory in directories:
        for path in directory.rglob("*"):
            require(not path.is_symlink(), "Unexpected symlink in original ESP directory")
            if path.is_file():
                originals[str(path.relative_to(ESP))] = digest(path.read_bytes())
    archive = ctx.file("backup/original-esp.tar")
    with tarfile.open(archive, "w") as out:
        for directory in directories:
            out.add(directory, arcname=str(directory.relative_to(ESP)))
    os.chown(archive, ctx.uid, int(os.environ["SUDO_GID"]))
    owned_write(ctx, "backup/grub.cfg", (ESP / "EFI/ubuntu/grub.cfg").read_bytes())
    owned_write(ctx, "backup/kernel.efi", Path("/boot/vmlinuz-" + os.uname().release).read_bytes())
    owned_write(ctx, "backup/boot-entries.txt", read_command(["efibootmgr", "-v"]).encode())
    owned_write(ctx, "backup/snapshot.json", json.dumps({
        "variables": variables, "original_files": originals,
        "archive_sha256": digest(archive.read_bytes()),
        "baseline": "readable state after any manual key clearing; not a pre-clear backup",
    }, indent=2).encode() + b"\n")
    os.sync()


def entry(ctx):
    return find_entry(read_command(["efibootmgr", "-v"]), ctx.state["esp"]["partuuid"])


def select_next(number):
    require(next_is_safe(variable("BootNext"), number), "Refusing to replace another pending BootNext")
    subprocess.run(["efibootmgr", "--bootnext", number], check=True)
    require(boot_number(variable("BootNext")) == int(number, 16), "BootNext readback mismatch")


def receipt(ctx, number):
    owned_write(ctx, "operation.json", json.dumps({"entry": number, "boot_id": boot_id()}).encode())


def stage(ctx):
    ctx.require_phase("preparing")
    require(variable("SecureBoot") == b"\0" and variable("SetupMode") == b"\1" and variable("PK") is None,
            "Unexpected firmware state before staging")
    check_manifest(ctx)
    module_identity(ctx)
    original_files(ctx)
    before = variable("BootOrder")
    initial = bytes.fromhex(json.loads(ctx.file("backup/snapshot.json").read_text())["variables"]["BootOrder"])
    require(before == initial, "BootOrder changed during preparation")
    number = entry(ctx)
    require(variable("BootNext") is None or number is not None and next_is_safe(variable("BootNext"), number),
            "Another BootNext operation is pending")
    require(not TARGET.is_symlink(), "Unexpected target symlink")
    if TARGET.exists():
        require({p.name for p in TARGET.iterdir()} <= set(FILES), "Unfamiliar files in staging directory")
        for name in FILES:
            if (TARGET / name).exists():
                require((TARGET / name).read_bytes() == ctx.file("artifacts/" + name).read_bytes(),
                        "Refusing to overwrite a different staged loader")
    else:
        required_bytes = sum(ctx.file("artifacts/" + name).stat().st_size for name in FILES)
        require(shutil.disk_usage(ESP).free > required_bytes + 1024 * 1024, "Insufficient ESP space")
        TARGET.mkdir()
    for name in FILES:
        shutil.copyfile(ctx.file("artifacts/" + name), TARGET / name)
    os.sync()
    staged(ctx)
    if number is None:
        identity = ctx.state["esp"]
        subprocess.run(["efibootmgr", "--create-only", "--disk", identity["disk"], "--part", identity["part"],
                        "--label", LABEL, "--loader", LOADER], check=True)
        number = entry(ctx)
    require(number is not None and variable("BootOrder") == before, "Boot entry creation changed BootOrder; inspect")
    receipt(ctx, number)
    select_next(number)
    print("Staged separate loaders; existing Ubuntu/fallback files and firmware trust preserved.")


def write_setup(ctx, name, filename):
    raw = ctx.file("trust/" + filename).read_bytes()
    expected = authenticated_payload(raw)[1] if name == "PK" else raw
    actual = variable(name)
    if actual == expected:
        return
    require(variable("SecureBoot") == b"\0" and variable("SetupMode") == b"\1",
            "Writing trust requires Secure Boot disabled and Setup Mode active")
    original = json.loads(ctx.file("backup/snapshot.json").read_text())["variables"][name]
    require(actual == (bytes.fromhex(original) if original is not None else None),
            "Unexpected existing database; refusing replacement")
    if actual:
        require(entry_set(actual) <= entry_set(expected), "Trust write would remove existing entries")
    args = ["efi-updatevar"] + ([] if name == "PK" else ["-e"])
    subprocess.run([*args, "-f", ctx.file("trust/" + filename), name], check=True)
    require(variable(name) == expected, "Firmware database readback mismatch; stop")


def enroll(ctx):
    ctx.require_phase("enrolling")
    check_manifest(ctx)
    staged(ctx)
    number = current_entry(ctx)
    module_identity(ctx)
    original_files(ctx)
    require(variable("SecureBoot") == b"\0", "Keep Secure Boot disabled during enrollment")
    snapshot = json.loads(ctx.file("backup/snapshot.json").read_text())["variables"]
    # Validate the whole batch before starting; still recheck each individual write.
    planned = (("KEK", "prepared-KEK.esl"), ("db", "prepared-db.esl"),
               ("dbx", "prepared-dbx.esl"), ("PK", "factory-PK.auth"))
    for name, filename in planned:
        raw = ctx.file("trust/" + filename).read_bytes()
        expected = authenticated_payload(raw)[1] if name == "PK" else raw
        previous = bytes.fromhex(snapshot[name]) if snapshot[name] is not None else None
        actual = variable(name)
        require(actual in (previous, expected), "Unexpected database before enrollment; no writes started")
        if actual != expected:
            require(variable("SetupMode") == b"\1", "Incomplete enrollment outside Setup Mode; stop")
    select_next(number)
    for name, filename in planned:
        write_setup(ctx, name, filename)
    databases(ctx)
    require(variable("SetupMode") in (b"\0", b"\1"), "Unrecognized SetupMode")
    print("All trust databases read back exactly. Restart required to validate persistence/mode transition.")
    os.sync()


def schedule(ctx):
    ctx.require_phase("enrolled", "enable-scheduled")
    check_manifest(ctx)
    staged(ctx)
    databases(ctx)
    require(variable("SecureBoot") == b"\0" and variable("SetupMode") == b"\0",
            "Expected completed mode transition with Secure Boot still disabled")
    number = current_entry(ctx)
    module_identity(ctx)
    select_next(number)


def finish(ctx):
    ctx.require_phase("finishing")
    number = secure_boot(ctx, updated=True)
    # A partial retry may already have the update; all earlier revocations must remain.
    require(entry_set(bytes.fromhex(ctx.state["dbx_before"])) <= entry_set(variable("dbx") or b""),
            "Revocations disappeared since finish was requested")
    require(entry_set(ctx.file("trust/prepared-dbx.esl").read_bytes()) <= entry_set(variable("dbx") or b""),
            "Prepared baseline revocations missing")
    order = boot_order(variable("BootOrder"))
    desired = [int(number, 16)] + [value for value in order if value != int(number, 16)]
    subprocess.run(["efibootmgr", "--bootorder", ",".join(f"{n:04X}" for n in desired)], check=True)
    require(boot_order(variable("BootOrder")) == desired, "BootOrder readback mismatch")
    select_next(number)
    additions = entry_set(ctx.file("trust/microsoft-dbx-20260402.esl").read_bytes())
    if not additions <= entry_set(variable("dbx") or b""):
        subprocess.run(["efi-updatevar", "-a", "-f", ctx.file("trust/microsoft-dbx-20260402.auth"), "dbx"], check=True)
    count = final_dbx(ctx)
    print(f"Default entry finalized; authenticated dbx update verified ({count} unique revocations).")
    os.sync()


def verify(ctx):
    ctx.require_phase("finished", "complete")
    number = secure_boot(ctx, updated=True)
    require(boot_order(variable("BootOrder"))[0] == int(number, 16) and variable("BootNext") is None,
            "Default entry/BootNext state is unexpected")
    count = final_dbx(ctx)
    print(f"PASS: Secure Boot, lockdown, NVIDIA, originals and {count} revocations verified.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("snapshot", "stage", "enroll", "schedule", "finish", "verify"))
    parser.add_argument("--state", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    require(os.geteuid() == 0 and "SUDO_UID" in os.environ and int(os.environ["SUDO_UID"]) != 0,
            "Invoke through the unprivileged cookbook entry point")
    preflight()
    ctx = Context(args.state)
    ctx.bind()
    globals()[args.action](ctx)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"Stopped: {error}") from None
