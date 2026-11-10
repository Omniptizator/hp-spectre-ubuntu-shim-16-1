"""Checks used both before and inside narrowly scoped sudo operations."""

import json
import os
from pathlib import Path

from common import (ESP, FILES, GLOBAL, MOK_GUID, TARGET, boot_number, boot_order,
                    certificate_in_mok, code_digest, digest, find_entry, manifest,
                    mokutil_reports_enrolled, read_command, require, variable)
from efi_formats import entry_set
import subprocess


def check_manifest(ctx):
    audit = json.loads(ctx.file("artifacts/audit.json").read_text())
    require(audit["code"] == code_digest() and audit["production_c_h_unmodified"] is True and
            audit["upstream_tests"] == 118 and audit["vm_scenarios"] == 5 and
            audit.get("kernel_backup_verified") is True and ctx.state.get("kind") != "vm-only",
            "Build/test audit does not match this cookbook")
    raw = ctx.file("artifacts/manifest.json").read_bytes()
    require(digest(raw) == audit["manifest_sha256"], "Manifest changed after audit")
    hashes = json.loads(raw)
    required = {"artifacts/" + n for n in FILES} | {
        "trust/prepared-KEK.esl", "trust/prepared-db.esl", "trust/prepared-dbx.esl",
        "trust/factory-PK.esl", "trust/factory-PK.auth", "trust/microsoft-dbx-20260402.auth",
        "trust/microsoft-dbx-20260402.esl", "trust/efi-signing.pem", "trust/shim-helper.pem",
        "trust/canonical-uefi-ca.pem",
    }
    require(required <= hashes.keys(), "Incomplete deployment manifest")
    for name, expected in hashes.items():
        require(digest(ctx.file(name).read_bytes()) == expected, "Changed local deployment input")
    # Hashes are local integrity checkpoints, not an independent signing authority.
    for item in manifest()["downloads"]:
        require(digest(ctx.file("trust/" + item["name"]).read_bytes()) == item["sha256"],
                "Pinned public input no longer matches")
    for name, cert in (("shimx64.efi", "efi-signing"), ("mmx64.efi", "shim-helper"),
                       ("grubx64.efi", "canonical-uefi-ca")):
        ctx.run(["sbverify", "--cert", ctx.file("trust/" + cert + ".pem"), ctx.file("artifacts/" + name)])
    ctx.run(["sbverify", "--cert", ctx.file("trust/canonical-uefi-ca.pem"), "/boot/vmlinuz-" + os.uname().release])


def staged(ctx):
    require(TARGET.is_dir(), "Staged boot directory is missing")
    require({p.name for p in TARGET.iterdir()} == set(FILES), "Unexpected staged-directory contents")
    for name in FILES:
        require(not (TARGET / name).is_symlink() and
                (TARGET / name).read_bytes() == ctx.file("artifacts/" + name).read_bytes(),
                "Staged artifact missing or changed")


def current_entry(ctx):
    entry = find_entry(read_command(["efibootmgr", "-v"]), ctx.state["esp"]["partuuid"])
    require(entry is not None, "Cookbook boot entry is missing")
    if "entry" in ctx.state:
        require(entry == ctx.state["entry"], "Cookbook boot number changed unexpectedly")
    require(boot_number(variable("BootCurrent")) == int(entry, 16),
            "Not booted through the cookbook entry")
    return entry


def module_identity(ctx, capture=False):
    from cryptography import x509
    certificate_path = Path("/var/lib/shim-signed/mok/MOK.der")
    result = subprocess.run(["mokutil", "--ignore-keyring", "--test-key", certificate_path],
                            capture_output=True, text=True, env={**os.environ, "LC_ALL": "C"})
    require(mokutil_reports_enrolled(result, certificate_path), "MOK enrollment not explicitly confirmed")
    certificate = certificate_path.read_bytes()
    runtime = variable("MokListRT", MOK_GUID)
    require(runtime is not None and certificate_in_mok(certificate, runtime),
            "Exact module certificate is absent from MokListRT")
    serial = format(x509.load_der_x509_certificate(certificate).serial_number, "X")
    module_key = read_command(["modinfo", "-F", "sig_key", "nvidia"]).strip().replace(":", "").upper().lstrip("0")
    require(module_key == serial.lstrip("0"), "NVIDIA signing identity does not match enrolled certificate")
    require("nvidia " in Path("/proc/modules").read_text(), "NVIDIA kernel module is not loaded")
    identity = {"certificate_sha256": digest(certificate), "module_key": module_key}
    if capture:
        if "mok" in ctx.state:
            require(ctx.state["mok"] == identity, "Module identity changed during preparation")
        ctx.state["mok"] = identity
        ctx.save()
    else:
        require(ctx.state.get("mok") == identity, "Module identity changed since preparation")
    ctx.run(["nvidia-smi"], log="nvidia.log")


def databases(ctx, include_dbx=True):
    for name, filename in (("PK", "factory-PK.esl"), ("KEK", "prepared-KEK.esl"),
                           ("db", "prepared-db.esl"), ("dbx", "prepared-dbx.esl")):
        if name == "dbx" and not include_dbx:
            continue
        require(variable(name) == ctx.file("trust/" + filename).read_bytes(),
                "Enrolled database differs from approved payload: " + name)
        from common import DATABASE, EFIVARS
        guid = DATABASE if name in ("db", "dbx") else GLOBAL
        require(int.from_bytes((EFIVARS / f"{name}-{guid}").read_bytes()[:4], "little") == 0x27,
                "Unexpected database attributes: " + name)


def original_files(ctx):
    snapshot = json.loads(ctx.file("backup/snapshot.json").read_text())
    for relative, expected in snapshot["original_files"].items():
        path = ESP / relative
        require(path.is_file() and digest(path.read_bytes()) == expected, "Original ESP file changed; review updates before proceeding")


def secure_boot(ctx, *, updated=False):
    check_manifest(ctx)
    staged(ctx)
    entry = current_entry(ctx)
    require(variable("SecureBoot") == b"\1" and variable("SetupMode") == b"\0",
            "Secure Boot must be enabled outside Setup Mode")
    databases(ctx, include_dbx=not updated)
    lockdown = Path("/sys/kernel/security/lockdown").read_text()
    require("[integrity]" in lockdown or "[confidentiality]" in lockdown, "Kernel lockdown is inactive")
    module_identity(ctx)
    original_files(ctx)
    return entry


def final_dbx(ctx):
    before = bytes.fromhex(ctx.state["dbx_before"])
    additions = ctx.file("trust/microsoft-dbx-20260402.esl").read_bytes()
    after = variable("dbx")
    require(after is not None and entry_set(before) | entry_set(additions) <= entry_set(after),
            "Updated dbx is missing preexisting or requested revocations")
    return len(entry_set(after))
