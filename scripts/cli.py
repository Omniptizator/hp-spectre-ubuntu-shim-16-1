#!/usr/bin/env python3
"""Five user-facing deployment phases, separated only by required firmware actions."""

import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

from common import Context, ROOT, boot_id, digest, preflight, require, variable


def prepare(ctx, args):
    import pipeline
    from deployment import module_identity

    ctx.require_phase("new", "preparing")
    require(args.recovery_ready or ctx.state.get("recovery_ready"),
            "Read docs/recovery.md, prepare/test recovery media, then pass --recovery-ready")
    require(args.accept_reconstructed_trust or ctx.state.get("accept_reconstructed_trust"),
            "Review docs/cookbook.md trust policy, then pass --accept-reconstructed-trust")
    require(variable("SecureBoot") == b"\0" and variable("SetupMode") == b"\1" and variable("PK") is None,
            "This recovery workflow starts with Secure Boot disabled and PK absent in Setup Mode; existing deployments are not replayed")
    ctx.state.update(phase="preparing", recovery_ready=True, accept_reconstructed_trust=True)
    ctx.save()
    if args.install_dependencies:
        packages = tomllib.loads((ROOT / "manifests/dependencies.toml").read_text())["packages"]
        print("Installing the explicitly listed Ubuntu packages; normal interactive sudo/APT applies.", flush=True)
        subprocess.run(["sudo", "--", "apt-get", "update"], check=True)
        subprocess.run(["sudo", "--", "apt-get", "install", *packages], check=True)
    for program in ("gcc-14", "make", "git", "gpg", "openssl", "sbverify", "sbsign", "efi-updatevar",
                    "efibootmgr", "mokutil", "qemu-system-x86_64", "patch", "dos2unix", "pkg-config",
                    "sign-efi-sig-list", "hash-to-efi-sig-list", "objcopy", "ld", "nvidia-smi"):
        require(shutil.which(program), "Missing dependency; rerun prepare --install-dependencies")
    for module in ("cryptography", "pefile", "virt"):
        require(importlib.util.find_spec(module) is not None,
                "Missing Python dependency; rerun prepare --install-dependencies")
    for firmware in ("OVMF_CODE_4M.secboot.fd", "OVMF_VARS_4M.fd"):
        require(Path("/usr/share/OVMF", firmware).is_file(), "Missing reviewed OVMF firmware image")
    ctx.file("backup").mkdir(exist_ok=True, mode=0o700)
    module_identity(ctx, capture=True)
    ctx.sudo("snapshot")
    print("Fetching pinned inputs and verifying the upstream release.", flush=True)
    pipeline.fetch(ctx)
    print("Generating/reusing dedicated local signing keys and preparing reviewed trust.", flush=True)
    pipeline.prepare_keys(ctx)
    pipeline.trust(ctx, args.factory_inputs)
    print("Building and running upstream, local, signature/SBAT, and five isolated VM checks.", flush=True)
    subprocess.run([sys.executable, "-B", ROOT / "tests/run.py"], check=True)
    pipeline.build(ctx)
    from vm_test import run_all
    run_all(ctx)
    pipeline.audit(ctx)
    ctx.sudo("stage")
    operation = json.loads(ctx.file("operation.json").read_text())
    require(operation["boot_id"] == boot_id(), "Unexpected stage receipt")
    ctx.state["entry"] = operation["entry"]
    ctx.checkpoint("staged")
    print("Reboot 1 manually, with Secure Boot DISABLED. Select 'Shim16 cookbook' if needed.\n"
          "After Ubuntu returns: ./cookbook enroll")


def enroll(ctx, args):
    ctx.require_phase("staged", "enrolling")
    ctx.new_boot()
    ctx.state["phase"] = "enrolling"
    ctx.save()
    ctx.sudo("enroll")
    ctx.checkpoint("enrolled")
    print("Reboot 2 manually, with Secure Boot still DISABLED. Do not repeat enrollment or load factory keys.\n"
          "After Ubuntu returns: ./cookbook enable")


def enable(ctx, args):
    ctx.require_phase("enrolled", "enable-scheduled")
    if ctx.state["phase"] == "enrolled":
        ctx.new_boot()
    else:
        require(ctx.state["boot_id"] == boot_id(), "An enforcement test may already have occurred; run finish instead")
    ctx.sudo("schedule")
    ctx.checkpoint("enable-scheduled")
    print("Reboot 3 manually into firmware settings. ENABLE Secure Boot without loading factory/default keys.\n"
          "Boot 'Shim16 cookbook'. After Ubuntu returns: ./cookbook finish --apply-dbx")


def finish(ctx, args):
    ctx.require_phase("enable-scheduled", "finishing")
    ctx.new_boot()
    require(args.apply_dbx, "This phase requires explicit --apply-dbx consent for the pinned 20260402 update")
    before = variable("dbx")
    require(before is not None, "No baseline dbx; stop")
    if "dbx_before" not in ctx.state:
        ctx.state["dbx_before"] = before.hex()
    ctx.state["phase"] = "finishing"
    ctx.save()
    ctx.sudo("finish")
    ctx.checkpoint("finished")
    print("Reboot 4 manually, keeping Secure Boot ENABLED. Photograph any warning if useful.\n"
          "After Ubuntu returns: ./cookbook verify")


def verify(ctx, args):
    ctx.require_phase("finished", "complete")
    if ctx.state["phase"] == "finished":
        ctx.new_boot()
    ctx.sudo("verify")
    ctx.checkpoint("complete")
    report = {"model": "HP Spectre x360 15-bl012dx", "board": "82C1", "bios": "F.42",
              "shim": "16.1", "secure_boot": True, "lockdown_verified": True,
              "nvidia_verified": True, "dbx_update": "20260402",
              "original_esp_hashes_verified": True,
              "limitation": "Complete TPM measurement logging/attestation is not established"}
    ctx.file("shareable-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Complete. Only shareable-report.json is intended for manual public review/export.\n"
          "Keep all other private state private. Read docs/maintenance.md.")


def status(path):
    print("Read-only status; no ESP or firmware writes.")
    preflight()
    print("Model/firmware/OS profile: supported")
    print("Secure Boot:", {b"\0": "disabled", b"\1": "enabled"}.get(variable("SecureBoot"), "unknown"))
    print("Setup Mode:", {b"\0": "inactive", b"\1": "active"}.get(variable("SetupMode"), "unknown"))
    if Path(path).expanduser().exists():
        ctx = Context(path)
        print("Cookbook checkpoint:", ctx.state.get("phase", "absent"))
    else:
        print("No cookbook checkpoint. Do not use prepare to replay an existing working installation.")


def build_vm(ctx, args):
    """Read-only hardware inputs, synthetic redirect, fresh local keys; NEVER deployable state."""
    import pipeline
    from vm_test import run_all

    require(not ctx.state or ctx.state.get("kind") == "vm-only", "Use a separate empty state directory for VM testing")
    ctx.state.update(kind="vm-only", phase="vm-only")
    ctx.save()
    ctx.file("backup").mkdir(exist_ok=True, mode=0o700)
    ctx.file("backup/snapshot.json").write_text(json.dumps({"variables": {n: None for n in ("PK", "KEK", "db", "dbx")}}))
    ctx.file("backup/grub.cfg").write_text("search --file --set=root /boot/grub/grub.cfg\nconfigfile /boot/grub/grub.cfg\n")
    pipeline.fetch(ctx)
    pipeline.prepare_keys(ctx)
    pipeline.trust(ctx, args.factory_inputs)
    pipeline.build(ctx)
    run_all(ctx)
    pipeline.audit(ctx)
    print("PASS: clean-input build, 118 upstream tests, signatures/SBAT and five VM scenarios. No hardware writes.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "enroll", "enable", "finish", "verify", "status", "test"))
    parser.add_argument("--state", default=str(Path.home() / ".local/state/spectre-shim-cookbook"))
    parser.add_argument("--install-dependencies", action="store_true")
    parser.add_argument("--recovery-ready", action="store_true")
    parser.add_argument("--accept-reconstructed-trust", action="store_true")
    parser.add_argument("--apply-dbx", action="store_true")
    parser.add_argument("--build-vm", action="store_true", help="test only: read-only firmware inputs and isolated VMs; use separate --state")
    parser.add_argument("--factory-inputs", type=Path, help="directory of four public factory-*.esl inputs; all must match profile hashes")
    args = parser.parse_args()
    os.umask(0o077)
    require(os.geteuid() != 0, "Do not sudo ./cookbook; it requests sudo only for explicit privileged operations")
    os.environ.update(LC_ALL="C", TZ="UTC", PYTHONDONTWRITEBYTECODE="1")
    if args.phase == "status":
        return status(args.state)
    if args.phase == "test" and not args.build_vm:
        subprocess.run([sys.executable, "-B", ROOT / "tests/run.py"], check=True)
        subprocess.run([sys.executable, "-B", ROOT / "scripts/check_public.py"], check=True)
        return
    if args.phase != "test":
        preflight()
    ctx = Context(args.state, create=args.phase in ("prepare", "test"))
    # Lock the private workspace across the whole phase, including sudo and builds.
    flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW
    with os.fdopen(os.open(ctx.file("workflow.lock"), flags, 0o600), "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Another cookbook operation is running") from None
        if args.phase == "test":
            build_vm(ctx, args)
        else:
            ctx.bind()
            globals()[args.phase](ctx, args)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"Stopped: {error}") from None
