"""Exercise the actual newly signed loaders in isolated, networkless OVMF VMs."""

import concurrent.futures
import json
import shutil
import struct
import subprocess

from common import ROOT, require


def fixtures(ctx):
    prod, vm = ctx.file("build/production"), ctx.file("vm-test")
    includes = prod / "gnu-efi/inc"
    for name, source in (("probe", "probe.c"), ("tpm-full", "tpm_full.c")):
        ctx.run(["gcc-14", "-O2", "-fpic", "-fshort-wchar", "-mno-red-zone", "-fno-stack-protector",
                 "-fno-strict-aliasing", "-maccumulate-outgoing-args", "-DEFI_FUNCTION_WRAPPER",
                 "-I" + str(includes), "-I" + str(includes / "x86_64"), "-I" + str(includes / "protocol"),
                 "-I" + str(ctx.file("src/shim/include")), "-Wall", "-Wextra", "-Werror",
                 "-c", ROOT / "tests/ovmf" / source, "-o", vm / (name + "-base.o")])
    for name, component in (("probe", "vm.probe,1"), ("revoked", "grub,1"),
                             ("forbidden", "vm.forbidden,1"), ("tpm-full", "vm.tpmfull,1")):
        sbat = vm / (name + ".csv")
        sbat.write_text("sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\n"
                        + component + ",VM-only fixture,fixture,1,https://github.com/rhboot/shim\n")
        obj, shared, unsigned = (vm / (name + suffix) for suffix in (".o", ".so", "-unsigned.efi"))
        ctx.run(["objcopy", "--add-section", ".sbat=" + str(sbat), "--set-section-flags",
                 ".sbat=contents,alloc,load,readonly,data", vm / ("tpm-full-base.o" if name == "tpm-full" else "probe-base.o"), obj])
        ctx.run(["ld", "--hash-style=sysv", "--no-undefined", "-nostdlib", "-znocombreloc", "-T",
                 prod / "elf_x86_64_efi.lds", "-shared", "-Bsymbolic", prod / "gnu-efi/x86_64/gnuefi/crt0-efi-x86_64.o",
                 obj, prod / "lib/string.o", "-L" + str(prod / "gnu-efi/x86_64/lib"),
                 "-L" + str(prod / "gnu-efi/x86_64/gnuefi"), "-lefi", "-lgnuefi", "-o", shared])
        ctx.run(["objcopy", "-O", "efi-app-x86_64", "--file-alignment", "0x1000",
                 *[arg for section in (".text", ".sdata", ".data", ".dynamic", ".rodata", ".rel*", ".rela*",
                                       ".dyn", ".reloc", ".eh_frame", ".sbat") for arg in ("-j", section)], shared, unsigned])
        ctx.run([prod / "post-process-pe", unsigned])
        stem = "efi-signing" if name == "tpm-full" else "shim-helper"
        ctx.run(["sbsign", "--key", ctx.file(f"keys/{stem}.key"), "--cert", ctx.file(f"trust/{stem}.pem"),
                 "--output", vm / (name + ".efi"), unsigned])
    ctx.run(["hash-to-efi-sig-list", vm / "forbidden.efi", vm / "forbidden-hash.esl"])


def scenario(ctx, name):
    from virt.firmware.efi import efivar
    from virt.firmware.varstore import edk2

    vm = ctx.file("vm-test")
    directory = vm / name
    esp = directory / "esp"
    boot = esp / "EFI/BOOT"
    boot.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ctx.file("artifacts/shimx64.efi"), boot / "BOOTX64.EFI")
    if name == "tpm-full":
        shutil.copyfile(ctx.file("artifacts/shimx64.efi"), boot / "shimx64.efi")
        shutil.copyfile(vm / "tpm-full.efi", boot / "BOOTX64.EFI")
    shutil.copyfile(ctx.file("artifacts/mmx64.efi"), boot / "mmx64.efi")
    canonical = name == "canonical-grub"
    shutil.copyfile(ctx.file("artifacts/grubx64.efi") if canonical else vm / "probe.efi", boot / "grubx64.efi")
    for source, target in ((ctx.file("artifacts/grubx64.efi"), "canonical.efi"),
                           (ctx.file("artifacts/mmx64.efi"), "manager.efi"),
                           (vm / "probe-unsigned.efi", "unsigned.efi"), (vm / "revoked.efi", "revoked.efi"),
                           (vm / "forbidden.efi", "forbidden.efi")):
        shutil.copyfile(source, esp / target)
    tampered = bytearray(ctx.file("artifacts/grubx64.efi").read_bytes())
    pe = struct.unpack_from("<I", tampered, 60)[0]
    start = pe + 24 + struct.unpack_from("<H", tampered, pe + 20)[0]
    for i in range(struct.unpack_from("<H", tampered, pe + 6)[0]):
        offset = start + 40 * i
        if tampered[offset:offset + 8].rstrip(b"\0") == b".text":
            raw = struct.unpack_from("<I", tampered, offset + 20)[0]
            tampered[raw + 64] ^= 1
            break
    else:
        raise RuntimeError("No GRUB text section")
    (esp / "tampered.efi").write_bytes(tampered)
    config = "serial --unit=0 --speed=115200\nterminal_output serial\necho COOKBOOK_CANONICAL_GRUB_STARTED\nhalt\n"
    for folder in (boot, esp / "EFI/ubuntu", esp / "boot/grub", esp / "grub"):
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "grub.cfg").write_text(config)
    (esp / "grub.cfg").write_text(config)
    store = edk2.Edk2VarStore("/usr/share/OVMF/OVMF_VARS_4M.fd")
    variables = store.get_varlist()
    for variable, filename in (("PK", "factory-PK.esl"), ("KEK", "prepared-KEK.esl"),
                               ("db", "prepared-db.esl"), ("dbx", "prepared-dbx.esl")):
        data = ctx.file("trust/" + filename).read_bytes()
        if variable == "db" and name == "untrusted-shim":
            from efi_formats import X509_GUID, make_signature_list, signature_lists
            local = ctx.file("trust/efi-signing.der").read_bytes()
            data = b"".join(make_signature_list(kind, filtered, header)
                            for kind, header, entries in signature_lists(data)
                            if (filtered := [(owner, value) for owner, value in entries
                                             if not (kind == X509_GUID and value == local)]))
        if variable == "dbx":
            if name == "latest-dbx":
                data += ctx.file("trust/microsoft-dbx-20260402.esl").read_bytes()
            data += (vm / "forbidden-hash.esl").read_bytes()
        variables[variable] = efivar.EfiVar(variable, data=data)
        variables[variable].update_time(efivar.initial_ts)
    variables.enable_secureboot()
    varfile = directory / "OVMF_VARS.fd"
    store.write_varstore(str(varfile), variables)
    serial, debug = directory / "serial.log", directory / "debug.log"
    # Never accept stale successful output from a previous execution.
    serial.write_text("")
    debug.write_text("")
    command = ["qemu-system-x86_64", "-machine", "q35,smm=on", "-accel", "tcg", "-m", "256",
               "-global", "driver=cfi.pflash01,property=secure,value=on",
               "-drive", "if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
               "-drive", f"if=pflash,format=raw,unit=1,file={varfile}",
               "-drive", f"if=none,id=esp,format=raw,readonly=on,file=fat:ro:{esp}",
               "-device", "virtio-blk-pci,drive=esp", "-nic", "none", "-display", "none",
               "-serial", f"file:{serial}", "-debugcon", f"file:{debug}",
               "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-no-reboot"]
    with (directory / "qemu.log").open("w") as log:
        try:
            result = subprocess.run(command, stdout=log, stderr=log, timeout=45 if name == "untrusted-shim" else 90)
            returncode = result.returncode
        except subprocess.TimeoutExpired:
            returncode = None
    serial_text, debug_text = serial.read_text(errors="replace"), debug.read_text(errors="replace")
    if name == "untrusted-shim":
        passed = "PROBE START" not in debug_text and any(
            s in serial_text.lower() for s in ("access denied", "security violation"))
    elif canonical:
        passed = "COOKBOOK_CANONICAL_GRUB_STARTED" in serial_text
    else:
        passed = returncode == 1 and "ALL PASS" in debug_text and "FAIL" not in debug_text
        if name == "tpm-full":
            passed = passed and "INJECT EFI_VOLUME_FULL" in debug_text
    return {"scenario": name, "passed": passed, "qemu_returncode": returncode}


def run_all(ctx):
    fixtures(ctx)
    names = ("baseline-dbx", "latest-dbx", "canonical-grub", "untrusted-shim", "tpm-full")
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda name: scenario(ctx, name), names))
    ctx.file("artifacts/vm-results.json").write_text(json.dumps(results, indent=2) + "\n")
    for result in results:
        print(result["scenario"] + ": " + ("PASS" if result["passed"] else "FAIL"), flush=True)
    require(all(result["passed"] for result in results), "VM checks failed; do not deploy")
