"""Shared read-only checks and private state; no firmware write functions."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tomllib

from efi_formats import X509_GUID, signature_lists

ROOT = Path(__file__).resolve().parent.parent
EFIVARS = Path("/sys/firmware/efi/efivars")
ESP = Path("/boot/efi")
GLOBAL = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
DATABASE = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
MOK_GUID = "605dab50-e046-4300-abb6-3dd810dd8b23"
LABEL = "Shim16 cookbook"
LOADER = "\\EFI\\shim16-cookbook\\shimx64.efi"
TARGET = ESP / "EFI/shim16-cookbook"
FILES = ("shimx64.efi", "mmx64.efi", "grubx64.efi", "grub.cfg")


def require(value, message):
    if not value:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def manifest():
    return tomllib.loads((ROOT / "manifests/upstream-inputs.toml").read_text())


def code_digest():
    files = [ROOT / "cookbook"]
    for directory in ("scripts", "manifests", "patches", "tests", "config"):
        files += sorted(p for p in (ROOT / directory).rglob("*")
                        if p.is_file() and "__pycache__" not in p.parts)
    return digest(b"".join(str(p.relative_to(ROOT)).encode() + b"\0" + p.read_bytes()
                           for p in files))


def variable(name, guid=None):
    guid = guid or (DATABASE if name in ("db", "dbx") else GLOBAL)
    p = EFIVARS / f"{name}-{guid}"
    if not p.exists():
        return None
    data = p.read_bytes()
    require(len(data) >= 4, "Truncated firmware variable")
    return data[4:]


def boot_id():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def boot_number(data):
    require(data is not None and len(data) == 2, "Invalid boot number")
    return struct.unpack("<H", data)[0]


def boot_order(data):
    require(data is not None and len(data) >= 2 and len(data) % 2 == 0,
            "Missing or malformed BootOrder")
    return list(struct.unpack("<" + "H" * (len(data) // 2), data))


def find_entry(text, partuuid):
    matches = []
    for line in text.splitlines():
        m = re.match(r"^Boot([0-9A-Fa-f]{4})\*?\s+" + re.escape(LABEL) + r"\s+", line)
        if m:
            require(LOADER.lower() in line.lower() and
                    (",GPT," + partuuid + ",").lower() in line.lower(),
                    "Boot label belongs to an unexpected loader/device")
            matches.append(m.group(1).upper())
    require(len(matches) <= 1, "Duplicate cookbook boot entries")
    return matches[0] if matches else None


def next_is_safe(existing, entry):
    return existing is None or boot_number(existing) == int(entry, 16)


def rebooted(previous, current):
    require(bool(previous) and previous != current, "A manual reboot is required before this phase")


def mokutil_reports_enrolled(result, path):
    return result.returncode in (0, 1) and result.stdout.strip() == f"{path} is already enrolled"


def certificate_in_mok(certificate, payload):
    return any(kind == X509_GUID and value == certificate
               for kind, _, entries in signature_lists(payload) for _, value in entries)


def preflight():
    expected = {"sys_vendor": "HP", "board_name": "82C1", "bios_version": "F.42",
                "product_name": "HP Spectre x360 Convertible 15-bl0XX"}
    for name, value in expected.items():
        require(Path("/sys/class/dmi/id", name).read_text().strip() == value,
                f"Unsupported hardware/firmware: {name}")
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines()
                   if "=" in line and not line.startswith("#"))
    require(release.get("ID", "").strip('"') == "ubuntu" and
            release.get("VERSION_ID", "").strip('"') == "26.04" and
            os.uname().machine == "x86_64", "Only Ubuntu 26.04 x86_64 is reviewed")
    require(EFIVARS.is_dir(), "UEFI runtime variables are unavailable")


def read_command(args):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True,
                            env={**os.environ, "LC_ALL": "C"}, check=False)
    require(result.returncode == 0, f"Read-only check failed: {args[0]}")
    return result.stdout


def esp_identity():
    mounts = json.loads(read_command(["findmnt", "--json", "--target", ESP]))["filesystems"]
    require(len(mounts) == 1 and mounts[0]["target"] == str(ESP) and
            mounts[0]["fstype"] == "vfat", "ESP must be a dedicated vfat mount at /boot/efi")
    source = str(Path(mounts[0]["source"]).resolve())
    require(re.fullmatch(r"/dev/nvme[0-9]+n[0-9]+p[0-9]+", source),
            "Only the reviewed internal NVMe ESP layout is supported")
    block = json.loads(read_command(["lsblk", "--json", "--paths", "--nodeps", "--output",
                                    "PATH,TYPE,PKNAME,PARTTYPE,PARTUUID", source]))["blockdevices"]
    require(len(block) == 1 and block[0]["type"] == "part" and
            block[0]["parttype"].lower() == "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
            "Expected a GPT EFI System Partition")
    part = Path("/sys/class/block", Path(source).name, "partition").read_text().strip()
    disk = block[0]["pkname"]
    require(disk and str(disk).startswith("/dev/nvme") and part.isdigit() and
            bool(block[0]["partuuid"]), "Cannot establish unique ESP identity")
    return {"source": source, "disk": disk, "part": part, "partuuid": block[0]["partuuid"]}


class Context:
    def __init__(self, path, create=False):
        supplied = Path(path).expanduser().absolute()
        require(not any(p.is_symlink() for p in (supplied, *supplied.parents)),
                "Private state path must not contain symlinks")
        self.path = supplied.resolve()
        require(self.path != ROOT and ROOT not in self.path.parents and self.path not in ROOT.parents,
                "Private state must be separate from the public repository")
        self.uid = int(os.environ.get("SUDO_UID", os.getuid()))
        if create:
            self.path.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = self.path.stat()
        require(info.st_uid == self.uid and stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o077,
                "Private state must be owned by the invoking user and mode 0700")
        self.statefile = self.path / "checkpoint.json"
        require(not self.statefile.is_symlink(), "Checkpoint must not be a symlink")
        if self.statefile.exists():
            checkpoint_info = self.statefile.stat()
            require(checkpoint_info.st_uid == self.uid and not checkpoint_info.st_mode & 0o077,
                    "Checkpoint ownership/permissions are unsafe")
        self.state = json.loads(self.statefile.read_text()) if self.statefile.exists() else {}

    def file(self, relative):
        p = self.path / relative
        require(not Path(relative).is_absolute() and ".." not in Path(relative).parts,
                "Unsafe private-state path")
        require(not any(x.is_symlink() for x in (p, *p.parents) if x != self.path.parent),
                "Unexpected symlink in private state")
        return p

    def save(self):
        p = self.file("checkpoint.new")
        p.write_text(json.dumps(self.state, indent=2) + "\n")
        p.chmod(0o600)
        p.replace(self.statefile)

    def run(self, args, *, log="commands.log", env=None, cwd=None):
        with self.file(log).open("a") as out:
            result = subprocess.run([str(a) for a in args], stdout=out, stderr=subprocess.STDOUT,
                                    env={**os.environ, "LC_ALL": "C", **(env or {})}, cwd=cwd)
        require(result.returncode == 0, f"Command failed: {Path(str(args[0])).name}; inspect the private {log}")

    def sudo(self, action):
        subprocess.run(["sudo", "--", "/usr/bin/python3", "-B", ROOT / "scripts/privileged.py",
                        action, "--state", self.path], check=True)

    def bind(self):
        identity = esp_identity()
        machine = digest(Path("/etc/machine-id").read_bytes())
        if self.state:
            require(self.state.get("esp") == identity and self.state.get("machine") == machine,
                    "Private checkpoint belongs to another system or ESP")
            require(self.state.get("code") == code_digest(),
                    "Cookbook code/inputs changed during deployment; review before continuing")
        else:
            self.state = {"esp": identity, "machine": machine, "code": code_digest(), "phase": "new"}
            self.save()

    def require_phase(self, *phases):
        require(self.state.get("phase") in phases, "Unexpected workflow state; use ./cookbook status")

    def checkpoint(self, phase):
        self.state.update(phase=phase, boot_id=boot_id())
        self.save()

    def new_boot(self):
        rebooted(self.state.get("boot_id"), boot_id())
