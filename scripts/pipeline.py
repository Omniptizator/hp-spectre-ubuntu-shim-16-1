"""Unprivileged fetching, local key preparation, build, and audit."""

import datetime
import io
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tarfile
import urllib.request
import uuid

from common import ROOT, EFIVARS, code_digest, digest, manifest, require, variable
from efi_formats import X509_GUID, entry_set, make_signature_list, pe_sections, signature_lists, union_lists


def save_input(path, data):
    if path.exists():
        require(path.read_bytes() == data, "Refusing to replace a different prepared input")
    else:
        path.write_bytes(data)


def download(url):
    require(url.startswith("https://"), "Downloads require HTTPS")
    with urllib.request.urlopen(url, timeout=60) as response:
        require(response.url.startswith("https://"), "Insecure redirect")
        data = response.read(32 * 1024 * 1024 + 1)
    require(len(data) <= 32 * 1024 * 1024, "Download exceeds size limit")
    return data


def checkout(ctx, name, url, ref, commit):
    target = ctx.file("src/" + name)
    if not target.exists():
        ctx.run(["git", "clone", "--no-checkout", "--depth", "1", "--branch", ref, url, target])
    actual = subprocess.check_output(["git", "-C", target, "rev-parse", "HEAD"], text=True).strip()
    if actual != commit:
        ctx.run(["git", "-C", target, "fetch", "--depth", "1", "origin", commit])
    ctx.run(["git", "-C", target, "checkout", "--detach", commit])
    require(subprocess.check_output(["git", "-C", target, "rev-parse", "HEAD"], text=True).strip() == commit,
            "Source commit mismatch")
    require(not subprocess.check_output(["git", "-C", target, "status", "--porcelain"], text=True),
            "Source checkout has local modifications")
    return target


def fetch(ctx):
    spec = manifest()
    for directory in ("src", "trust", "keys", "artifacts", "build", "gnupg", "vm-test"):
        ctx.file(directory).mkdir(exist_ok=True, mode=0o700)
    for item in spec["downloads"]:
        target = ctx.file("trust/" + item["name"])
        data = target.read_bytes() if target.exists() else download(item["url"])
        require(digest(data) == item["sha256"], "Downloaded input hash mismatch: " + item["name"])
        save_input(target, data)
    shim = checkout(ctx, "shim", spec["shim"]["url"], spec["shim"]["tag"], spec["shim"]["commit"])
    checkout(ctx, "gnu-efi", spec["gnu_efi"]["url"], "shim-16.1", spec["gnu_efi"]["commit"])
    linked = subprocess.check_output(["git", "-C", shim, "ls-tree", "HEAD", "gnu-efi"], text=True)
    require(spec["gnu_efi"]["commit"] in linked, "Pinned gnu-efi differs from signed shim tree")
    key = ctx.file("trust/upstream-release.asc")
    if not key.exists():
        key.write_bytes(download(spec["shim"]["key_url"]))
    env = {**os.environ, "GNUPGHOME": str(ctx.file("gnupg")), "LC_ALL": "C"}
    ctx.run(["gpg", "--batch", "--import", key], env=env)
    result = subprocess.run(["git", "-C", shim, "verify-tag", "--raw", spec["shim"]["tag"]],
                            capture_output=True, text=True, env=env)
    ctx.file("tag-verification.log").write_text(result.stdout + result.stderr)
    require(result.returncode == 0 and valid_tag_signer(result.stderr, spec["shim"]["signer"]),
        "Upstream release signature/fingerprint verification failed")
    tagged = subprocess.check_output(["git", "-C", shim, "rev-parse", spec["shim"]["tag"] + "^{commit}"], text=True).strip()
    require(tagged == spec["shim"]["commit"], "Signed tag does not identify pinned source")


def valid_tag_signer(status, primary):
    # GnuPG VALIDSIG reports the signing SUBKEY first and its bound primary last.
    # Accept only the pinned primary, whether it signed directly or via a subkey.
    for line in status.splitlines():
        fields = line.split()
        if len(fields) >= 11 and fields[:2] == ["[GNUPG:]", "VALIDSIG"]:
            if fields[2] == primary or len(fields) == 12 and fields[-1] == primary:
                return True
    return False


def prepare_keys(ctx):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.datetime.now(datetime.timezone.utc)
    for stem in ("efi-signing", "shim-helper"):
        keyfile = ctx.file(f"keys/{stem}.key")
        pem = ctx.file(f"trust/{stem}.pem")
        require(keyfile.exists() == pem.exists(), "Incomplete local key pair; do not regenerate an enrolled key")
        if not keyfile.exists():
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Local cookbook " + stem)])
            certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                           .public_key(key.public_key()).serial_number(x509.random_serial_number())
                           .not_valid_before(now - datetime.timedelta(days=1))
                           .not_valid_after(now + datetime.timedelta(days=3650))
                           .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                           .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                          key_encipherment=False, data_encipherment=False, key_agreement=False,
                                          key_cert_sign=True, crl_sign=True, encipher_only=False,
                                          decipher_only=False), critical=True)
                           .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False)
                           .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                           .sign(key, hashes.SHA256()))
            # Interrupted pair generation stops on retry rather than silently rotating keys.
            with keyfile.open("xb") as output:
                output.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
            save_input(pem, certificate.public_bytes(serialization.Encoding.PEM))
        require(not keyfile.stat().st_mode & 0o077, "Private key permissions are too broad")
        key = serialization.load_pem_private_key(keyfile.read_bytes(), password=None)
        certificate = x509.load_pem_x509_certificate(pem.read_bytes())
        require(key.public_key().public_numbers() == certificate.public_key().public_numbers(),
                "Local key and certificate do not match")
        save_input(ctx.file(f"trust/{stem}.der"), certificate.public_bytes(serialization.Encoding.DER))


def der_wrap(tag, value):
    n = len(value)
    length = bytes([n]) if n < 128 else n.to_bytes((n.bit_length() + 7) // 8, "big")
    if n >= 128:
        length = bytes([0x80 | len(length)]) + length
    return bytes([tag]) + length + value


def authenticated_payload(data):
    require(len(data) >= 40, "Truncated authenticated update")
    size = struct.unpack_from("<I", data, 16)[0]
    require(size >= 24 and 16 + size <= len(data) and
            data[24:40] == uuid.UUID("4aafd29d-68df-49ee-8aa9-347d375665a7").bytes_le,
            "Invalid authenticated update wrapper")
    payload = data[16 + size:]
    require(bool(signature_lists(payload)), "Empty authenticated update")
    return size, payload


def verify_update(ctx, version):
    data = ctx.file(f"trust/microsoft-dbx-{version}.auth").read_bytes()
    size, payload = authenticated_payload(data)
    signature = der_wrap(0x30, bytes.fromhex("06092a864886f70d010702") + der_wrap(0xA0, data[40:16 + size]))
    ctx.file("trust/update.p7").write_bytes(signature)
    content = ("dbx".encode("utf-16-le") + uuid.UUID("d719b2cb-3d3a-4596-a3bc-dad00e67656f").bytes_le
               + struct.pack("<I", 0x67) + data[:16] + payload)
    ctx.file("trust/update.content").write_bytes(content)
    ctx.run(["openssl", "cms", "-verify", "-binary", "-inform", "DER", "-in", ctx.file("trust/update.p7"),
             "-content", ctx.file("trust/update.content"), "-CAfile", ctx.file("trust/microsoft-kek-2011.pem"),
             "-partial_chain", "-purpose", "any", "-no_check_time", "-out", "/dev/null"])
    save_input(ctx.file(f"trust/microsoft-dbx-{version}.esl"), payload)
    return payload


def trust(ctx, factory_inputs=None):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    spec = manifest()
    for name, expected in spec["factory"].items():
        cached = ctx.file(f"trust/factory-{name}.esl")
        if cached.exists():
            data = cached.read_bytes()
        elif factory_inputs:
            data = (Path(factory_inputs) / f"factory-{name}.esl").read_bytes()
        else:
            paths = list(EFIVARS.glob(name + "Default-*"))
            require(len(paths) == 1, "Public firmware templates unavailable; provide reviewed --factory-inputs (see docs/cookbook.md): " + name)
            data = paths[0].read_bytes()[4:]
        signature_lists(data)
        require(digest(data) == expected, "Unreviewed firmware default template: " + name)
        save_input(cached, data)
    vendor = pe_sections(Path("/usr/lib/shim/shimx64.efi").read_bytes())[".vendor_cert"]
    require(len(vendor) >= 16, "Invalid installed vendor table")
    cs, ds, co, do = struct.unpack_from("<IIII", vendor)
    require(cs > 0 and ds > 0 and min(co, do) >= 16 and max(co + cs, do + ds) <= len(vendor),
            "Invalid installed vendor table ranges")
    ca, dbx = vendor[co:co + cs], vendor[do:do + ds]
    require(digest(ca) == spec["canonical"]["ca_sha256"] and
            digest(dbx) == spec["canonical"]["vendor_dbx_sha256"], "Unreviewed Canonical embedded trust")
    save_input(ctx.file("trust/canonical-uefi-ca.der"), ca)
    save_input(ctx.file("trust/canonical-vendor-dbx.esl"), dbx)
    save_input(ctx.file("trust/canonical-uefi-ca.pem"),
               x509.load_der_x509_certificate(ca).public_bytes(serialization.Encoding.PEM))
    for kind, _, entries in signature_lists(ctx.file("trust/factory-KEK.esl").read_bytes()):
        require(kind == X509_GUID, "Unexpected factory KEK signature type")
        for _, der in entries:
            cert = x509.load_der_x509_certificate(der)
            if "Microsoft Corporation KEK CA 2011" in cert.subject.rfc4514_string():
                save_input(ctx.file("trust/microsoft-kek-2011.pem"), cert.public_bytes(serialization.Encoding.PEM))
    old = verify_update(ctx, "20230509")
    verify_update(ctx, "20260402")
    original = json.loads(ctx.file("backup/snapshot.json").read_text())["variables"]
    if "signature_owner" not in ctx.state:
        ctx.state["signature_owner"] = str(uuid.uuid4())
        ctx.save()
    owner = uuid.UUID(ctx.state["signature_owner"])
    for name in ("KEK", "db", "dbx"):
        factory = ctx.file(f"trust/factory-{name}.esl").read_bytes()
        previous = bytes.fromhex(original[name]) if original[name] is not None else b""
        additions = b""
        if name == "db":
            additions = make_signature_list(X509_GUID, [
                (owner, ctx.file("trust/microsoft-uefi-ca-2011.der").read_bytes()),
            ]) + make_signature_list(X509_GUID, [(owner, ctx.file("trust/efi-signing.der").read_bytes())])
        elif name == "dbx":
            additions = old
        result = union_lists(factory, previous, additions)
        require(entry_set(previous) <= entry_set(result), "Prepared trust would remove an existing entry")
        save_input(ctx.file(f"trust/prepared-{name}.esl"), result)
    # This signature is a Setup-Mode wrapper, NOT authority over HP's PK in User Mode.
    if not ctx.file("trust/factory-PK.auth").exists():
        ctx.run(["sign-efi-sig-list", "-k", ctx.file("keys/efi-signing.key"), "-c", ctx.file("trust/efi-signing.pem"),
                 "PK", ctx.file("trust/factory-PK.esl"), ctx.file("trust/factory-PK.auth")])
    _, wrapped = authenticated_payload(ctx.file("trust/factory-PK.auth").read_bytes())
    require(wrapped == ctx.file("trust/factory-PK.esl").read_bytes(), "PK wrapper payload mismatch")


def archive(source, target):
    data = subprocess.check_output(["git", "-C", source, "archive", "HEAD"])
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as archive_file:
        archive_file.extractall(target, filter="data")


def build(ctx):
    spec = manifest()
    for flavor in ("tests", "production"):
        target = ctx.file("build/" + flavor)
        if not target.exists():
            archive(ctx.file("src/shim"), target)
            archive(ctx.file("src/gnu-efi"), target / "gnu-efi")
    test = ctx.file("build/tests")
    if "#undef strrchr" not in (test / "lib/string.c").read_text():
        ctx.run(["patch", "--batch", "--forward", "-d", test, "-p1", "-i", ROOT / "patches/tests-glibc.patch"])
    args = ["COMPILER=gcc-14", "CC=gcc-14", "HOSTCC=gcc-14", "COMMIT_ID=" + spec["shim"]["commit"]]
    timestamp = subprocess.check_output(["git", "-C", ctx.file("src/shim"), "show", "-s", "--format=%ct", "HEAD"], text=True).strip()
    env = {"SOURCE_DATE_EPOCH": timestamp, "LC_ALL": "C", "TZ": "UTC"}
    # Dedicated logs are truncated: old successful runs cannot mask a failed rerun.
    ctx.file("unit-tests.log").write_text("")
    ctx.run(["make", "-C", test, *args, "test"], log="unit-tests.log", env=env)
    prod = ctx.file("build/production")
    shutil.copyfile(ctx.file("trust/shim-helper.pem"), prod / "shim.crt")
    shutil.copyfile(ctx.file("trust/shim-helper.der"), prod / "shim.cer")
    link = prod / "shim.key"
    if not link.is_symlink():
        require(not link.exists(), "Unexpected production helper key file")
        link.symlink_to(ctx.file("keys/shim-helper.key"))
    require(link.resolve() == ctx.file("keys/shim-helper.key"), "Unexpected helper key link")
    (prod / "data/sbat.cookbook.csv").write_text(
        "shim.spectrecookbook,1,Local Spectre cookbook,shim,16.1,https://github.com/rhboot/shim\n")
    ctx.file("build.log").write_text("")
    ctx.run(["make", "-C", prod, "-j2", *args, "RELEASE=cookbook1", "EFIDIR=shim16-cookbook",
             "FORMAT=--output-target=efi-app-x86_64",
             "VENDOR_CERT_FILE=" + str(ctx.file("trust/canonical-uefi-ca.der")),
             "VENDOR_DBX_FILE=" + str(ctx.file("trust/canonical-vendor-dbx.esl")),
             "ENABLE_SHIM_CERT=1", "ENABLE_SBSIGN=1", "DISABLE_REMOVABLE_LOAD_OPTIONS=1", "all"],
            log="build.log", env=env)
    ctx.run(["sbsign", "--key", ctx.file("keys/efi-signing.key"), "--cert", ctx.file("trust/efi-signing.pem"),
             "--output", ctx.file("artifacts/shimx64.efi"), prod / "shimx64.efi"])
    shutil.copyfile(prod / "mmx64.efi.signed", ctx.file("artifacts/mmx64.efi"))
    shutil.copyfile("/usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed", ctx.file("artifacts/grubx64.efi"))
    # The private backup supplies exactly this target's existing Ubuntu redirect.
    config = ctx.file("backup/grub.cfg").read_bytes()
    require(b"configfile" in config and b"search" in config, "Unsupported Ubuntu GRUB redirect")
    save_input(ctx.file("artifacts/grub.cfg"), config)


def sbat_generations(text):
    result = {}
    for line in text.strip("\0\n").splitlines():
        fields = line.split(",")
        require(len(fields) >= 2 and fields[1].isdigit(), "Malformed SBAT input")
        result[fields[0]] = int(fields[1])
    return result


def check_sbat(image, policies):
    generations = sbat_generations(pe_sections(image)[".sbat"].rstrip(b"\0").decode())
    for policy in policies:
        for component, minimum in sbat_generations(policy).items():
            if component != "sbat" and component in generations:
                require(generations[component] >= minimum, "A loader is revoked by SBAT policy")


def audit(ctx):
    spec = manifest()
    source, prod = ctx.file("src/shim"), ctx.file("build/production")
    for name in subprocess.check_output(["git", "-C", source, "ls-files", "*.c", "*.h"], text=True).splitlines():
        require((source / name).read_bytes() == (prod / name).read_bytes(), "Production C/header source changed")
    tests = ctx.file("unit-tests.log").read_text()
    require(tests.count(": passed") == 118, "Expected 118 upstream tests")
    shim = ctx.file("artifacts/shimx64.efi").read_bytes()
    sections = pe_sections(shim)
    table = sections[".vendor_cert"]
    cs, ds, co, do = struct.unpack_from("<IIII", table)
    require(table[co:co + cs] == ctx.file("trust/canonical-uefi-ca.der").read_bytes() and
            table[do:do + ds] == ctx.file("trust/canonical-vendor-dbx.esl").read_bytes(), "Embedded vendor trust mismatch")
    require("TPM extend operation occurred, but the event could".encode("utf-16-le") in shim,
            "Expected upstream TPM-full behavior marker missing")
    level = sections[".sbatlevel"]
    version, automatic, latest = struct.unpack_from("<III", level)
    require(version == 0, "Unsupported SBAT level format")
    policies = [level[4 + offset:level.index(b"\0", 4 + offset)].decode() for offset in (automatic, latest)]
    runtime = variable("SbatLevelRT", "605dab50-e046-4300-abb6-3dd810dd8b23")
    if runtime:
        policies.append(runtime.rstrip(b"\0").decode())
    for name, cert in (("shimx64.efi", "efi-signing"), ("mmx64.efi", "shim-helper"),
                       ("grubx64.efi", "canonical-uefi-ca")):
        image = ctx.file("artifacts/" + name).read_bytes()
        pe = struct.unpack_from("<I", image, 60)[0]
        require(struct.unpack_from("<H", image, pe + 4)[0] == 0x8664 and
                struct.unpack_from("<H", image, pe + 24 + 68)[0] == 10, "Not an x86_64 EFI application")
        check_sbat(image, policies)
        ctx.run(["sbverify", "--cert", ctx.file("trust/" + cert + ".pem"), ctx.file("artifacts/" + name)])
    kernel_checked = ctx.state.get("kind") != "vm-only"
    if kernel_checked:
        # Ubuntu can restrict /boot/vmlinuz to root. The explicit snapshot operation
        # copies it privately; privileged deployment checks the live kernel again.
        ctx.run(["sbverify", "--cert", ctx.file("trust/canonical-uefi-ca.pem"), ctx.file("backup/kernel.efi")])
    vm = json.loads(ctx.file("artifacts/vm-results.json").read_text())
    require({row["scenario"] for row in vm} == {"baseline-dbx", "latest-dbx", "canonical-grub", "untrusted-shim", "tpm-full"}
            and len(vm) == 5 and all(row["passed"] for row in vm), "VM verification incomplete")
    full = ctx.file("vm-test/tpm-full/serial.log").read_text(errors="replace")
    require(full.count("TPM extend operation occurred") == 1, "Expected exactly one shim TPM-full warning")
    paths = ["artifacts/" + n for n in ("shimx64.efi", "mmx64.efi", "grubx64.efi", "grub.cfg")]
    paths += [str(p.relative_to(ctx.path)) for p in sorted(ctx.file("trust").iterdir()) if p.suffix in (".esl", ".auth", ".der", ".pem")]
    hashes = {name: digest(ctx.file(name).read_bytes()) for name in paths}
    ctx.file("artifacts/manifest.json").write_text(json.dumps(hashes, indent=2) + "\n")
    ctx.file("artifacts/audit.json").write_text(json.dumps({
        "code": code_digest(), "source_commit": spec["shim"]["commit"],
        "upstream_tests": 118, "vm_scenarios": 5, "production_c_h_unmodified": True,
        "kernel_backup_verified": kernel_checked,
        "manifest_sha256": digest(ctx.file("artifacts/manifest.json").read_bytes()),
    }, indent=2) + "\n")
