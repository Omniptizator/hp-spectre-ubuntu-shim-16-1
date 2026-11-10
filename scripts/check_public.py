#!/usr/bin/env python3
"""Allowlist-based privacy check and source-only export; no key files are read."""

import argparse
import getpass
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile

from common import ROOT, require

PUBLIC_GUIDS = {
    "a5c059a1-94e4-4aa7-87b5-ab155c2bf072", "c1c41626-504c-4092-aca9-41f936934328",
    "8be4df61-93ca-11d2-aa0d-00e098032b8c", "d719b2cb-3d3a-4596-a3bc-dad00e67656f",
    "605dab50-e046-4300-abb6-3dd810dd8b23", "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
    "4aafd29d-68df-49ee-8aa9-347d375665a7",
}


def problems(name, data, forbidden=()):
    findings = []
    if Path(name).suffix.lower() not in (".py", ".c", ".md", ".toml", ".json", ".yml", ".patch", "") and name not in (".gitignore", ".gitattributes"):
        findings.append("unexpected file type")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return ["binary/non-UTF-8 content"]
    if "\0" in text:
        findings.append("binary content")
    patterns = {
        "private-key material": (rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|"
                                 + rb"-----BEGIN " + rb"PGP PRIVATE KEY BLOCK-----"),
        "user-home path": rb"/" + rb"(?:home|Users)/[A-Za-z0-9_.-]+",
        "GitHub credential": rb"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})",
        "embedded password": rb"(?i)(?:password|passwd)\s*[=:]\s*['\"][^'\"\n]{4,}['\"]",
        "SSH key material": rb"ssh-(?:rsa|ed25519)\s+AAAA[A-Za-z0-9+/=]+",
    }
    for label, pattern in patterns.items():
        if re.search(pattern, data):
            findings.append(label)
    for value in re.findall(r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b", text):
        if value.lower() not in PUBLIC_GUIDS:
            findings.append("nonstandard identifying UUID")
    for token in forbidden:
        if token and re.search(r"(?<![\w])" + re.escape(token) + r"(?![\w])", text, re.IGNORECASE):
            findings.append("forbidden local identifier")
    return sorted(set(findings))


def check_files(root, allowed, forbidden):
    actual = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if relative.parts[0] == ".git":
            continue
        if path.is_symlink():
            raise RuntimeError("Symlink in public tree: " + str(relative))
        if path.is_dir():
            continue
        if "__pycache__" in relative.parts or path.suffix == ".pyc":
            continue
        name = relative.as_posix()
        require(name in allowed, "Unexpected public file: " + name)
        actual.add(name)
        found = problems(name, path.read_bytes(), forbidden)
        require(not found, "Privacy check failed for " + name + ": " + ", ".join(found))
    require(actual == set(allowed), "Public allowlist files are missing")


def check_history(root, allowed, forbidden):
    result = subprocess.run(["git", "rev-list", "--all"], cwd=root, capture_output=True, text=True)
    require(result.returncode == 0, "Cannot inspect Git history")
    commits = result.stdout.splitlines()
    checked = set()
    for commit in commits:
        metadata = subprocess.check_output(["git", "show", "-s", "--format=fuller", commit], cwd=root)
        require(not problems("commit", metadata, forbidden), "Private identifier/secret in commit metadata")
        tree = subprocess.check_output(["git", "ls-tree", "-rz", commit], cwd=root)
        for record in tree.split(b"\0"):
            if not record:
                continue
            info, name = record.split(b"\t", 1)
            mode, kind, object_id = info.split()
            path = name.decode("utf-8")
            require(mode in (b"100644", b"100755") and kind == b"blob" and path in allowed,
                    "Disallowed historical file: " + path)
            item = (path, object_id)
            if item not in checked:
                data = subprocess.check_output(["git", "cat-file", "blob", object_id.decode()], cwd=root)
                require(not problems(path, data, forbidden), "Private content in history: " + path)
                checked.add(item)
    return len(commits)


def check_staged(root, allowed, forbidden):
    tree = subprocess.check_output(["git", "ls-files", "--stage", "-z"], cwd=root)
    found = set()
    for record in tree.split(b"\0"):
        if not record:
            continue
        info, name = record.split(b"\t", 1)
        mode, object_id, stage = info.split()
        path = name.decode("utf-8")
        require(stage == b"0" and mode in (b"100644", b"100755") and path in allowed,
                "Disallowed/unmerged staged file: " + path)
        data = subprocess.check_output(["git", "cat-file", "blob", object_id.decode()], cwd=root)
        require(not problems(path, data, forbidden), "Private content in Git index: " + path)
        found.add(path)
    require(found == set(allowed), "Git index does not contain the complete public allowlist")
    return len(found)


def export(root, allowed, destination):
    destination = Path(destination).expanduser().absolute()
    require(not any(p.is_symlink() for p in (destination, *destination.parents)),
            "Export destination must not contain symlinks")
    require(root != destination.parent and root not in destination.parents,
            "Export must be outside the repository")
    # Exclusive create also protects existing symlink targets from overwrite.
    with destination.open("xb") as output:
        with tarfile.open(fileobj=output, mode="w") as archive:
            for name in sorted(allowed):
                data = (root / name).read_bytes()
                item = tarfile.TarInfo("community-cookbook/" + name)
                item.size = len(data)
                item.mode = 0o755 if name in ("cookbook", ".githooks/pre-commit") else 0o644
                item.uid = item.gid = item.mtime = 0
                item.uname = item.gname = ""
                archive.addfile(item, io.BytesIO(data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history", action="store_true")
    parser.add_argument("--staged", action="store_true")
    parser.add_argument("--export", metavar="OUTSIDE_REPOSITORY_TAR")
    parser.add_argument("--forbid-local-token", action="append", default=[], help="additional private identifier; not printed")
    args = parser.parse_args()
    login = getpass.getuser()
    forbidden = args.forbid_local_token + ([login] if len(login) > 2 and login not in ("root", "user", "runner", "ubuntu") else [])
    allowed = json.loads((ROOT / "manifests/public-files.json").read_text())
    require(len(allowed) == len(set(allowed)) and all(
        not Path(n).is_absolute() and ".." not in Path(n).parts and not n.startswith(".git/") for n in allowed),
        "Unsafe or duplicate publication allowlist")
    check_files(ROOT, allowed, forbidden)
    print(f"PASS: {len(allowed)} allowlisted public files; no detected secrets/local identifiers.")
    if args.staged:
        count = check_staged(ROOT, allowed, forbidden)
        print(f"PASS: {count} staged files checked.")
    if args.history:
        count = check_history(ROOT, allowed, forbidden)
        print(f"PASS: {count} historical commits checked.")
    if args.export:
        export(ROOT, allowed, args.export)
        print("Source-only export created; archive owner metadata normalized.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"Stopped: {error}") from None
