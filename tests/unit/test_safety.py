import argparse
from contextlib import ExitStack, redirect_stdout
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

import check_public
import cli
import common
import deployment
from efi_formats import (SHA256_GUID, X509_GUID, entry_set, make_signature_list,
                         pe_sections, signature_lists, union_lists)
import pipeline
import privileged


class Formats(unittest.TestCase):
    def setUp(self):
        self.owner = uuid.UUID(int=1)
        self.first = make_signature_list(SHA256_GUID, [(self.owner, bytes(32))])
        self.second = make_signature_list(SHA256_GUID, [(self.owner, bytes(range(32)))])

    def test_signature_roundtrip(self):
        self.assertEqual(signature_lists(self.first), [(SHA256_GUID, b"", [(self.owner, bytes(32))])])

    def test_truncated_list(self):
        with self.assertRaises(ValueError):
            signature_lists(bytes(27))

    def test_bad_sizes(self):
        data = SHA256_GUID.bytes_le + struct.pack("<III", 28, 0, 15)
        with self.assertRaises(ValueError):
            signature_lists(data)

    def test_incomplete_entry(self):
        with self.assertRaises(ValueError):
            signature_lists(self.first[:-1])

    def test_empty_list_creation(self):
        with self.assertRaises(ValueError):
            make_signature_list(SHA256_GUID, [])

    def test_unequal_signatures(self):
        with self.assertRaises(ValueError):
            make_signature_list(SHA256_GUID, [(self.owner, b"a"), (self.owner, b"ab")])

    def test_union_preserves_and_deduplicates(self):
        combined = union_lists(self.first, self.second, self.first)
        self.assertEqual(len(entry_set(combined)), 2)
        self.assertLessEqual(entry_set(self.first), entry_set(combined))

    def test_union_preserves_headers(self):
        extra = make_signature_list(SHA256_GUID, [(self.owner, bytes(32))], b"header")
        self.assertEqual(len(entry_set(union_lists(self.first, extra))), 2)

    def test_union_handles_duplicate_within_list(self):
        repeated = make_signature_list(SHA256_GUID, [(self.owner, bytes(32)), (self.owner, bytes(32))])
        self.assertEqual(union_lists(repeated), self.first)

    def test_invalid_pe(self):
        for value in (b"", b"not PE", b"MZ" + bytes(62)):
            with self.assertRaises(ValueError):
                pe_sections(value)

    def test_truncated_pe_section(self):
        data = bytearray(100)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 60, 64)
        data[64:68] = b"PE\0\0"
        struct.pack_into("<H", data, 70, 1)
        with self.assertRaises(ValueError):
            pe_sections(data)

    def test_truncated_authenticated_wrapper(self):
        with self.assertRaises(RuntimeError):
            pipeline.authenticated_payload(bytes(39))

    def test_invalid_authenticated_guid(self):
        with self.assertRaises(RuntimeError):
            pipeline.authenticated_payload(bytes(80))


class BootAndMok(unittest.TestCase):
    def test_tag_signing_subkey_bound_to_pinned_primary(self):
        primary, subkey = "A" * 40, "B" * 40
        status = f"[GNUPG:] VALIDSIG {subkey} 2025-01-01 1 0 4 0 1 10 00 {primary}"
        self.assertTrue(pipeline.valid_tag_signer(status, primary))
        self.assertFalse(pipeline.valid_tag_signer(status, "C" * 40))
        self.assertFalse(pipeline.valid_tag_signer("untrusted " + primary, primary))

    def test_manual_reboot_required(self):
        with self.assertRaises(RuntimeError):
            common.rebooted("same", "same")
        with self.assertRaises(RuntimeError):
            common.rebooted(None, "new")
        common.rebooted("old", "new")

    def test_pending_bootnext(self):
        self.assertTrue(common.next_is_safe(None, "ABCD"))
        self.assertTrue(common.next_is_safe(bytes.fromhex("cdab"), "ABCD"))
        self.assertFalse(common.next_is_safe(b"\0\0", "ABCD"))

    def test_malformed_boot_number(self):
        for value in (None, b"", b"a", b"abc"):
            with self.assertRaises(RuntimeError):
                common.boot_number(value)

    def test_malformed_boot_order(self):
        for value in (None, b"", b"a"):
            with self.assertRaises(RuntimeError):
                common.boot_order(value)

    def test_find_exact_entry(self):
        partition = str(uuid.UUID(int=2))
        text = f"BootABCD* {common.LABEL}\tHD(1,GPT,{partition},0x800,0x100)/{common.LOADER}"
        self.assertEqual(common.find_entry(text, partition), "ABCD")
        with self.assertRaises(RuntimeError):
            common.find_entry(text + "\n" + text, partition)
        with self.assertRaises(RuntimeError):
            common.find_entry(text, str(uuid.UUID(int=3)))
        with self.assertRaises(RuntimeError):
            common.find_entry(text.replace(common.LOADER, "other"), partition)

    def test_positive_mok_exit_one(self):
        path = Path("synthetic.der")
        result = subprocess.CompletedProcess([], 1, stdout=f"{path} is already enrolled\n")
        self.assertTrue(common.mokutil_reports_enrolled(result, path))

    def test_mok_exit_zero_is_not_proof(self):
        self.assertFalse(common.mokutil_reports_enrolled(subprocess.CompletedProcess([], 0, stdout=""), "synthetic.der"))

    def test_mok_error_not_accepted(self):
        self.assertFalse(common.mokutil_reports_enrolled(
            subprocess.CompletedProcess([], 2, stdout="synthetic.der is already enrolled"), "synthetic.der"))

    def test_mok_substring_not_accepted(self):
        self.assertFalse(common.mokutil_reports_enrolled(
            subprocess.CompletedProcess([], 1, stdout="warning\nsynthetic.der is already enrolled"), "synthetic.der"))

    def test_mok_exact_certificate_required(self):
        payload = make_signature_list(X509_GUID, [(uuid.UUID(int=1), b"public-fixture")])
        self.assertTrue(common.certificate_in_mok(b"public-fixture", payload))
        self.assertFalse(common.certificate_in_mok(b"different", payload))

    def test_wrong_hardware_stops(self):
        with patch.object(Path, "read_text", return_value="Other vendor"):
            with self.assertRaises(RuntimeError):
                common.preflight()


class Workspace(unittest.TestCase):
    def test_private_directory_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o755)
            with self.assertRaises(RuntimeError):
                common.Context(root)

    def test_state_must_be_outside_checkout(self):
        with self.assertRaises(RuntimeError):
            common.Context(common.ROOT / "not-created")

    def test_reject_symlink_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "real").mkdir(mode=0o700)
            (root / "link").symlink_to(root / "real")
            with self.assertRaises(RuntimeError):
                common.Context(root / "link")

    def test_reject_path_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            ctx = common.Context(directory)
            for name in ("../outside", "/outside"):
                with self.assertRaises(RuntimeError):
                    ctx.file(name)

    def test_checkpoint_phase_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            ctx = common.Context(directory)
            with self.assertRaises(RuntimeError):
                ctx.require_phase("staged")

    def test_vm_checkpoint_cannot_bind_for_deployment(self):
        with tempfile.TemporaryDirectory() as directory:
            ctx = common.Context(directory)
            ctx.state = {"kind": "vm-only", "phase": "vm-only"}
            with patch.object(common, "esp_identity", return_value={"source": "synthetic"}):
                with self.assertRaises(RuntimeError):
                    ctx.bind()


class FirmwareWrites(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "trust").mkdir()
        (self.root / "backup").mkdir()
        self.ctx = SimpleNamespace(file=lambda name: self.root / name)
        self.owner = uuid.UUID(int=1)
        self.before = make_signature_list(SHA256_GUID, [(self.owner, b"a" * 32)])
        self.extra = make_signature_list(SHA256_GUID, [(self.owner, b"b" * 32)])
        self.expected = union_lists(self.before, self.extra)
        (self.root / "trust/prepared-db.esl").write_bytes(self.expected)
        (self.root / "backup/snapshot.json").write_text(json.dumps({"variables": {"db": self.before.hex()}}))

    def test_already_matching_write_is_noop(self):
        with patch.object(privileged, "variable", return_value=self.expected), patch.object(privileged.subprocess, "run") as run:
            privileged.write_setup(self.ctx, "db", "prepared-db.esl")
            run.assert_not_called()

    def test_user_mode_refuses_write(self):
        values = {"db": self.before, "SecureBoot": b"\0", "SetupMode": b"\0"}
        with patch.object(privileged, "variable", side_effect=lambda name: values[name]), patch.object(privileged.subprocess, "run") as run:
            with self.assertRaises(RuntimeError):
                privileged.write_setup(self.ctx, "db", "prepared-db.esl")
            run.assert_not_called()

    def test_unexpected_database_refuses_write(self):
        values = {"db": self.extra, "SecureBoot": b"\0", "SetupMode": b"\1"}
        with patch.object(privileged, "variable", side_effect=lambda name: values[name]), patch.object(privileged.subprocess, "run") as run:
            with self.assertRaises(RuntimeError):
                privileged.write_setup(self.ctx, "db", "prepared-db.esl")
            run.assert_not_called()

    def test_existing_revocation_cannot_be_removed(self):
        (self.root / "trust/prepared-db.esl").write_bytes(self.extra)
        values = {"db": self.before, "SecureBoot": b"\0", "SetupMode": b"\1"}
        with patch.object(privileged, "variable", side_effect=lambda name: values[name]), patch.object(privileged.subprocess, "run") as run:
            with self.assertRaises(RuntimeError):
                privileged.write_setup(self.ctx, "db", "prepared-db.esl")
            run.assert_not_called()

    def test_guarded_write_readback(self):
        values = {"db": self.before, "SecureBoot": b"\0", "SetupMode": b"\1"}
        def update(*args, **kwargs):
            values["db"] = self.expected
        with patch.object(privileged, "variable", side_effect=lambda name: values[name]), patch.object(privileged.subprocess, "run", side_effect=update) as run:
            privileged.write_setup(self.ctx, "db", "prepared-db.esl")
            self.assertEqual(run.call_count, 1)

    def test_failed_readback_stops(self):
        values = {"db": self.before, "SecureBoot": b"\0", "SetupMode": b"\1"}
        with patch.object(privileged, "variable", side_effect=lambda name: values[name]), patch.object(privileged.subprocess, "run"):
            with self.assertRaises(RuntimeError):
                privileged.write_setup(self.ctx, "db", "prepared-db.esl")

    def test_finish_requires_explicit_consent(self):
        ctx = Mock()
        with self.assertRaises(RuntimeError):
            cli.finish(ctx, argparse.Namespace(apply_dbx=False))
        ctx.sudo.assert_not_called()

    def test_deferred_setup_mode_is_a_reboot_checkpoint(self):
        expected = {}
        for name in ("KEK", "db", "dbx"):
            (self.root / f"trust/prepared-{name}.esl").write_bytes(self.expected)
            expected[name] = self.expected
        # Structurally valid synthetic PK wrapper; never sent to firmware.
        pk = bytes(16) + struct.pack("<IHH", 24, 0x200, 0xEF1) + uuid.UUID("4aafd29d-68df-49ee-8aa9-347d375665a7").bytes_le + self.before
        (self.root / "trust/factory-PK.auth").write_bytes(pk)
        expected["PK"] = self.before
        expected.update(SecureBoot=b"\0", SetupMode=b"\1")
        (self.root / "backup/snapshot.json").write_text(json.dumps({"variables": {n: None for n in ("PK", "KEK", "db", "dbx")}}))
        ctx = Mock()
        ctx.file.side_effect = lambda name: self.root / name
        with ExitStack() as stack:
            for name in ("check_manifest", "staged", "module_identity", "original_files", "databases", "select_next"):
                stack.enter_context(patch.object(privileged, name))
            stack.enter_context(patch.object(privileged, "current_entry", return_value="ABCD"))
            stack.enter_context(patch.object(privileged, "variable", side_effect=lambda name: expected[name]))
            stack.enter_context(patch.object(privileged.os, "sync"))
            write = stack.enter_context(patch.object(privileged, "write_setup"))
            with redirect_stdout(io.StringIO()):
                privileged.enroll(ctx)  # Exact readback with SetupMode=1 must not demand reenrollment.
            self.assertEqual([call.args[1] for call in write.call_args_list], ["KEK", "db", "dbx", "PK"])

    def test_enroll_cannot_skip_reboot(self):
        ctx = Mock()
        ctx.new_boot.side_effect = RuntimeError("reboot required")
        with self.assertRaises(RuntimeError):
            cli.enroll(ctx, argparse.Namespace())
        ctx.sudo.assert_not_called()

    def test_sbat_rejects_revoked_component(self):
        with patch.object(pipeline, "pe_sections", return_value={".sbat": b"sbat,1\ngrub,1\n"}):
            with self.assertRaises(RuntimeError):
                pipeline.check_sbat(b"synthetic", ["sbat,1\ngrub,2\n"])

    def test_sbat_accepts_current_component(self):
        with patch.object(pipeline, "pe_sections", return_value={".sbat": b"sbat,1\ngrub,2\n"}):
            pipeline.check_sbat(b"synthetic", ["sbat,1\ngrub,2\n"])

    def test_dbx_union_requires_old_entries(self):
        ctx = SimpleNamespace(state={"dbx_before": self.before.hex()}, file=lambda name: self.root / name)
        (self.root / "trust/microsoft-dbx-20260402.esl").write_bytes(self.extra)
        with patch.object(deployment, "variable", return_value=self.extra):
            with self.assertRaises(RuntimeError):
                deployment.final_dbx(ctx)
        with patch.object(deployment, "variable", return_value=self.expected):
            self.assertEqual(deployment.final_dbx(ctx), 2)


class Publication(unittest.TestCase):
    def test_staged_secret_is_rejected_even_after_working_file_is_cleaned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "--quiet", root], check=True, capture_output=True)
            fixture = root / "fixture.md"
            fixture.write_bytes(b"-----BEGIN " + b"RSA PRIVATE KEY-----")
            subprocess.run(["git", "-C", root, "add", "--", "fixture.md"], check=True)
            fixture.write_text("now clean")
            check_public.check_files(root, ["fixture.md"], [])
            with self.assertRaises(RuntimeError):
                check_public.check_staged(root, ["fixture.md"], [])

    def test_incomplete_index_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "--quiet", root], check=True, capture_output=True)
            with self.assertRaises(RuntimeError):
                check_public.check_staged(root, ["fixture.md"], [])

    def test_private_key_block_rejected(self):
        marker = b"-----BEGIN " + b"RSA PRIVATE KEY-----"
        self.assertIn("private-key material", check_public.problems("fixture.py", marker))

    def test_local_home_path_rejected(self):
        text = b"/" + b"home/" + b"synthetic-login/project"
        self.assertIn("user-home path", check_public.problems("fixture.md", text))

    def test_local_token_rejected(self):
        self.assertIn("forbidden local identifier", check_public.problems("fixture.md", b"synthetic-login", ["synthetic-login"]))

    def test_unknown_uuid_rejected(self):
        self.assertIn("nonstandard identifying UUID", check_public.problems("fixture.md", str(uuid.UUID(int=99)).encode()))

    def test_standard_guid_allowed(self):
        self.assertEqual(check_public.problems("fixture.py", str(SHA256_GUID).encode()), [])

    def test_binary_key_file_rejected(self):
        self.assertTrue(check_public.problems("fixture.key", bytes([255, 0])))

    def test_unexpected_file_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "unexpected.md").write_text("fixture")
            with self.assertRaises(RuntimeError):
                check_public.check_files(Path(directory), [], [])

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fixture.md").write_text("fixture")
            (root / "link.md").symlink_to(root / "fixture.md")
            with self.assertRaises(RuntimeError):
                check_public.check_files(root, ["fixture.md", "link.md"], [])

    def test_export_refuses_existing_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "fixture.md").write_text("fixture")
            target = root / "existing.tar"
            target.write_bytes(b"keep")
            with self.assertRaises(FileExistsError):
                check_public.export(source, ["fixture.md"], target)
            self.assertEqual(target.read_bytes(), b"keep")

    def test_export_normalizes_metadata_and_excludes_unlisted_files(self):
        import tarfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "fixture.md").write_text("fixture")
            (source / "private.key").write_text("not part of export")
            target = root / "source.tar"
            check_public.export(source, ["fixture.md"], target)
            with tarfile.open(target) as archive:
                self.assertEqual(archive.getnames(), ["community-cookbook/fixture.md"])
                item = archive.getmembers()[0]
                self.assertEqual((item.uid, item.gid, item.uname, item.gname), (0, 0, "", ""))


class PhaseSequence(unittest.TestCase):
    def test_four_reboots_and_only_expected_privileged_actions(self):
        with tempfile.TemporaryDirectory() as directory:
            ctx = common.Context(directory)
            ctx.state = {"phase": "staged", "boot_id": "boot0", "machine": "private-fixture"}
            current = ["boot0"]
            ctx.sudo = Mock()
            args = argparse.Namespace(apply_dbx=True)
            with patch.object(common, "boot_id", side_effect=lambda: current[0]), patch.object(cli, "variable", return_value=b"fixture"), redirect_stdout(io.StringIO()):
                with self.assertRaises(RuntimeError):
                    cli.enroll(ctx, args)
                current[0] = "boot1"
                cli.enroll(ctx, args)
                self.assertEqual(ctx.state["phase"], "enrolled")
                with self.assertRaises(RuntimeError):
                    cli.enable(ctx, args)
                current[0] = "boot2"
                cli.enable(ctx, args)
                with self.assertRaises(RuntimeError):
                    cli.finish(ctx, args)
                current[0] = "boot3"
                cli.finish(ctx, args)
                with self.assertRaises(RuntimeError):
                    cli.verify(ctx, args)
                current[0] = "boot4"
                cli.verify(ctx, args)
            self.assertEqual([call.args[0] for call in ctx.sudo.call_args_list], ["enroll", "schedule", "finish", "verify"])
            report = json.loads(ctx.file("shareable-report.json").read_text())
            self.assertNotIn("machine", report)
            self.assertNotIn("boot_id", report)
            self.assertEqual(ctx.state["phase"], "complete")


if __name__ == "__main__":
    unittest.main()
