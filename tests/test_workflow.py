import ctypes
import hashlib
import hmac
import importlib.util
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import workflow_common
from win_dacl import secure_directory, secure_write_text


def load_numbered_script(filename: str, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


derive_keys = load_numbered_script("3_derive_keys.py", "derive_keys_for_test")
configure_cli = load_numbered_script("4_configure_wechat_cli.py", "configure_cli_for_test")
anchor = load_numbered_script("find_kdf_anchor.py", "anchor_for_test")
preflight = load_numbered_script("0_preflight.py", "preflight_for_test")
capture = load_numbered_script("1_capture_launch.py", "capture_for_test")
privacy = load_numbered_script("privacy_check.py", "privacy_for_test")


def make_page(passphrase: bytes, salt: bytes) -> bytes:
    page = bytearray(os.urandom(derive_keys.PAGE_SIZE))
    page[:derive_keys.SALT_SIZE] = salt
    enc_key = hashlib.pbkdf2_hmac(
        "sha512", passphrase, salt, derive_keys.ROUNDS, dklen=32
    )
    mac_salt = bytes(value ^ 0x3A for value in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=32)
    data_end = derive_keys.PAGE_SIZE - derive_keys.RESERVE + derive_keys.IV_SIZE
    digest = hmac.new(mac_key, digestmod=hashlib.sha512)
    digest.update(page[derive_keys.SALT_SIZE:data_end])
    digest.update(struct.pack("<I", 1))
    page[data_end:data_end + derive_keys.HMAC_SIZE] = digest.digest()
    return bytes(page)


class WorkflowCommonTests(unittest.TestCase):
    def test_anchor_defaults_are_exact_and_parseable(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            rva, version, expected = workflow_common.resolve_anchor_config()
        self.assertGreater(rva, 0)
        self.assertEqual(version.count("."), 3)
        self.assertGreaterEqual(len(expected), 3)

    def test_anchor_rejects_partial_version(self):
        with (
            mock.patch.dict(
                os.environ, {"WX_EXPECTED_VERSION": "4.1.12"}, clear=False
            ),
            self.assertRaises(workflow_common.WorkflowConfigError),
        ):
            workflow_common.resolve_anchor_config()

    def test_sensitive_output_inside_repo_must_stay_under_secrets(self):
        unsafe = ROOT / "tests" / "private-output"
        with (
            mock.patch.dict(
                os.environ, {"WX_SECRETS_DIR": str(unsafe)}, clear=False
            ),
            self.assertRaises(workflow_common.WorkflowConfigError),
        ):
            workflow_common.resolve_secrets_dir()

    def test_dll_discovery_rejects_ambiguous_installation(self):
        with tempfile.TemporaryDirectory(prefix="wx-chatlog-test-") as temp_dir:
            base = Path(temp_dir)
            exe = base / "Weixin.exe"
            exe.write_bytes(b"placeholder")
            for version in ("one", "two"):
                dll = base / version / "Weixin.dll"
                dll.parent.mkdir()
                dll.write_bytes(b"placeholder")
            with (
                mock.patch.dict(os.environ, {"WX_DLL": ""}, clear=False),
                self.assertRaises(workflow_common.WorkflowConfigError),
            ):
                workflow_common.resolve_weixin_dll(exe, base)

    def test_pe_parser_rejects_non_pe_input(self):
        with self.assertRaises(ValueError):
            anchor.parse_sections(b"not a PE file")

    @unittest.skipUnless(os.name == "nt", "PE32+ fixture is the running Windows Python")
    def test_pe_parser_accepts_running_python(self):
        image_base, sections = anchor.parse_sections(Path(sys.executable).read_bytes())
        self.assertGreater(image_base, 0)
        self.assertIn(".text", {section[0] for section in sections})


class PreflightTests(unittest.TestCase):
    def test_ready_report_redacts_machine_paths(self):
        with tempfile.TemporaryDirectory(prefix="wx-chatlog-test-") as temp_dir:
            base = Path(temp_dir)
            exe = base / "Weixin.exe"
            exe.write_bytes(b"placeholder")
            (base / "Weixin.dll").write_bytes(b"placeholder")
            db_dir = base / "account" / "db_storage"
            db_dir.mkdir(parents=True)
            (db_dir / "sample.db").write_bytes(os.urandom(4096))
            env = {
                "WX_EXE": str(exe),
                "WX_DB_DIR": str(db_dir),
                "WX_DLL": "",
                "WX_SECRETS_DIR": str(base / "private-output"),
            }
            def fake_version(path):
                return (
                    "4.1.12.26"
                    if Path(path).name.casefold() == "weixin.dll"
                    else "9.9.9.9"
                )

            with (
                mock.patch.dict(os.environ, env, clear=False),
                mock.patch.object(preflight, "get_file_version", side_effect=fake_version),
                mock.patch.object(preflight, "discover_weixin_exes", return_value=[exe]),
                mock.patch.object(preflight, "discover_db_dirs", return_value=[db_dir]),
            ):
                report = preflight.build_report()
        self.assertTrue(report["ready"])
        self.assertNotIn(temp_dir, str(report))
        profile = next(
            check for check in report["checks"]
            if check["name"] == "breakpoint_profile"
        )
        self.assertEqual(profile["detail"]["actual_dll_version"], "4.1.12.26")


class DerivationTests(unittest.TestCase):
    def test_derive_all_emits_wechat_cli_compatible_shape(self):
        passphrase = bytes(range(32))
        salt = bytes(range(16))
        with tempfile.TemporaryDirectory(prefix="wx-chatlog-test-") as temp_dir:
            db_dir = Path(temp_dir) / "db_storage"
            db_path = db_dir / "contact" / "contact.db"
            db_path.parent.mkdir(parents=True)
            db_path.write_bytes(make_page(passphrase, salt))
            result, ok, fail = derive_keys.derive_all(passphrase, str(db_dir))
        self.assertEqual((ok, fail), (1, 0))
        self.assertEqual(set(result), {"contact/contact.db"})
        self.assertEqual(set(result["contact/contact.db"]), {"enc_key", "salt", "size_mb"})
        self.assertEqual(result["contact/contact.db"]["salt"], salt.hex())

    def test_load_passphrase_rejects_legacy_enckey(self):
        marker = "en" + "ckey:" + bytes(range(32)).hex()
        with tempfile.TemporaryDirectory(prefix="wx-chatlog-test-") as temp_dir:
            path = Path(temp_dir) / "material.txt"
            path.write_text(marker, encoding="ascii")
            with self.assertRaises(workflow_common.WorkflowConfigError):
                derive_keys.load_passphrase(str(path))


class WechatCliConfigurationTests(unittest.TestCase):
    def test_key_map_validation_normalizes_path(self):
        payload = {
            "contact\\contact.db": {
                "enc_key": "00" * 32,
                "salt": "11" * 16,
                "size_mb": 1.0,
            }
        }
        result = configure_cli.validate_key_map(payload)
        self.assertEqual(set(result), {"contact/contact.db"})

    def test_key_map_validation_rejects_parent_traversal(self):
        payload = {
            "../outside.db": {
                "enc_key": "00" * 32,
                "salt": "11" * 16,
            }
        }
        with self.assertRaises(workflow_common.WorkflowConfigError):
            configure_cli.validate_key_map(payload)

    def test_key_map_validation_rejects_windows_absolute_path(self):
        payload = {
            "C:/outside.db": {
                "enc_key": "00" * 32,
                "salt": "11" * 16,
            }
        }
        with self.assertRaises(workflow_common.WorkflowConfigError):
            configure_cli.validate_key_map(payload)

    def test_key_map_validation_rejects_normalized_collision(self):
        info = {"enc_key": "00" * 32, "salt": "11" * 16, "size_mb": 1.0}
        payload = {"contact\\contact.db": info, "contact/contact.db": info}
        with self.assertRaises(workflow_common.WorkflowConfigError):
            configure_cli.validate_key_map(payload)

    def test_key_map_validation_rejects_non_finite_size(self):
        payload = {
            "contact/contact.db": {
                "enc_key": "00" * 32,
                "salt": "11" * 16,
                "size_mb": float("nan"),
            }
        }
        with self.assertRaises(workflow_common.WorkflowConfigError):
            configure_cli.validate_key_map(payload)


class PrivacyCheckTests(unittest.TestCase):
    def test_only_exact_github_noreply_address_is_allowed(self):
        generic = "noreply" + "@github.com"
        personal = "person" + "@github.com"
        nonstandard_masked = "12345+sample" + "@users.noreply.github.org"
        self.assertNotIn(
            "email",
            {item["category"] for item in privacy._scan_text(
                generic, "fixture.txt", "test"
            )},
        )
        self.assertIn(
            "email",
            {item["category"] for item in privacy._scan_text(
                personal, "fixture.txt", "test"
            )},
        )
        self.assertIn(
            "email",
            {item["category"] for item in privacy._scan_text(
                nonstandard_masked, "fixture.txt", "test"
            )},
        )

    def test_forward_slash_windows_user_path_is_detected_without_value_echo(self):
        private_path = "C:" + "/Users/" + "sample/private"
        findings = privacy._scan_text(
            "configured at " + private_path, "fixture.txt", "test"
        )
        self.assertIn("windows_user_path", {item["category"] for item in findings})
        self.assertNotIn(private_path, str(findings))

    def test_binary_or_large_content_is_not_treated_as_scanned_text(self):
        self.assertIsNone(privacy._decode_text(b"prefix\x00secret"))


@unittest.skipUnless(os.name == "nt", "Windows DACL only")
class WindowsDaclTests(unittest.TestCase):
    def test_secure_write_roundtrip_and_verification(self):
        with tempfile.TemporaryDirectory(prefix="wx-chatlog-test-") as temp_dir:
            path = Path(temp_dir) / "private.txt"
            secure_write_text(path, "private")
            self.assertEqual(path.read_text(encoding="utf-8"), "private")

    def test_secure_directory_roundtrip(self):
        with tempfile.TemporaryDirectory(prefix="wx-chatlog-test-") as temp_dir:
            path = Path(temp_dir) / "private-dir"
            path.mkdir()
            child = path / "existing.txt"
            child.write_text("private", encoding="utf-8")
            secure_directory(path)
            self.assertTrue(path.is_dir())
            self.assertEqual(child.read_text(encoding="utf-8"), "private")

    def test_steps_2_to_4_synthetic_end_to_end(self):
        passphrase = bytes(range(32))
        salt = bytes(reversed(range(16)))
        with tempfile.TemporaryDirectory(prefix="wx-chatlog-e2e-") as temp_dir:
            base = Path(temp_dir)
            db_dir = base / "account" / "db_storage"
            db_path = db_dir / "contact" / "contact.db"
            db_path.parent.mkdir(parents=True)
            db_path.write_bytes(make_page(passphrase, salt))

            secrets_dir = base / "sensitive-output"
            dump_dir = secrets_dir / "ctx_dumps"
            dump_dir.mkdir(parents=True)
            (dump_dir / "ctx_test.json").write_text(
                json.dumps({"regions": {"region": passphrase.hex()}}), encoding="utf-8"
            )

            env = os.environ.copy()
            env.update(
                {
                    "WX_DB_DIR": str(db_dir),
                    "WX_SECRETS_DIR": str(secrets_dir),
                    "WX_WORKERS": "1",
                    "WX_SCAN_STEP": "8",
                    "USERPROFILE": str(base / "profile"),
                    "HOME": str(base / "profile"),
                    "PYTHONUTF8": "1",
                }
            )
            commands = (
                [sys.executable, str(SCRIPTS / "2_extract_passphrase.py")],
                [sys.executable, str(SCRIPTS / "3_derive_keys.py")],
                [sys.executable, str(SCRIPTS / "4_configure_wechat_cli.py"), "--apply"],
            )
            combined_output = ""
            for command in commands:
                result = subprocess.run(
                    command, env=env, cwd=ROOT, check=False,
                    capture_output=True, text=True, encoding="utf-8",
                )
                combined_output += result.stdout + result.stderr
                self.assertEqual(result.returncode, 0, combined_output)

            self.assertNotIn(passphrase.hex(), combined_output)
            key_map = json.loads(
                (secrets_dir / "all_keys.json").read_text(encoding="utf-8")
            )
            self.assertEqual(set(key_map), {"contact/contact.db"})
            state_dir = base / "profile" / ".wechat-cli"
            self.assertTrue((state_dir / "all_keys.json").is_file())
            config = json.loads((state_dir / "config.json").read_text(encoding="utf-8"))
            self.assertEqual(config["db_dir"], str(db_dir))


@unittest.skipUnless(os.name == "nt", "Windows debugger structures only")
class CaptureStructureTests(unittest.TestCase):
    def test_windows_x64_structure_sizes(self):
        self.assertEqual(ctypes.sizeof(capture.CONTEXT), 1232)
        self.assertEqual(ctypes.sizeof(capture.DEBUG_EVENT), 176)
        self.assertEqual(ctypes.sizeof(capture.EXCEPTION_DEBUG_INFO), 160)
        self.assertEqual(ctypes.sizeof(capture.STARTUPINFOW), 104)
        self.assertEqual(ctypes.sizeof(capture.PROCESS_INFORMATION), 24)

    def test_patch_byte_roundtrip_in_current_process(self):
        buffer = ctypes.create_string_buffer(b"\x90")
        address = ctypes.addressof(buffer)
        process = capture.kernel32.GetCurrentProcess()
        self.assertTrue(capture._patch_byte(process, address, 0xCC))
        self.assertEqual(buffer.raw[0], 0xCC)
        self.assertTrue(capture._patch_byte(process, address, 0x90))
        self.assertEqual(buffer.raw[0], 0x90)

    def test_capture_refuses_missing_configuration_before_launch(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(capture.main(), 2)


if __name__ == "__main__":
    unittest.main()
