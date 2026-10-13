"""Opt-in native checks against a disposable Keychain, never the login Keychain."""

import json
import os
import re
import secrets
import shlex
import sys
import unittest
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from harness_secrets import KEYCHAIN_STORE_HELPER, process


@unittest.skipUnless(
    sys.platform == "darwin" and os.environ.get("HARNESS_SECRETS_TEST_KEYCHAIN") == "1",
    "requires opt-in native macOS Keychain access",
)
class NativeKeychainTests(unittest.TestCase):
    def test_helper_rechecks_current_protection_and_uses_only_the_reference(self):
        # Shadow Security's calls in a test copy of the real helper. This covers
        # protected/synchronized metadata without enrolling protected credentials
        # or touching the data-protection/login Keychain.
        swift = process.trusted_executable(("/usr/bin/swift",))
        self.assertIsNotNone(swift)
        source = KEYCHAIN_STORE_HELPER.read_text()
        expected = {
            "schema_version": 2,
            "account": "account",
            "created_at": "2026-01-01T00:00:00.000000+00:00",
            "modified_at": "2026-01-02T00:00:00.250000+00:00",
            "has_access_control": False,
            "synchronizable": False,
            "persistent_ref": "cmVmZXJlbmNl",
        }
        shim = """
let scenario = CommandLine.arguments.last!
func SecItemCopyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
  let query = query as! [CFString: Any]
  guard query[kSecReturnData] as? Bool == false,
    query[kSecReturnAttributes] as? Bool == true,
    query[kSecValuePersistentRef] as? Data == Data("reference".utf8),
    query[kSecAttrAccount] == nil else { fatalError("Unsafe metadata query") }
  if scenario == "missing" { return errSecItemNotFound }
  if scenario == "unavailable" { return errSecInteractionNotAllowed }
  var attributes: [CFString: Any] = [
    kSecAttrService: "test.cache", kSecAttrAccount: "account",
    kSecAttrCreationDate: Date(timeIntervalSince1970: 1767225600),
    kSecAttrModificationDate: Date(timeIntervalSince1970: 1767312000.25),
    kSecAttrSynchronizable: scenario == "synchronized",
    kSecValuePersistentRef: Data("reference".utf8),
  ]
  if scenario == "protected" { attributes[kSecAttrAccessControl] = true }
  if scenario == "refreshed" { attributes[kSecAttrModificationDate] = Date() }
  if scenario == "recreated" { attributes[kSecAttrCreationDate] = Date() }
  if scenario == "other-account" { attributes[kSecAttrAccount] = "replacement" }
  if scenario == "other-reference" { attributes[kSecValuePersistentRef] = Data("replacement".utf8) }
  result?.pointee = attributes as CFDictionary
  return errSecSuccess
}
func SecItemDelete(_ query: CFDictionary) -> OSStatus {
  let query = query as! [CFString: Any]
  guard query[kSecValuePersistentRef] as? Data == Data("reference".utf8),
    query[kSecAttrAccount] == nil else { fatalError("Unsafe deletion query") }
  if scenario == "disappeared" { return errSecItemNotFound }
  if scenario == "delete-unavailable" { return errSecInteractionNotAllowed }
  guard scenario == "unchanged" else { fatalError("Changed item deleted") }
  FileHandle.standardOutput.write(Data("deleted-by-reference".utf8))
  return errSecSuccess
}
"""
        # Place the shim's declarations after imports and its argument adjustment
        # after the helper has copied argv, before argument validation.
        source = source.replace("import Security\n", "import Security\n" + shim)
        source = source.replace(
            "var arguments = Array(CommandLine.arguments.dropFirst())",
            "var arguments = Array(CommandLine.arguments.dropFirst())\narguments.removeLast()",
        )
        with TemporaryDirectory() as directory:
            root = Path(directory)
            helper = root / "guard.swift"
            helper.write_text(source)

            def run(mode, scenario, request):
                return process.run(
                    [
                        swift,
                        "-module-cache-path",
                        str(root / "modules"),
                        str(helper),
                        mode,
                        "test.cache",
                        scenario,
                    ],
                    input_text=json.dumps(request),
                    environment=process.child_environment(
                        ("DEVELOPER_DIR", "SDKROOT", "TOOLCHAINS")
                    ),
                    timeout=120,
                )

            for scenario, status in (
                ("unchanged", 0),
                ("missing", 44),
                ("protected", 45),
                ("synchronized", 45),
                ("refreshed", 45),
                ("recreated", 45),
                ("other-account", 45),
                ("other-reference", 45),
                ("disappeared", 44),
                ("unavailable", 1),
                ("delete-unavailable", 1),
            ):
                with self.subTest(scenario=scenario):
                    result = run("--delete-if-unchanged", scenario, expected)
                    self.assertEqual(
                        result.returncode, status, "Guard helper returned wrong status"
                    )
                    self.assertEqual(
                        result.stdout, "deleted-by-reference" if status == 0 else ""
                    )
                    if status == 1:
                        self.assertIn(
                            "[keychain-store][error] Unable to", result.stderr
                        )
            for scenario, field in (
                ("protected", "has_access_control"),
                ("synchronized", "synchronizable"),
            ):
                result = run(
                    "--inspect",
                    scenario,
                    {"schema_version": 2, "persistent_ref": expected["persistent_ref"]},
                )
                self.assertEqual(result.returncode, 0, "Value-free inspection failed")
                self.assertIs(json.loads(result.stdout)["items"][0][field], True)

    def test_fresh_reads_partition_update_behavior_and_locked_failures(self):
        swift = process.trusted_executable(("/usr/bin/swift",))
        security = process.trusted_executable(("/usr/bin/security",))
        self.assertIsNotNone(swift)
        self.assertIsNotNone(security)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            # macOS enables partition ACLs only under ~/Library/Keychains.
            # A unique disposable file there exercises the login Keychain format.
            keychain = str(
                Path.home()
                / "Library"
                / "Keychains"
                / f"harness-secrets-test-{secrets.token_hex(12)}.keychain"
            )
            keychain_files = (Path(keychain), Path(keychain + "-db"))
            password = secrets.token_hex(32)

            def security_command(*arguments):
                # Even this disposable Keychain's password travels only on stdin.
                result = process.run(
                    [security, "-i"],
                    input_text=shlex.join(arguments) + "\n",
                    environment=process.child_environment(),
                    timeout=30,
                )
                self.assertEqual(result.returncode, 0, "Keychain command failed")

            def helper(*arguments, value=None):
                return process.run(
                    [
                        swift,
                        "-module-cache-path",
                        str(root / "modules"),
                        str(KEYCHAIN_STORE_HELPER),
                        "--keychain",
                        keychain,
                        *arguments,
                    ],
                    input_text=value,
                    environment=process.child_environment(
                        ("DEVELOPER_DIR", "SDKROOT", "TOOLCHAINS")
                    ),
                    timeout=120,
                )

            def partitions():
                result = process.run(
                    [security, "dump-keychain", "-a", keychain],
                    environment=process.child_environment(),
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0, "Keychain metadata read failed")
                entries = re.findall(
                    r"\bpartition_id\b.*?\n\s*description: ([^\n]+)",
                    result.stdout + result.stderr,
                    re.DOTALL,
                )
                self.assertTrue(entries, "No partition metadata returned")
                return entries

            try:
                security_command("create-keychain", "-p", password, keychain)
                self.assertTrue(
                    any(path.exists() for path in keychain_files),
                    "Test Keychain was not created",
                )
                security_command("unlock-keychain", "-p", password, keychain)
                for service in (
                    "test.harness-secrets.cache",
                    "test.harness-secrets.token",
                ):
                    with self.subTest(service=service):
                        missing = helper("--read", service, "profile")
                        self.assertEqual(missing.returncode, 44)
                        self.assertEqual(missing.stdout, "")
                        written = helper(
                            service, "profile", "Test item", value="first value"
                        )
                        self.assertEqual(
                            written.returncode, 0, "Fresh item write failed"
                        )
                        read = helper("--read", service, "profile")
                        self.assertEqual(read.returncode, 0, "Fresh item read failed")
                        self.assertEqual(read.stdout, "first value")

                original = partitions()
                self.assertTrue(all("apple:" in entry for entry in original))
                self.assertTrue(all("apple-tool:" not in entry for entry in original))
                security_command(
                    "set-generic-password-partition-list",
                    "-S",
                    "apple-tool:,apple:",
                    "-a",
                    "profile",
                    "-s",
                    "test.harness-secrets.cache",
                    "-k",
                    password,
                    keychain,
                )
                modified = partitions()
                self.assertTrue(any("apple-tool:" in entry for entry in modified))
                updated = helper(
                    "test.harness-secrets.cache",
                    "profile",
                    "Updated label",
                    value="second value",
                )
                self.assertEqual(updated.returncode, 0, "Item update failed")
                # SecItemUpdate regenerates the partition ACL for swift-frontend,
                # undoing the security CLI stopgap. Swift can still read the item.
                self.assertEqual(partitions(), original)
                self.assertEqual(
                    helper("--read", "test.harness-secrets.cache", "profile").stdout,
                    "second value",
                )

                ordinary_service = "test.harness-secrets.ordinary"
                self.assertEqual(helper("--list", ordinary_service).returncode, 44)
                for account, value in (("z", "exact 🔑 value \r\n"), ("a", "")):
                    written = helper(
                        "--put",
                        ordinary_service,
                        account,
                        "Ordinary secret",
                        value=value,
                    )
                    self.assertEqual(written.returncode, 0, "Exact item write failed")
                    read = helper("--read", ordinary_service, account)
                    self.assertEqual(read.returncode, 0, "Exact item read failed")
                    self.assertEqual(read.stdout, value)
                listed = helper("--list", ordinary_service)
                self.assertEqual(listed.returncode, 0, "Metadata listing failed")
                payload = json.loads(listed.stdout)
                self.assertEqual(set(payload), {"schema_version", "items"})
                self.assertEqual(payload["schema_version"], 2)
                self.assertEqual(
                    [item["account"] for item in payload["items"]], ["a", "z"]
                )
                self.assertNotIn("exact 🔑 value", listed.stdout)
                for item in payload["items"]:
                    self.assertEqual(
                        set(item),
                        {
                            "account",
                            "created_at",
                            "modified_at",
                            "has_access_control",
                            "synchronizable",
                            "persistent_ref",
                        },
                    )
                    self.assertIs(item["has_access_control"], False)
                    self.assertIs(item["synchronizable"], False)
                    self.assertTrue(item["persistent_ref"])
                    created = datetime.fromisoformat(item["created_at"])
                    modified = datetime.fromisoformat(item["modified_at"])
                    self.assertIsNotNone(created.tzinfo)
                    self.assertIsNotNone(modified.tzinfo)
                    self.assertGreaterEqual(modified, created)
                    inspected = helper(
                        "--inspect",
                        ordinary_service,
                        value=json.dumps(
                            {
                                "schema_version": 2,
                                "persistent_ref": item["persistent_ref"],
                            }
                        ),
                    )
                    self.assertEqual(
                        inspected.returncode, 0, "Reference inspection failed"
                    )
                    self.assertEqual(json.loads(inspected.stdout)["items"], [item])
                    wrong_service = helper(
                        "--inspect",
                        "test.other.service",
                        value=json.dumps(
                            {
                                "schema_version": 2,
                                "persistent_ref": item["persistent_ref"],
                            }
                        ),
                    )
                    self.assertEqual(wrong_service.returncode, 44)

                def guarded(item, service=ordinary_service):
                    return helper(
                        "--delete-if-unchanged",
                        service,
                        value=json.dumps({"schema_version": 2, **item}),
                    )

                a, z = payload["items"]
                for changed in (
                    {**a, "account": "different"},
                    {**a, "created_at": "2000-01-01T00:00:00.000Z"},
                    {**a, "modified_at": "2000-01-01T00:00:00.000Z"},
                    {**a, "has_access_control": True},
                    {**a, "synchronizable": True},
                ):
                    self.assertEqual(guarded(changed).returncode, 45)
                    self.assertEqual(
                        helper("--read", ordinary_service, "a").returncode, 0
                    )
                self.assertEqual(guarded(a, "test.other.service").returncode, 44)
                self.assertEqual(
                    helper(
                        "--put",
                        ordinary_service,
                        "z",
                        "Refreshed",
                        value="refreshed value",
                    ).returncode,
                    0,
                )
                self.assertEqual(
                    guarded(z).returncode, 45, "Refreshed item was deleted"
                )
                self.assertEqual(
                    helper("--read", ordinary_service, "z").stdout, "refreshed value"
                )
                current_z = json.loads(
                    helper(
                        "--inspect",
                        ordinary_service,
                        value=json.dumps(
                            {"schema_version": 2, "persistent_ref": z["persistent_ref"]}
                        ),
                    ).stdout
                )["items"][0]
                self.assertEqual(
                    guarded(current_z).returncode, 0, "Unchanged item was not deleted"
                )
                self.assertEqual(
                    helper("--read", ordinary_service, "a").returncode,
                    0,
                    "Guarded deletion affected another account",
                )
                self.assertEqual(guarded(current_z).returncode, 44)
                self.assertEqual(
                    helper("--delete", ordinary_service, "a").returncode, 0
                )
                self.assertEqual(
                    helper(
                        "--put",
                        ordinary_service,
                        "a",
                        "Replacement",
                        value="replacement value",
                    ).returncode,
                    0,
                )
                self.assertIn(
                    guarded(a).returncode,
                    (44, 45),
                    "Old reference targeted a replacement",
                )
                # File-based Keychains may reuse a persistent reference for a
                # recreated account. Creation/modification dates still guard it.
                self.assertEqual(
                    helper("--read", ordinary_service, "a").stdout, "replacement value"
                )
                for account in ("a", "z", "z", "absent"):
                    deleted = helper("--delete", ordinary_service, account)
                    self.assertEqual(deleted.returncode, 0, "Item deletion failed")
                    self.assertEqual(
                        helper("--read", ordinary_service, account).returncode, 44
                    )
                self.assertEqual(helper("--list", ordinary_service).returncode, 44)
                # Sweeping ordinary items never affects another service.
                self.assertEqual(
                    helper("--read", "test.harness-secrets.token", "profile").stdout,
                    "first value",
                )

                security_command("lock-keychain", keychain)
                locked = helper("--read", "test.harness-secrets.cache", "profile")
                self.assertNotEqual(locked.returncode, 0)
                self.assertEqual(locked.stdout, "")
                self.assertIn("Unable to read the Keychain item.", locked.stderr)
                locked_write = helper(
                    "test.harness-secrets.cache",
                    "profile",
                    "Test item",
                    value="third value",
                )
                self.assertNotEqual(locked_write.returncode, 0)
                self.assertEqual(locked_write.stdout, "")
                unavailable = process.run(
                    [
                        swift,
                        "-module-cache-path",
                        str(root / "modules"),
                        str(KEYCHAIN_STORE_HELPER),
                        "--keychain",
                        str(root / "absent.keychain"),
                        "--read",
                        "test.harness-secrets.cache",
                        "profile",
                    ],
                    environment=process.child_environment(),
                    timeout=120,
                )
                self.assertNotEqual(unavailable.returncode, 0)
                self.assertEqual(unavailable.stdout, "")
            finally:
                if any(path.exists() for path in keychain_files):
                    security_command("delete-keychain", keychain)
                self.assertFalse(
                    any(path.exists() for path in keychain_files),
                    "Disposable Keychain was not removed",
                )
