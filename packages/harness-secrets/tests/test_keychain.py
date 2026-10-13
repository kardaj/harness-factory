import base64
import json
import os
import unittest
from dataclasses import fields, replace
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from harness_secrets import (
    KEYCHAIN_STORE_HELPER,
    KeychainItemMetadata,
    KeychainUnavailable,
    MacOSKeychainStore,
    SecretValue,
    process,
)


class KeychainStoreTests(unittest.TestCase):
    def setUp(self):
        with (
            patch(
                "harness_secrets.keychain.process.trusted_executable",
                return_value="/usr/bin/swift",
            ),
            patch(
                "harness_secrets.keychain.process.trusted_file",
                return_value=str(KEYCHAIN_STORE_HELPER),
            ),
        ):
            self.store = MacOSKeychainStore(service="test.cache", label="Cached token")
        self.item = {
            "account": "account",
            "created_at": "2026-01-01T00:00:00.000Z",
            "modified_at": "2026-01-02T00:00:00.250Z",
            "has_access_control": False,
            "synchronizable": False,
            "persistent_ref": base64.b64encode(b"opaque-reference").decode("ascii"),
        }
        self.metadata = KeychainItemMetadata(
            account="account",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            modified_at=datetime(2026, 1, 2, microsecond=250000, tzinfo=timezone.utc),
            has_access_control=False,
            synchronizable=False,
            persistent_ref=b"opaque-reference",
        )

    def metadata_result(self, *items):
        return process.ProcessResult(
            0, json.dumps({"schema_version": 2, "items": items}), ""
        )

    def operations(self):
        return (
            ("get", lambda: self.store.get("account")),
            ("put", lambda: self.store.put("account", SecretValue("private-token"))),
            ("delete", lambda: self.store.delete("account")),
            ("list", lambda: self.store.list()),
            ("inspect", lambda: self.store.inspect(b"opaque-reference")),
            (
                "delete_if_unchanged",
                lambda: self.store.delete_if_unchanged(self.metadata),
            ),
        )

    def test_get_returns_redacted_exact_values_or_none(self):
        for value in ("token \r\n", "", "unicode 🔑"):
            with (
                self.subTest(value=value),
                patch(
                    "harness_secrets.keychain.process.run",
                    return_value=process.ProcessResult(0, value, ""),
                ) as run,
            ):
                result = self.store.get("account")
            self.assertIsInstance(result, SecretValue)
            self.assertEqual(result.reveal(), value)
            self.assertEqual(repr(result), "<redacted>")
            self.assertEqual(
                run.call_args.args[0],
                [
                    "/usr/bin/swift",
                    str(KEYCHAIN_STORE_HELPER),
                    "--read",
                    "test.cache",
                    "account",
                ],
            )
        with patch(
            "harness_secrets.keychain.process.run",
            return_value=process.ProcessResult(44, "discard", "discard"),
        ):
            self.assertIsNone(self.store.get("account"))

    def test_put_sends_exact_value_only_to_stdin_and_uses_bounded_environment(self):
        for value in ("", "private-token \r\n", SecretValue("private-token")):
            with (
                self.subTest(value=type(value).__name__),
                patch.dict(
                    os.environ,
                    {
                        "OP_SERVICE_ACCOUNT_TOKEN": "ambient-token",
                        "UNRELATED_SECRET": "ambient-secret",
                    },
                ),
                patch(
                    "harness_secrets.keychain.process.run",
                    return_value=process.ProcessResult(0, "", ""),
                ) as run,
            ):
                self.assertIsNone(self.store.put("account", value))
            self.assertEqual(
                run.call_args.args[0],
                [
                    "/usr/bin/swift",
                    str(KEYCHAIN_STORE_HELPER),
                    "--put",
                    "test.cache",
                    "account",
                    "Cached token: account",
                ],
            )
            self.assertEqual(
                run.call_args.kwargs["input_text"],
                value.reveal() if isinstance(value, SecretValue) else value,
            )
            self.assertEqual(run.call_args.kwargs["timeout"], 120)
            self.assertNotIn("private-token", repr(run.call_args.args))
            environment = run.call_args.kwargs["environment"]
            self.assertNotIn("private-token", repr(environment))
            self.assertNotIn("OP_SERVICE_ACCOUNT_TOKEN", environment)
            self.assertNotIn("UNRELATED_SECRET", environment)
            self.assertEqual(environment["PATH"], process.SYSTEM_PATH)

    def test_put_rejects_non_string_values_with_a_fixed_error(self):
        with patch("harness_secrets.keychain.process.run") as run:
            with self.assertRaisesRegex(
                TypeError, "Keychain values must be strings or SecretValue instances"
            ):
                self.store.put("account", b"private-token")
        run.assert_not_called()

    def test_delete_uses_helper_and_missing_is_harmless(self):
        for status in (0, 44):
            with (
                self.subTest(status=status),
                patch(
                    "harness_secrets.keychain.process.run",
                    return_value=process.ProcessResult(status, "", ""),
                ) as run,
            ):
                self.assertIsNone(self.store.delete("account"))
            self.assertEqual(
                run.call_args.args[0],
                [
                    "/usr/bin/swift",
                    str(KEYCHAIN_STORE_HELPER),
                    "--delete",
                    "test.cache",
                    "account",
                ],
            )
            self.assertIsNone(run.call_args.kwargs["input_text"])

    def test_list_returns_sorted_metadata_with_utc_dates_and_service_scope(self):
        item = {
            "account": "z",
            "created_at": "2026-01-01T01:00:00+01:00",
            "modified_at": "2026-01-02T00:00:00.250Z",
        }
        payload = {"schema_version": 1, "items": [item, {**item, "account": "a"}]}
        with patch(
            "harness_secrets.keychain.process.run",
            return_value=process.ProcessResult(0, json.dumps(payload), ""),
        ) as run:
            result = self.store.list("another.service")
        self.assertEqual(
            run.call_args.args[0],
            ["/usr/bin/swift", str(KEYCHAIN_STORE_HELPER), "--list", "another.service"],
        )
        self.assertEqual(tuple(item.account for item in result), ("a", "z"))
        self.assertEqual(
            result[0].created_at, datetime(2026, 1, 1, tzinfo=timezone.utc)
        )
        self.assertEqual(
            result[0].modified_at,
            datetime(2026, 1, 2, microsecond=250000, tzinfo=timezone.utc),
        )
        self.assertEqual(
            {field.name for field in fields(KeychainItemMetadata)},
            {
                "account",
                "created_at",
                "modified_at",
                "has_access_control",
                "synchronizable",
                "persistent_ref",
            },
        )
        # A custom version-1 helper still lists, but cannot authorize a sweep.
        self.assertIsNone(result[0].has_access_control)
        self.assertIsNone(result[0].synchronizable)
        self.assertIsNone(result[0].persistent_ref)
        with patch("harness_secrets.keychain.process.run") as run:
            self.assertFalse(self.store.delete_if_unchanged(result[0]))
        run.assert_not_called()

    def test_rich_metadata_contains_protection_sync_and_opaque_reference(self):
        for protected, synchronized in (
            (False, False),
            (True, False),
            (False, True),
            (True, True),
        ):
            item = {
                **self.item,
                "has_access_control": protected,
                "synchronizable": synchronized,
            }
            with patch(
                "harness_secrets.keychain.process.run",
                return_value=self.metadata_result(item),
            ):
                result = self.store.list()[0]
            self.assertIs(result.has_access_control, protected)
            self.assertIs(result.synchronizable, synchronized)
            self.assertEqual(result.persistent_ref, b"opaque-reference")
            self.assertNotIn("opaque-reference", repr(result))

    def test_inspect_requests_only_a_reference_over_stdin_and_checks_identity(self):
        with patch(
            "harness_secrets.keychain.process.run",
            return_value=self.metadata_result(self.item),
        ) as run:
            self.assertEqual(
                self.store.inspect(b"opaque-reference", service="other.service"),
                self.metadata,
            )
        self.assertEqual(run.call_args.args[0][-2:], ["--inspect", "other.service"])
        self.assertNotIn("opaque-reference", repr(run.call_args.args))
        self.assertEqual(
            json.loads(run.call_args.kwargs["input_text"]),
            {"schema_version": 2, "persistent_ref": self.item["persistent_ref"]},
        )
        with patch(
            "harness_secrets.keychain.process.run",
            return_value=process.ProcessResult(44, "discard", "discard"),
        ):
            self.assertIsNone(self.store.inspect(b"opaque-reference"))
        for items in (
            (),
            (self.item, self.item),
            ({**self.item, "persistent_ref": "b3RoZXI="},),
        ):
            with (
                self.subTest(items=items),
                patch(
                    "harness_secrets.keychain.process.run",
                    return_value=self.metadata_result(*items),
                ),
                self.assertRaises(KeychainUnavailable) as raised,
            ):
                self.store.inspect(b"opaque-reference")
            self.assertEqual(str(raised.exception), "Keychain is locked or unavailable")

    def test_inspect_rejects_invalid_references_without_a_child(self):
        for value in (None, "private-token", b"", bytearray(b"reference")):
            with (
                self.subTest(value=type(value).__name__),
                patch("harness_secrets.keychain.process.run") as run,
                self.assertRaisesRegex(
                    ValueError, "^Invalid Keychain persistent reference$"
                ),
            ):
                self.store.inspect(value)
            run.assert_not_called()

    def test_guarded_delete_uses_one_helper_and_skips_missing_or_changed(self):
        for status, deleted in ((0, True), (44, False), (45, False)):
            with (
                self.subTest(status=status),
                patch(
                    "harness_secrets.keychain.process.run",
                    return_value=process.ProcessResult(status, "", ""),
                ) as run,
            ):
                self.assertIs(
                    self.store.delete_if_unchanged(
                        self.metadata, service="other.service"
                    ),
                    deleted,
                )
            run.assert_called_once()
            self.assertEqual(
                run.call_args.args[0][-2:], ["--delete-if-unchanged", "other.service"]
            )
            request = json.loads(run.call_args.kwargs["input_text"])
            self.assertEqual(set(request), {"schema_version", *self.item})
            self.assertEqual(request["persistent_ref"], self.item["persistent_ref"])
            self.assertEqual(request["account"], self.metadata.account)
            self.assertEqual(
                datetime.fromisoformat(request["modified_at"]),
                self.metadata.modified_at,
            )
            self.assertEqual(
                datetime.fromisoformat(request["created_at"]), self.metadata.created_at
            )
            self.assertIs(request["has_access_control"], False)
            self.assertIs(request["synchronizable"], False)

    def test_guarded_delete_preserves_protected_synced_or_unknown_items(self):
        for metadata in (
            replace(self.metadata, has_access_control=True),
            replace(self.metadata, synchronizable=True),
            replace(self.metadata, has_access_control=None),
            replace(self.metadata, synchronizable=None),
            replace(self.metadata, persistent_ref=None),
        ):
            with (
                self.subTest(metadata=metadata),
                patch("harness_secrets.keychain.process.run") as run,
            ):
                self.assertFalse(self.store.delete_if_unchanged(metadata))
            run.assert_not_called()

    def test_guarded_delete_rejects_invalid_expected_metadata(self):
        for metadata in (
            replace(self.metadata, created_at=datetime(2026, 1, 1)),
            replace(self.metadata, modified_at="private-token"),
            replace(self.metadata, persistent_ref=b""),
            replace(self.metadata, account=None),
        ):
            with (
                self.subTest(metadata=metadata),
                patch("harness_secrets.keychain.process.run") as run,
                self.assertRaisesRegex(
                    ValueError, "^Invalid expected Keychain metadata$"
                ),
            ):
                self.store.delete_if_unchanged(metadata)
            run.assert_not_called()

    def test_changed_exit_is_valid_only_for_guarded_deletion(self):
        for name, operation in self.operations():
            if name == "delete_if_unchanged":
                continue
            with (
                self.subTest(operation=name),
                patch(
                    "harness_secrets.keychain.process.run",
                    return_value=process.ProcessResult(
                        45, "private-token", "private-token"
                    ),
                ),
                self.assertRaises(KeychainUnavailable) as raised,
            ):
                operation()
            self.assertEqual(str(raised.exception), "Keychain is locked or unavailable")

    def test_rich_metadata_rejects_unknown_fields_bad_booleans_and_references(self):
        for change in (
            {"has_access_control": 0},
            {"has_access_control": None},
            {"synchronizable": "false"},
            {"synchronizable": 1},
            {"persistent_ref": "!private-token!"},
            {"persistent_ref": ""},
            {"persistent_ref": 12},
            {"value": "private-token"},
        ):
            for operation in (
                self.store.list,
                lambda: self.store.inspect(b"opaque-reference"),
            ):
                with (
                    self.subTest(change=change),
                    patch(
                        "harness_secrets.keychain.process.run",
                        return_value=self.metadata_result({**self.item, **change}),
                    ),
                    self.assertRaises(KeychainUnavailable) as raised,
                ):
                    operation()
                self.assertEqual(
                    str(raised.exception), "Keychain is locked or unavailable"
                )

    def test_list_with_no_matches_is_empty(self):
        for result in (
            process.ProcessResult(44, "", ""),
            process.ProcessResult(0, '{"schema_version":1,"items":[]}', ""),
        ):
            with (
                self.subTest(status=result.returncode),
                patch(
                    "harness_secrets.keychain.process.run", return_value=result
                ) as run,
            ):
                self.assertEqual(self.store.list(), ())
            self.assertEqual(run.call_args.args[0][-2:], ["--list", "test.cache"])

    def test_list_rejects_malformed_metadata_and_never_exposes_output(self):
        item = {
            "account": "a",
            "created_at": "2026-01-01T00:00:00Z",
            "modified_at": "2026-01-01T00:00:00Z",
        }
        for payload in (
            None,
            [],
            {"schema_version": 3, "items": []},
            {"schema_version": True, "items": []},
            {"schema_version": 1, "items": [], "private-token": "value"},
            {"schema_version": 1, "items": {}},
            *(
                {"schema_version": 1, "items": [entry]}
                for entry in (
                    None,
                    {},
                    {**item, "value": "private-token"},
                    {**item, "account": 1},
                    {**item, "created_at": "private-token"},
                    {**item, "modified_at": "2026-01-01"},
                    {**item, "created_at": None},
                )
            ),
        ):
            with (
                self.subTest(payload=payload),
                patch(
                    "harness_secrets.keychain.process.run",
                    return_value=process.ProcessResult(
                        0, json.dumps(payload), "private-token"
                    ),
                ),
                self.assertRaises(KeychainUnavailable) as raised,
            ):
                self.store.list()
            self.assertEqual(str(raised.exception), "Keychain is locked or unavailable")
        with (
            patch(
                "harness_secrets.keychain.process.run",
                return_value=process.ProcessResult(0, "private-token", ""),
            ),
            self.assertRaises(KeychainUnavailable) as raised,
        ):
            self.store.list()
        self.assertEqual(str(raised.exception), "Keychain is locked or unavailable")

    def test_every_operation_maps_process_failures_to_fixed_redacted_reasons(self):
        for name, operation in self.operations():
            for failure, reason in (
                (
                    process.ExecutableUnavailable("private-token"),
                    "macOS security CLI is unavailable",
                ),
                (
                    process.ProcessTimeout("private-token"),
                    "Keychain is locked or unavailable",
                ),
                (
                    process.OutputLimitExceeded("private-token"),
                    "Keychain is locked or unavailable",
                ),
                (
                    UnicodeEncodeError("utf-8", "private-token", 0, 1, "invalid"),
                    "Keychain is locked or unavailable",
                ),
                (
                    process.ProcessResult(1, "private-token", "private-token"),
                    "Keychain is locked or unavailable",
                ),
            ):
                options = (
                    {"side_effect": failure}
                    if isinstance(failure, Exception)
                    else {"return_value": failure}
                )
                with (
                    self.subTest(operation=name, failure=type(failure).__name__),
                    patch("harness_secrets.keychain.process.run", **options),
                    self.assertRaises(KeychainUnavailable) as raised,
                ):
                    operation()
                self.assertEqual(str(raised.exception), reason)
                self.assertEqual(raised.exception.reason, reason)
                self.assertIsNone(raised.exception.__cause__)
        with (
            patch(
                "harness_secrets.keychain.process.run",
                return_value=process.ProcessResult(44, "private-token", ""),
            ),
            self.assertRaises(KeychainUnavailable) as raised,
        ):
            self.store.put("account", "private-token")
        self.assertEqual(str(raised.exception), "Keychain is locked or unavailable")

    def test_missing_or_untrusted_swift_never_starts_a_child(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "swift"
            path.write_text("#!/bin/sh\nexit 0\n")
            path.chmod(0o777)
            for candidate in (str(path), str(path.parent / "absent"), "swift"):
                self.store = MacOSKeychainStore(
                    service="test.cache", label="Cache", swift_path=candidate
                )
                for name, operation in self.operations():
                    with (
                        self.subTest(candidate=candidate, operation=name),
                        patch("harness_secrets.keychain.process.run") as run,
                        self.assertRaises(KeychainUnavailable) as raised,
                    ):
                        operation()
                    run.assert_not_called()
                    self.assertEqual(
                        str(raised.exception), "macOS security CLI is unavailable"
                    )

    def helper_store(self, helper: Path) -> MacOSKeychainStore:
        with patch(
            "harness_secrets.keychain.process.trusted_executable",
            return_value="/usr/bin/swift",
        ):
            return MacOSKeychainStore(
                service="test.cache", label="Cache", store_helper=helper
            )

    def test_trusted_helper_is_run_by_its_resolved_path(self):
        with TemporaryDirectory() as directory:
            helper = Path(directory) / "store.swift"
            helper.write_text("// helper\n")
            helper.chmod(0o644)
            self.store = self.helper_store(helper)
            with patch(
                "harness_secrets.keychain.process.run",
                return_value=process.ProcessResult(0, "", ""),
            ) as run:
                self.store.delete("account")
            self.assertEqual(
                run.call_args.args[0][:2],
                ["/usr/bin/swift", str(helper.resolve())],
            )

    def test_untrusted_helper_never_starts_a_child(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            group_writable = root / "group.swift"
            world_writable = root / "world.swift"
            writable_directory = root / "writable"
            writable_directory.mkdir()
            in_writable_directory = writable_directory / "store.swift"
            for path, mode in (
                (group_writable, 0o664),
                (world_writable, 0o646),
                (in_writable_directory, 0o644),
            ):
                path.write_text("// helper\n")
                path.chmod(mode)
            writable_directory.chmod(0o777)
            for helper in (
                group_writable,
                world_writable,
                in_writable_directory,
                root / "absent.swift",
            ):
                self.store = self.helper_store(helper)
                for name, operation in self.operations():
                    with (
                        self.subTest(helper=helper.name, operation=name),
                        patch("harness_secrets.keychain.process.run") as run,
                        self.assertRaises(KeychainUnavailable) as raised,
                    ):
                        operation()
                    run.assert_not_called()
                    self.assertEqual(
                        str(raised.exception),
                        "Keychain helper is missing or untrusted",
                    )
                    self.assertNotIn("private-token", str(raised.exception))
