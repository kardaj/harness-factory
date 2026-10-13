"""Non-interactive ordinary secrets, accessed through one trusted Swift identity."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from harness_secrets import process
from harness_secrets.values import SecretValue

SWIFT_CANDIDATES = ("/usr/bin/swift",)
SWIFT_ENV_VARS = ("DEVELOPER_DIR", "SDKROOT", "TOOLCHAINS")
KEYCHAIN_ITEM_NOT_FOUND = 44
KEYCHAIN_ITEM_CHANGED = 45
KEYCHAIN_STORE_HELPER = Path(__file__).resolve().parent / "store_keychain_secret.swift"
KEYCHAIN_UNAVAILABLE = "Keychain is locked or unavailable"
KEYCHAIN_HELPER_UNTRUSTED = "Keychain helper is missing or untrusted"
# Kept for compatibility with the existing 1Password failure reasons.
SECURITY_UNAVAILABLE = "macOS security CLI is unavailable"


class KeychainUnavailable(RuntimeError):
    """The Keychain or its helper could not answer; carries a fixed ``reason``."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class KeychainItemMetadata:
    """Value-free metadata; references are opaque and local to this Keychain."""

    account: str
    created_at: datetime
    modified_at: datetime
    has_access_control: bool | None = None
    synchronizable: bool | None = None
    persistent_ref: bytes | None = field(default=None, repr=False)


class MacOSKeychainStore:
    """Store ordinary generic passwords under a caller-supplied service.

    All operations use the same trusted Swift executable and helper with interaction
    disabled and bounded time/output. Values travel only over stdin/stdout.
    The label is a prefix: stored items are labeled ``LABEL: ACCOUNT``.
    """

    def __init__(
        self,
        *,
        service: str,
        label: str,
        swift_path: str | None = None,
        store_helper: Path | None = None,
    ) -> None:
        self.service = service
        self.label = label
        self.swift_path = process.trusted_executable(
            (swift_path,) if swift_path else SWIFT_CANDIDATES
        )
        self.store_helper = (
            KEYCHAIN_STORE_HELPER if store_helper is None else Path(store_helper)
        )
        self.helper_path = process.trusted_file(self.store_helper)

    def get(self, account: str) -> SecretValue | None:
        """Return an exact value, None if missing, or raise ``KeychainUnavailable``."""
        result = self._run("--read", self.service, account)
        return (
            None
            if result.returncode == KEYCHAIN_ITEM_NOT_FOUND
            else SecretValue(result.stdout)
        )

    def put(self, account: str, value: str | SecretValue) -> None:
        """Store and verify an exact value, including empty strings and newlines."""
        if isinstance(value, SecretValue):
            value = value.reveal()
        if not isinstance(value, str):
            raise TypeError("Keychain values must be strings or SecretValue instances")
        self._run(
            "--put",
            self.service,
            account,
            f"{self.label}: {account}",
            input_text=value,
            missing_ok=False,
        )

    def delete(self, account: str) -> None:
        """Delete an item using the same identity; a missing item is harmless."""
        self._run("--delete", self.service, account)

    def list(self, service: str | None = None) -> tuple[KeychainItemMetadata, ...]:
        """List metadata for a service (defaulting to this store's), never values."""
        result = self._run("--list", self.service if service is None else service)
        if result.returncode == KEYCHAIN_ITEM_NOT_FOUND:
            return ()
        return tuple(
            sorted(
                _metadata(result.stdout),
                key=lambda item: (
                    item.account,
                    item.created_at,
                    item.modified_at,
                    item.persistent_ref or b"",
                ),
            )
        )

    def inspect(
        self, persistent_ref: bytes, *, service: str | None = None
    ) -> KeychainItemMetadata | None:
        """Inspect the referenced item's metadata without requesting its value."""
        result = self._run(
            "--inspect",
            self.service if service is None else service,
            input_text=json.dumps(
                {"schema_version": 2, "persistent_ref": _reference(persistent_ref)}
            ),
        )
        if result.returncode == KEYCHAIN_ITEM_NOT_FOUND:
            return None
        items = _metadata(result.stdout)
        if len(items) != 1 or items[0].persistent_ref != persistent_ref:
            raise KeychainUnavailable(KEYCHAIN_UNAVAILABLE)
        return items[0]

    def delete_if_unchanged(
        self, expected: KeychainItemMetadata, *, service: str | None = None
    ) -> bool:
        """Recheck and delete by reference, skipping changed/protected/synced items.

        This is not an atomic compare-and-delete. Writers must coordinate with
        sweepers if they need to exclude changes between the check and deletion.
        """
        if not isinstance(expected, KeychainItemMetadata):
            raise TypeError("Expected KeychainItemMetadata")
        if (
            expected.has_access_control is not False
            or expected.synchronizable is not False
            or expected.persistent_ref is None
        ):
            return False
        try:
            if not isinstance(expected.account, str) or (
                expected.created_at.tzinfo is None
                or expected.modified_at.tzinfo is None
            ):
                raise ValueError
            payload = {
                "schema_version": 2,
                "account": expected.account,
                "created_at": expected.created_at.astimezone(timezone.utc).isoformat(
                    timespec="microseconds"
                ),
                "modified_at": expected.modified_at.astimezone(timezone.utc).isoformat(
                    timespec="microseconds"
                ),
                "has_access_control": False,
                "synchronizable": False,
                "persistent_ref": _reference(expected.persistent_ref),
            }
        except (AttributeError, TypeError, ValueError):
            raise ValueError("Invalid expected Keychain metadata") from None
        result = self._run(
            "--delete-if-unchanged",
            self.service if service is None else service,
            input_text=json.dumps(payload),
            changed_ok=True,
        )
        return result.returncode == 0

    def _run(
        self,
        *arguments: str,
        input_text: str | None = None,
        missing_ok: bool = True,
        changed_ok: bool = False,
    ) -> process.ProcessResult:
        if self.swift_path is None:
            raise KeychainUnavailable(SECURITY_UNAVAILABLE)
        if self.helper_path is None:
            raise KeychainUnavailable(KEYCHAIN_HELPER_UNTRUSTED)
        try:
            result = process.run(
                [self.swift_path, self.helper_path, *arguments],
                environment=process.child_environment(SWIFT_ENV_VARS),
                input_text=input_text,
                timeout=120,
            )
        except process.ExecutableUnavailable:
            raise KeychainUnavailable(SECURITY_UNAVAILABLE) from None
        except (process.ProcessTimeout, process.OutputLimitExceeded, UnicodeError):
            raise KeychainUnavailable(KEYCHAIN_UNAVAILABLE) from None
        if (
            result.returncode != 0
            and not (missing_ok and result.returncode == KEYCHAIN_ITEM_NOT_FOUND)
            and not (changed_ok and result.returncode == KEYCHAIN_ITEM_CHANGED)
        ):
            raise KeychainUnavailable(KEYCHAIN_UNAVAILABLE)
        return result


def _reference(value: bytes) -> str:
    if not isinstance(value, bytes) or not value:
        raise ValueError("Invalid Keychain persistent reference")
    return base64.b64encode(value).decode("ascii")


def _metadata(output: str) -> tuple[KeychainItemMetadata, ...]:
    try:
        payload = json.loads(output)
        if (
            not isinstance(payload, dict)
            or set(payload) != {"schema_version", "items"}
            or type(payload["schema_version"]) is not int
            or payload["schema_version"] not in (1, 2)
            or not isinstance(payload["items"], list)
        ):
            raise ValueError
        items = []
        for item in payload["items"]:
            fields = {"account", "created_at", "modified_at"}
            if payload["schema_version"] == 2:
                fields |= {"has_access_control", "synchronizable", "persistent_ref"}
            if (
                not isinstance(item, dict)
                or set(item) != fields
                or not isinstance(item["account"], str)
            ):
                raise ValueError
            extra = {}
            if payload["schema_version"] == 2:
                if (
                    type(item["has_access_control"]) is not bool
                    or type(item["synchronizable"]) is not bool
                    or not isinstance(item["persistent_ref"], str)
                ):
                    raise ValueError
                reference = base64.b64decode(item["persistent_ref"], validate=True)
                if not reference:
                    raise ValueError
                extra = {
                    "has_access_control": item["has_access_control"],
                    "synchronizable": item["synchronizable"],
                    "persistent_ref": reference,
                }
            items.append(
                KeychainItemMetadata(
                    account=item["account"],
                    created_at=_date(item["created_at"]),
                    modified_at=_date(item["modified_at"]),
                    **extra,
                )
            )
        return tuple(items)
    except (TypeError, ValueError):
        raise KeychainUnavailable(KEYCHAIN_UNAVAILABLE) from None


def _date(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError
    date = datetime.fromisoformat(value)
    if date.tzinfo is None:
        raise ValueError
    return date.astimezone(timezone.utc)
