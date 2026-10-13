"""Read 1Password references with a service-account token kept in the macOS Keychain.

Tokens never reach command arguments or exception messages: the Keychain
supplies them, ``op`` receives them only in a minimal child environment, and
failures are reported as fixed reasons. References must name their profile's
vault and are read through its resolved vault ID. Resolved values and the vault
ID may be cached in the Keychain, each for a bounded time, so a cache hit makes
no 1Password request.
"""

from __future__ import annotations

import contextlib
import copy
import errno
import fcntl
import hashlib
import json
import os
import time
from collections.abc import Iterator
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from harness_secrets import process
from harness_secrets.keychain import (
    KEYCHAIN_STORE_HELPER,
    KEYCHAIN_UNAVAILABLE,
    KeychainUnavailable,
    MacOSKeychainStore,
)
from harness_secrets.values import SecretValue

CONFLICTING_OP_ENV_VARS = (
    "OP_ACCOUNT",
    "OP_CONNECT_HOST",
    "OP_CONNECT_TOKEN",
    "OP_SERVICE_ACCOUNT_TOKEN",
)
OP_ENV_VARS = (*process.NETWORK_ENV_VARS, "XDG_CONFIG_HOME", "OP_CONFIG_DIR")
SECURITY_CANDIDATES = ("/usr/bin/security",)
OP_CANDIDATES = ("/opt/homebrew/bin/op", "/usr/local/bin/op")
CACHE_SCHEMA_VERSION = 2

RATE_LIMITED = "1Password request limit has been reached"
CREDENTIAL_MISSING = "Keychain credential is missing"
CLI_UNAVAILABLE = "1Password CLI is unavailable"
CLI_TIMEOUT = "1Password CLI timed out"
CLI_OUTPUT = "1Password CLI output exceeded the limit"
CREDENTIAL_INVALID = "service-account credential is invalid or inactive"
UNREADABLE = "reference is unreadable"
EMPTY = "reference resolved to an empty value"
CACHE_WRITE_FAILED = "Keychain cache could not be written"


class OnePasswordError(RuntimeError):
    """A 1Password failure carrying only a fixed, safe ``reason``."""

    reason = UNREADABLE

    def __init__(self, reason: str | None = None) -> None:
        if reason is not None:
            self.reason = reason
        super().__init__(self.reason)


class OnePasswordCliUnavailable(OnePasswordError):
    reason = CLI_UNAVAILABLE


class OnePasswordRateLimited(OnePasswordError):
    reason = RATE_LIMITED


class OnePasswordCommandFailed(OnePasswordError):
    """``op`` failed without a more specific classification."""


class CacheWriteError(RuntimeError):
    """The cache could not be persisted."""


@dataclass(frozen=True)
class OnePasswordProfile:
    """A service account, identified by its Keychain account, and the vault it reads."""

    name: str
    description: str
    vault: str


@dataclass(frozen=True)
class ProfileResolution:
    """Resolved values and fixed failure reasons, keyed by reference.

    ``cache_failure`` reports a cache that could not be written, which would
    otherwise show up only as repeated 1Password requests.
    """

    values: dict[str, SecretValue] = field(default_factory=dict)
    failures: dict[str, str] = field(default_factory=dict)
    cache_failure: str | None = None


def reference_path(reference: str, vault: str) -> str:
    """Return the part of an ``op://`` reference after its vault.

    Raises ``ValueError`` with a fixed reason unless the reference is
    ``op://VAULT/ITEM/[SECTION/]FIELD``, optionally followed by a query, and
    names ``vault``.
    """
    path, _, query = reference.removeprefix("op://").partition("?")
    segments = path.split("/")
    if (
        not reference.startswith("op://")
        or not 3 <= len(segments) <= 4
        or any(not segment or segment != segment.strip() for segment in segments)
        or any(ord(character) < 32 or ord(character) == 127 for character in reference)
        or "?" in query
    ):
        raise ValueError("reference must be op://VAULT/ITEM/[SECTION/]FIELD")
    if segments[0] != vault:
        raise ValueError("reference is outside the profile's vault")
    return reference.removeprefix(f"op://{vault}/")


class CredentialStore(Protocol):
    """Machine credential boundary used by the resolver."""

    def get_token(self, profile: str) -> str | None:
        """Return the profile token, None when missing, or raise ``KeychainUnavailable``."""


class OnePasswordClient(Protocol):
    """Minimal read-only 1Password operations used during rendering.

    Failures raise ``OnePasswordError`` with a fixed reason.
    """

    def authenticate(self, token: str) -> bool:
        """Return whether the token identifies an active service account."""

    def vault_id(self, token: str, vault: str) -> str:
        """Return the ID of a vault the service account can read."""

    def read(self, token: str, reference: str) -> str:
        """Read one op:// reference exactly."""


class OnePasswordSecretCache(Protocol):
    """Short-lived resolved values and vault IDs, each with its own expiry."""

    def get(
        self, profile: str, token: str, vault: str, references: tuple[str, ...]
    ) -> dict[str, str]:
        """Return the unexpired cached values among ``references``."""

    def vault_id(self, profile: str, token: str, vault: str) -> str | None:
        """Return the unexpired cached vault ID."""

    def put(
        self,
        profile: str,
        token: str,
        vault: str,
        values: dict[str, str],
        vault_id: str | None,
    ) -> None:
        """Add fresh entries, keeping other unexpired ones, or raise ``CacheWriteError``."""

    def refreshing(self, profile: str) -> AbstractContextManager[None]:
        """Serialize refreshes of one profile across processes."""

    def clear(self, profile: str) -> None:
        """Remove every cached entry of the profile."""


class MacOSKeychainCredentialStore:
    """Read service-account tokens from the macOS login Keychain."""

    def __init__(
        self,
        *,
        service: str,
        security_path: str | None = None,
        swift_path: str | None = None,
        store_helper: Path = KEYCHAIN_STORE_HELPER,
    ) -> None:
        self.service = service
        # Retained for caller compatibility; reads now use the writer's identity.
        self.security_path = process.trusted_executable(
            (security_path,) if security_path else SECURITY_CANDIDATES
        )
        self.store = MacOSKeychainStore(
            service=service,
            label=service,
            swift_path=swift_path,
            store_helper=store_helper,
        )
        self.swift_path = self.store.swift_path
        self.store_helper = self.store.store_helper

    def get_token(self, profile: str) -> str | None:
        value = self.store.get(profile)
        return None if value is None else value.reveal() or None


class RefreshLock:
    """An exclusive per-profile lock file shared by cooperating processes.

    Waiting is bounded; when the lock cannot be created or acquired in time the
    refresh proceeds unlocked, costing at most a duplicate refresh.
    """

    def __init__(self, directory: Path, *, timeout: float = 30) -> None:
        self.directory = directory
        self.timeout = timeout

    @contextlib.contextmanager
    def hold(self, name: str) -> Iterator[None]:
        with self._hold(name):
            yield

    @contextlib.contextmanager
    def _hold(self, name: str) -> Iterator[bool]:
        """Yield whether contention required waiting, even if the wait timed out."""
        digest = hashlib.sha256(name.encode()).hexdigest()[:24]
        try:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(
                self.directory / f"{digest}.lock", os.O_RDWR | os.O_CREAT, 0o600
            )
        except OSError:
            yield False
            return
        try:
            deadline = time.monotonic() + self.timeout
            waited = False
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError as error:
                    if error.errno not in (errno.EWOULDBLOCK, errno.EAGAIN):
                        break
                    waited = True
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(0.05)
            yield waited
        finally:
            os.close(descriptor)


class MacOSKeychainSecretCache:
    """Keep resolved values and the vault ID in one Keychain item per profile.

    Every entry carries its own expiry, set when it was fetched and never
    extended by reads or later writes. Entries are bound to a fingerprint of
    the service-account token and to the profile's vault, so replacing either
    invalidates them. Reads reject entries that expire further ahead than the
    TTL allows, so a shortened TTL also bounds existing entries. Expired entries
    are dropped on the next write, but stay stored until then.

    Reads and writes use the same Swift helper identity, with values carried
    only over stdout and stdin. ``lock_dir`` holds the per-profile refresh
    lock files; without it refreshes are not coordinated.
    """

    def __init__(
        self,
        *,
        service: str,
        label: str,
        ttl_seconds: int,
        lock_dir: Path | None = None,
        store_helper: Path = KEYCHAIN_STORE_HELPER,
        security_path: str | None = None,
        swift_path: str | None = None,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("1Password cache TTL must be positive")
        self.service = service
        self.label = label
        self.ttl_seconds = ttl_seconds
        self.lock = None if lock_dir is None else RefreshLock(lock_dir)
        self.security_path = process.trusted_executable(
            (security_path,) if security_path else SECURITY_CANDIDATES
        )
        self.store = MacOSKeychainStore(
            service=service,
            label=label,
            swift_path=swift_path,
            store_helper=store_helper,
        )
        self.swift_path = self.store.swift_path
        self.store_helper = self.store.store_helper
        self._entries: dict[tuple[str, str, str], dict] | None = None

    @contextlib.contextmanager
    def _session(self) -> Iterator[MacOSKeychainSecretCache]:
        """Reuse loaded entries only within this resolution, never across calls."""
        session = copy.copy(self)
        session._entries = {}
        try:
            yield session
        finally:
            session._entries.clear()

    def get(
        self, profile: str, token: str, vault: str, references: tuple[str, ...]
    ) -> dict[str, str]:
        values = self._load(profile, token, vault)["values"]
        return {
            reference: values[reference]["value"]
            for reference in references
            if reference in values
        }

    def vault_id(self, profile: str, token: str, vault: str) -> str | None:
        entry = self._load(profile, token, vault)["vault_id"]
        return None if entry is None else entry["value"]

    def put(
        self,
        profile: str,
        token: str,
        vault: str,
        values: dict[str, str],
        vault_id: str | None,
    ) -> None:
        expires_at = time.time() + self.ttl_seconds
        current = self._load(profile, token, vault)
        entry = {
            "schema_version": CACHE_SCHEMA_VERSION,
            "credential": _fingerprint(token),
            "vault": vault,
            "vault_id": (
                current["vault_id"]
                if vault_id is None
                else {"value": vault_id, "expires_at": expires_at}
            ),
            "values": {
                **current["values"],
                **{
                    reference: {"value": value, "expires_at": expires_at}
                    for reference, value in values.items()
                },
            },
        }
        try:
            self.store.put(profile, json.dumps(entry, separators=(",", ":")))
        except KeychainUnavailable:
            raise CacheWriteError(CACHE_WRITE_FAILED) from None
        if self._entries is not None:
            self._entries[(profile, _fingerprint(token), vault)] = entry

    @contextlib.contextmanager
    def refreshing(self, profile: str) -> Iterator[None]:
        if self.lock is None:
            yield
            return
        with self.lock._hold(f"{self.service}\0{profile}") as waited:
            if waited and self._entries is not None:
                self._entries.clear()
            yield

    def clear(self, profile: str) -> None:
        self.store.delete(profile)
        if self._entries is not None:
            self._entries.clear()

    def _load(self, profile: str, token: str, vault: str) -> dict:
        """Return the unexpired entries bound to this credential and vault."""
        key = (profile, _fingerprint(token), vault)
        if self._entries is not None and key in self._entries:
            entry = self._entries[key]
        else:
            entry = self._read(profile, token, vault)
            if self._entries is not None:
                self._entries[key] = entry
        now = time.time()
        return {
            "vault_id": entry["vault_id"]
            if self._fresh(entry["vault_id"], now)
            else None,
            "values": {
                reference: value
                for reference, value in entry["values"].items()
                if self._fresh(value, now)
            },
        }

    def _read(self, profile: str, token: str, vault: str) -> dict:
        empty: dict = {"vault_id": None, "values": {}}
        try:
            value = self.store.get(profile)
            entry = json.loads("" if value is None else value.reveal())
        except (KeychainUnavailable, ValueError):
            return empty
        if (
            not isinstance(entry, dict)
            or set(entry)
            != {"schema_version", "credential", "vault", "vault_id", "values"}
            or entry["schema_version"] != CACHE_SCHEMA_VERSION
            or entry["credential"] != _fingerprint(token)
            or entry["vault"] != vault
            or not isinstance(entry["values"], dict)
        ):
            return empty
        return entry

    def _fresh(self, entry: object, now: float) -> bool:
        return (
            isinstance(entry, dict)
            and set(entry) == {"value", "expires_at"}
            and isinstance(entry["value"], str)
            and bool(entry["value"])
            and isinstance(entry["expires_at"], (int, float))
            and 0 < entry["expires_at"] - now <= self.ttl_seconds
        )


def _fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class OpOnePasswordClient:
    """Invoke 1Password CLI with a selected service-account token.

    ``op`` is taken from trusted absolute paths and receives a minimal
    environment: the base variables, network proxy and certificate settings,
    its configuration directory, ``extra_env_vars`` the caller approves, and
    the token. That trusted process necessarily holds the token.
    """

    def __init__(
        self,
        *,
        op_path: str | None = None,
        use_cli_cache: bool = True,
        extra_env_vars: tuple[str, ...] = (),
        timeout: float = 30,
    ) -> None:
        self.op_path = process.trusted_executable(
            (op_path,) if op_path else OP_CANDIDATES
        )
        self.use_cli_cache = use_cli_cache
        self.extra_env_vars = tuple(
            name for name in extra_env_vars if name not in CONFLICTING_OP_ENV_VARS
        )
        self.timeout = timeout

    def authenticate(self, token: str) -> bool:
        try:
            self._run(token, "whoami")
        except OnePasswordCommandFailed:
            return False
        return True

    def vault_id(self, token: str, vault: str) -> str:
        output = self._run(token, "vault", "get", vault, "--format", "json")
        try:
            vault_id = json.loads(output)["id"]
        except (KeyError, TypeError, ValueError):
            raise OnePasswordCommandFailed() from None
        if not isinstance(vault_id, str) or not vault_id:
            raise OnePasswordCommandFailed()
        return vault_id

    def read(self, token: str, reference: str) -> str:
        return self._run(token, "read", "--no-newline", reference)

    def _run(self, token: str, *arguments: str) -> str:
        if self.op_path is None:
            raise OnePasswordCliUnavailable()
        settings = {"OP_SERVICE_ACCOUNT_TOKEN": token}
        if not self.use_cli_cache:
            settings["OP_CACHE"] = "false"
        try:
            result = process.run(
                [self.op_path, *arguments],
                environment=process.child_environment(
                    (*OP_ENV_VARS, *self.extra_env_vars), set_values=settings
                ),
                timeout=self.timeout,
            )
        except process.ExecutableUnavailable:
            raise OnePasswordCliUnavailable() from None
        except process.ProcessTimeout:
            raise OnePasswordError(CLI_TIMEOUT) from None
        except process.OutputLimitExceeded:
            raise OnePasswordError(CLI_OUTPUT) from None
        if result.returncode != 0:
            error = result.stderr.casefold()
            if (
                "rate-limited" in error
                or "too many requests" in error
                or "(429)" in error
            ):
                raise OnePasswordRateLimited()
            raise OnePasswordCommandFailed()
        return result.stdout


def resolve_profile(
    profile: OnePasswordProfile,
    references: tuple[str, ...],
    *,
    credential_store: CredentialStore,
    client: OnePasswordClient,
    cache: OnePasswordSecretCache | None = None,
    bypass_cache: bool = False,
    update_cache: bool = True,
) -> ProfileResolution:
    """Read every reference with the profile's token, reusing cached entries.

    References outside the profile's vault are rejected before the cache or
    1Password is consulted. When every reference is cached, 1Password is not
    called. Otherwise the refresh holds the cache's profile lock, rechecks the
    cache so concurrent callers share one refresh, and reads only the missing
    references through the vault's ID. The macOS cache reuses one loaded entry
    for this call, loading again only after lock contention. ``bypass_cache``
    ignores cached entries but still stores fresh ones unless ``update_cache``
    is false.
    """
    failures: dict[str, str] = {}
    paths: dict[str, str] = {}
    for reference in references:
        try:
            paths[reference] = reference_path(reference, profile.vault)
        except ValueError as error:
            failures[reference] = str(error)
    resolution = _Resolution(paths, failures)
    if not paths:
        return resolution.result()
    try:
        token = credential_store.get_token(profile.name)
    except KeychainUnavailable as error:
        return resolution.fail(error.reason)
    except Exception:  # noqa: BLE001 - port failures must be redacted
        return resolution.fail(KEYCHAIN_UNAVAILABLE)
    if not token:
        return resolution.fail(CREDENTIAL_MISSING)
    if cache is None:
        return _refresh(profile, token, resolution, client, None, update_cache)

    session = (
        cache._session()
        if isinstance(cache, MacOSKeychainSecretCache)
        else contextlib.nullcontext(cache)
    )
    with session as active_cache:
        return _resolve_cached(
            profile, token, resolution, client, active_cache, bypass_cache, update_cache
        )


def _resolve_cached(
    profile: OnePasswordProfile,
    token: str,
    resolution: _Resolution,
    client: OnePasswordClient,
    cache: OnePasswordSecretCache,
    bypass_cache: bool,
    update_cache: bool,
) -> ProfileResolution:
    def reuse_cached() -> bool:
        if not bypass_cache:
            try:
                resolution.values = cache.get(
                    profile.name, token, profile.vault, tuple(resolution.paths)
                )
            except Exception:  # noqa: BLE001 - cache failures must not expose values
                resolution.values = {}
        return not resolution.missing()

    if reuse_cached():
        return resolution.result()
    with cache.refreshing(profile.name):
        if reuse_cached():
            return resolution.result()
        vault_id = None
        if not bypass_cache:
            try:
                vault_id = cache.vault_id(profile.name, token, profile.vault)
            except Exception:  # noqa: BLE001 - cache failures must not expose values
                vault_id = None
        return _refresh(
            profile, token, resolution, client, cache, update_cache, vault_id
        )


class _Resolution:
    def __init__(self, paths: dict[str, str], failures: dict[str, str]) -> None:
        self.paths = paths
        self.failures = failures
        self.values: dict[str, str] = {}
        self.cache_failure: str | None = None

    def missing(self) -> list[str]:
        return [
            reference
            for reference in self.paths
            if reference not in self.values and reference not in self.failures
        ]

    def fail(self, reason: str) -> ProfileResolution:
        self.failures.update(dict.fromkeys(self.missing(), reason))
        return self.result()

    def result(self) -> ProfileResolution:
        return ProfileResolution(
            values={
                reference: SecretValue(value)
                for reference, value in self.values.items()
            },
            failures=self.failures,
            cache_failure=self.cache_failure,
        )


def _refresh(
    profile: OnePasswordProfile,
    token: str,
    resolution: _Resolution,
    client: OnePasswordClient,
    cache: OnePasswordSecretCache | None,
    update_cache: bool,
    vault_id: str | None = None,
) -> ProfileResolution:
    fetched_vault_id = None
    if vault_id is None:
        try:
            vault_id = fetched_vault_id = client.vault_id(token, profile.vault)
        except OnePasswordCommandFailed:
            return resolution.fail(_vault_failure(client, token, profile.vault))
        except OnePasswordError as error:
            return resolution.fail(error.reason)
        except Exception:  # noqa: BLE001 - client output may contain secret values
            return resolution.fail(_vault_failure(client, token, profile.vault))

    fetched: dict[str, str] = {}
    for reference in resolution.missing():
        try:
            value = client.read(token, f"op://{vault_id}/{resolution.paths[reference]}")
        except OnePasswordRateLimited:
            resolution.fail(RATE_LIMITED)
            break
        except OnePasswordError as error:
            resolution.failures[reference] = error.reason
            continue
        except Exception:  # noqa: BLE001 - client output may contain secret values
            resolution.failures[reference] = UNREADABLE
            continue
        if not value:
            resolution.failures[reference] = EMPTY
            continue
        fetched[reference] = resolution.values[reference] = value

    if cache is not None and update_cache and (fetched or fetched_vault_id):
        try:
            cache.put(profile.name, token, profile.vault, fetched, fetched_vault_id)
        except Exception:  # noqa: BLE001 - cache failures must not expose values
            resolution.cache_failure = CACHE_WRITE_FAILED
    return resolution.result()


def _vault_failure(client: OnePasswordClient, token: str, vault: str) -> str:
    """Explain why the vault could not be resolved, with one extra request."""
    try:
        if not client.authenticate(token):
            return CREDENTIAL_INVALID
    except OnePasswordError as error:
        return error.reason
    except Exception:  # noqa: BLE001 - client output may contain secret values
        return CREDENTIAL_INVALID
    return f"service account cannot read configured vault {vault!r}"
