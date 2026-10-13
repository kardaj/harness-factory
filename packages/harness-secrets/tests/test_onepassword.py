import contextlib
import errno
import fcntl
import json
import os
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from harness_secrets import (
    CacheWriteError,
    KeychainUnavailable,
    MacOSKeychainCredentialStore,
    MacOSKeychainSecretCache,
    OnePasswordCommandFailed,
    OnePasswordError,
    OnePasswordProfile,
    OnePasswordRateLimited,
    OpOnePasswordClient,
    RefreshLock,
    SecretValue,
    reference_path,
    resolve_profile,
)
from harness_secrets import process

PROFILE = OnePasswordProfile("personal", "Personal", "Vault")
A = "op://Vault/a/value"
B = "op://Vault/b/value"


class FakeCredentialStore:
    def __init__(self, token: str | None = "service-token", error=None):
        self.token = token
        self.error = error
        self.calls = 0

    def get_token(self, profile: str) -> str | None:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.token


class FakeClient:
    def __init__(self, values: dict[str, str], *, vault_error=None, active=True):
        self.values = values
        self.vault_error = vault_error
        self.active = active
        self.calls: list[tuple[str, ...]] = []

    def authenticate(self, token: str) -> bool:
        self.calls.append(("whoami",))
        return self.active

    def vault_id(self, token: str, vault: str) -> str:
        self.calls.append(("vault", vault))
        if self.vault_error is not None:
            raise self.vault_error
        return "vault-id"

    def read(self, token: str, reference: str) -> str:
        self.calls.append(("read", reference))
        value = self.values[reference.replace("op://vault-id/", "op://Vault/")]
        if isinstance(value, Exception):
            raise value
        return value


class NoClient:
    def __getattr__(self, name):
        raise AssertionError(f"1Password was called: {name}")


class MemoryCache:
    def __init__(self, values=None, vault_id=None, *, lock_dir=None, fail_put=False):
        self.values = dict(values or {})
        self.cached_vault_id = vault_id
        self.lock = None if lock_dir is None else RefreshLock(lock_dir)
        self.fail_put = fail_put
        self.puts: list[tuple[dict[str, str], str | None]] = []

    def get(self, profile, token, vault, references):
        return {r: self.values[r] for r in references if r in self.values}

    def vault_id(self, profile, token, vault):
        return self.cached_vault_id

    def put(self, profile, token, vault, values, vault_id):
        if self.fail_put:
            raise CacheWriteError("Keychain cache could not be written")
        self.puts.append((dict(values), vault_id))
        self.values.update(values)
        self.cached_vault_id = vault_id or self.cached_vault_id

    def refreshing(self, profile):
        return (
            contextlib.nullcontext() if self.lock is None else self.lock.hold(profile)
        )

    def clear(self, profile):
        self.values.clear()


def resolve(references, *, client, cache=None, store=None, **options):
    return resolve_profile(
        PROFILE,
        references,
        credential_store=store or FakeCredentialStore(),
        client=client,
        cache=cache,
        **options,
    )


class ResolveProfileTests(unittest.TestCase):
    def test_reads_references_and_reports_fixed_reasons_per_reference(self) -> None:
        client = FakeClient({A: "a", B: "", "op://Vault/c/value": RuntimeError("x")})

        resolution = resolve((A, B, "op://Vault/c/value"), client=client)

        self.assertEqual(resolution.values, {A: SecretValue("a")})
        self.assertEqual(
            resolution.failures,
            {
                B: "reference resolved to an empty value",
                "op://Vault/c/value": "reference is unreadable",
            },
        )
        self.assertNotIn("'a'", repr(resolution))
        self.assertEqual(
            client.calls[:2], [("vault", "Vault"), ("read", "op://vault-id/a/value")]
        )
        self.assertNotIn(("whoami",), client.calls)

    def test_references_outside_the_vault_never_reach_the_cache_or_1password(
        self,
    ) -> None:
        store = FakeCredentialStore()

        resolution = resolve(
            ("op://Other/a/value", "op://Vault/a", "Vault/a/value"),
            client=NoClient(),
            cache=NoClient(),
            store=store,
        )

        self.assertEqual(resolution.values, {})
        self.assertEqual(
            resolution.failures,
            {
                "op://Other/a/value": "reference is outside the profile's vault",
                "op://Vault/a": "reference must be op://VAULT/ITEM/[SECTION/]FIELD",
                "Vault/a/value": "reference must be op://VAULT/ITEM/[SECTION/]FIELD",
            },
        )
        self.assertEqual(store.calls, 0)

    def test_credential_failures_are_classified(self) -> None:
        for store, reason in (
            (FakeCredentialStore(None), "Keychain credential is missing"),
            (
                FakeCredentialStore(error=KeychainUnavailable("Keychain is locked")),
                "Keychain is locked",
            ),
            (
                FakeCredentialStore(error=RuntimeError("token-in-message")),
                "Keychain is locked or unavailable",
            ),
        ):
            with self.subTest(reason=reason):
                resolution = resolve((A,), client=NoClient(), store=store)
                self.assertEqual(resolution.failures, {A: reason})

    def test_complete_cache_hits_make_no_1password_calls(self) -> None:
        resolution = resolve((A,), client=NoClient(), cache=MemoryCache({A: "cached"}))

        self.assertEqual(resolution.values, {A: SecretValue("cached")})

    def test_partial_hits_read_only_missing_references_with_the_cached_vault_id(
        self,
    ) -> None:
        cache = MemoryCache({A: "cached"}, vault_id="vault-id")
        client = FakeClient({B: "fresh"})

        resolution = resolve((A, B), client=client, cache=cache)

        self.assertEqual(
            resolution.values, {A: SecretValue("cached"), B: SecretValue("fresh")}
        )
        self.assertEqual(client.calls, [("read", "op://vault-id/b/value")])
        self.assertEqual(cache.puts, [({B: "fresh"}, None)])

    def test_vault_failures_are_explained_with_one_extra_request(self) -> None:
        for client, reason in (
            (
                FakeClient({}, vault_error=OnePasswordCommandFailed(), active=False),
                "service-account credential is invalid or inactive",
            ),
            (
                FakeClient({}, vault_error=OnePasswordCommandFailed()),
                "service account cannot read configured vault 'Vault'",
            ),
            (
                FakeClient({}, vault_error=OnePasswordRateLimited()),
                "1Password request limit has been reached",
            ),
            (
                FakeClient({}, vault_error=OnePasswordError("1Password CLI timed out")),
                "1Password CLI timed out",
            ),
        ):
            with self.subTest(reason=reason):
                resolution = resolve((A, B), client=client)
                self.assertEqual(resolution.failures, {A: reason, B: reason})

    def test_rate_limits_keep_values_already_read_and_cache_them(self) -> None:
        cache = MemoryCache()
        client = FakeClient({A: "a", B: OnePasswordRateLimited()})

        resolution = resolve((A, B, "op://Vault/c/value"), client=client, cache=cache)

        self.assertEqual(resolution.values, {A: SecretValue("a")})
        self.assertEqual(
            resolution.failures,
            dict.fromkeys(
                (B, "op://Vault/c/value"), "1Password request limit has been reached"
            ),
        )
        self.assertEqual(cache.puts, [({A: "a"}, "vault-id")])

    def test_cache_write_failures_are_reported_without_losing_values(self) -> None:
        resolution = resolve(
            (A,), client=FakeClient({A: "a"}), cache=MemoryCache(fail_put=True)
        )

        self.assertEqual(resolution.values, {A: SecretValue("a")})
        self.assertEqual(
            resolution.cache_failure, "Keychain cache could not be written"
        )

    def test_bypass_ignores_entries_and_update_cache_controls_writes(self) -> None:
        cache = MemoryCache({A: "stale"}, vault_id="stale-id")
        client = FakeClient({A: "fresh"})

        resolution = resolve((A,), client=client, cache=cache, bypass_cache=True)
        unchanged = MemoryCache()
        resolve((A,), client=FakeClient({A: "a"}), cache=unchanged, update_cache=False)

        self.assertEqual(resolution.values, {A: SecretValue("fresh")})
        self.assertEqual(client.calls[0], ("vault", "Vault"))
        self.assertEqual(cache.puts, [({A: "fresh"}, "vault-id")])
        self.assertEqual(unchanged.puts, [])

    def test_concurrent_misses_share_one_refresh(self) -> None:
        with TemporaryDirectory() as directory:
            cache = MemoryCache(lock_dir=Path(directory))
            client = FakeClient({A: "a"})
            original_read = client.read

            def slow_read(token, reference):
                time.sleep(0.2)
                return original_read(token, reference)

            client.read = slow_read
            results = []
            threads = [
                threading.Thread(
                    target=lambda: results.append(
                        resolve((A,), client=client, cache=cache)
                    )
                )
                for _ in range(3)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        self.assertEqual([r.values for r in results], [{A: SecretValue("a")}] * 3)
        self.assertEqual(
            client.calls, [("vault", "Vault"), ("read", "op://vault-id/a/value")]
        )


class SecretValueTests(unittest.TestCase):
    def test_only_reveal_discloses_the_value(self) -> None:
        secret = SecretValue("hunter2")

        self.assertEqual(secret.reveal(), "hunter2")
        for shown in (str(secret), repr(secret), f"{secret}", f"{secret:>20}"):
            self.assertEqual(shown, "<redacted>")
        self.assertEqual(SecretValue("hunter2"), secret)
        self.assertNotEqual(SecretValue("other"), secret)
        with self.assertRaises(TypeError):
            json.dumps({"value": secret})
        with self.assertRaises(TypeError):
            import pickle

            pickle.dumps(secret)
        with self.assertRaises(TypeError):
            SecretValue(b"bytes")


class ReferencePathTests(unittest.TestCase):
    def test_accepts_items_sections_queries_and_names_with_spaces(self) -> None:
        for reference, path in (
            ("op://Vault/Home Assistant Token/value", "Home Assistant Token/value"),
            ("op://Vault/item/section/field", "item/section/field"),
            ("op://Vault/item/otp?attribute=otp", "item/otp?attribute=otp"),
        ):
            with self.subTest(reference=reference):
                self.assertEqual(reference_path(reference, "Vault"), path)

    def test_rejects_malformed_and_cross_vault_references(self) -> None:
        for reference in (
            "Vault/item/field",
            "op://Vault/item",
            "op://Vault/a/b/c/d",
            "op://Vault//field",
            "op://Vault/ item/field",
            "op://Vault/item/field\n",
            "op://Vault/item/field?a=1?b=2",
            "op://vault/item/field",
        ):
            with self.subTest(reference=reference), self.assertRaises(ValueError):
                reference_path(reference, "Vault")


class FakeExecutables:
    """Shell scripts standing in for security, swift, and op."""

    def __init__(self, test: unittest.TestCase) -> None:
        temporary = TemporaryDirectory()
        test.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.item = self.root / "keychain-item"
        self.log = self.root / "log"

    def script(self, name: str, body: str) -> str:
        path = self.root / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)
        return str(path)

    def helper(self) -> Path:
        path = self.root / "store.swift"
        path.write_text("// helper\n")
        path.chmod(0o644)
        return path

    def security(self, find_status: int | None = None) -> str:
        failure = "" if find_status is None else f"exit {find_status}\n"
        return self.script(
            "security",
            f"""echo "$@" >> '{self.log}'
case "$1" in
  find-generic-password) {failure}[ -f '{self.item}' ] || exit 44; cat '{self.item}'; echo ;;
  delete-generic-password) [ -f '{self.item}' ] || exit 44; rm '{self.item}' ;;
esac""",
        )

    def swift(self, status: int = 0, *, read_status: int | None = None) -> str:
        read_failure = "" if read_status is None else f"exit {read_status};"
        return self.script(
            "swift",
            f"""echo "$@" >> '{self.log}'
[ {status} -eq 0 ] || exit {status}
if [ "$2" = '--read' ]; then
  {read_failure} [ -f '{self.item}' ] || exit 44
  cat '{self.item}'
  exit 0
fi
if [ "$2" = '--delete' ]; then
  [ -f '{self.item}' ] || exit 44
  rm '{self.item}'
  exit 0
fi
cat > '{self.item}'""",
        )

    def op(self, body: str) -> str:
        return self.script(
            "op",
            f"""echo "$@" >> '{self.log}'
env > '{self.root}/env'
{body}""",
        )

    def environment(self) -> dict[str, str]:
        lines = (self.root / "env").read_text().splitlines()
        return dict(line.split("=", 1) for line in lines if "=" in line)


class KeychainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fake = FakeExecutables(self)

    def cache(self, **options) -> MacOSKeychainSecretCache:
        return MacOSKeychainSecretCache(
            service="test.1password.cache",
            label="test cache",
            ttl_seconds=options.pop("ttl_seconds", 3600),
            store_helper=self.fake.helper(),
            security_path=self.fake.security(),
            swift_path=options.pop("swift_path", None) or self.fake.swift(),
            **options,
        )

    def test_entries_expire_independently_and_bind_to_credential_and_vault(
        self,
    ) -> None:
        cache = self.cache()
        clock = "harness_secrets.onepassword.time.time"
        with patch(clock, return_value=1000):
            cache.put("personal", "token", "Vault", {A: "a"}, "vault-id")
        with patch(clock, return_value=3000):
            cache.put("personal", "token", "Vault", {B: "b"}, None)
            self.assertEqual(
                cache.get("personal", "token", "Vault", (A, B)), {A: "a", B: "b"}
            )
            self.assertEqual(cache.vault_id("personal", "token", "Vault"), "vault-id")
            self.assertEqual(cache.get("personal", "other-token", "Vault", (A,)), {})
            self.assertEqual(cache.get("personal", "token", "Other", (A,)), {})
        with patch(clock, return_value=5000):
            # A expired at 4600; reading B did not extend it and writing B kept A's expiry.
            self.assertEqual(cache.get("personal", "token", "Vault", (A, B)), {B: "b"})
            self.assertIsNone(cache.vault_id("personal", "token", "Vault"))
        self.assertNotIn("token", self.fake.item.read_text())
        self.assertNotIn('"a"', self.fake.log.read_text())
        self.assertIn("test cache: personal", self.fake.log.read_text())

    def test_shortened_ttl_and_old_schema_entries_are_misses(self) -> None:
        clock = "harness_secrets.onepassword.time.time"
        with patch(clock, return_value=1000):
            self.cache().put("personal", "token", "Vault", {A: "a"}, None)
            self.assertEqual(
                self.cache(ttl_seconds=60).get("personal", "token", "Vault", (A,)), {}
            )
        self.fake.item.write_text(json.dumps({"schema_version": 1, "values": {A: "a"}}))
        self.assertEqual(self.cache().get("personal", "token", "Vault", (A,)), {})

    def test_clear_and_failed_writes(self) -> None:
        cache = self.cache()
        cache.put("personal", "token", "Vault", {A: "a"}, None)
        cache.clear("personal")
        cache.clear("personal")

        self.assertEqual(cache.get("personal", "token", "Vault", (A,)), {})
        with self.assertRaises(CacheWriteError):
            self.cache(swift_path=self.fake.swift(status=1)).put(
                "personal", "token", "Vault", {A: "a"}, None
            )

    def test_credential_store_distinguishes_missing_from_unavailable(self) -> None:
        self.fake.item.write_text("token-with-trailing-space \n")
        store = MacOSKeychainCredentialStore(
            service="test.1password",
            swift_path=self.fake.swift(),
            store_helper=self.fake.helper(),
        )

        self.assertEqual(store.get_token("personal"), "token-with-trailing-space \n")
        self.fake.item.unlink()
        self.assertIsNone(store.get_token("personal"))
        locked = MacOSKeychainCredentialStore(
            service="test.1password",
            swift_path=self.fake.swift(read_status=1),
            store_helper=self.fake.helper(),
        )
        with self.assertRaisesRegex(KeychainUnavailable, "locked or unavailable"):
            locked.get_token("personal")
        missing = MacOSKeychainCredentialStore(
            service="test.1password", swift_path=str(self.fake.root / "absent")
        )
        with self.assertRaisesRegex(KeychainUnavailable, "security CLI is unavailable"):
            missing.get_token("personal")
        self.assertIn(
            "--read test.1password personal",
            self.fake.log.read_text(),
        )

    def test_keychain_read_process_failures_are_fixed_and_redacted(self) -> None:
        store = MacOSKeychainCredentialStore(
            service="test.1password",
            swift_path=self.fake.swift(),
            store_helper=self.fake.helper(),
        )
        for error, reason in (
            (
                process.ExecutableUnavailable("secret-output"),
                "macOS security CLI is unavailable",
            ),
            (
                process.ProcessTimeout("secret-output"),
                "Keychain is locked or unavailable",
            ),
            (
                process.OutputLimitExceeded("secret-output"),
                "Keychain is locked or unavailable",
            ),
        ):
            with (
                self.subTest(error=type(error).__name__),
                patch("harness_secrets.onepassword.process.run", side_effect=error),
                self.assertRaises(KeychainUnavailable) as raised,
            ):
                store.get_token("personal")
            self.assertEqual(str(raised.exception), reason)
            self.assertIsNone(raised.exception.__cause__)

        with (
            patch(
                "harness_secrets.onepassword.process.run",
                return_value=process.ProcessResult(1, "secret-output", "secret-error"),
            ),
            self.assertRaises(KeychainUnavailable) as raised,
        ):
            store.get_token("personal")
        self.assertEqual(str(raised.exception), "Keychain is locked or unavailable")

    def test_keychain_reads_use_the_writer_environment_and_exact_stdout(self) -> None:
        store = MacOSKeychainCredentialStore(
            service="test.1password",
            swift_path=self.fake.swift(),
            store_helper=self.fake.helper(),
        )
        with (
            patch.dict(os.environ, {"OP_SERVICE_ACCOUNT_TOKEN": "ambient-secret"}),
            patch(
                "harness_secrets.onepassword.process.run",
                return_value=process.ProcessResult(0, "secret\n", ""),
            ) as run,
        ):
            self.assertEqual(store.get_token("personal"), "secret\n")
        arguments = run.call_args.args[0]
        self.assertEqual(
            arguments,
            [
                store.swift_path,
                str(self.fake.root / "store.swift"),
                "--read",
                "test.1password",
                "personal",
            ],
        )
        self.assertEqual(run.call_args.kwargs["timeout"], 120)
        self.assertNotIn(
            "OP_SERVICE_ACCOUNT_TOKEN", run.call_args.kwargs["environment"]
        )
        self.assertNotIn("secret", repr(run.call_args))

    def test_cache_read_failures_are_misses_and_write_failures_are_redacted(
        self,
    ) -> None:
        cache = self.cache()
        for failure in (
            process.ProcessResult(44, "secret", "secret"),
            process.ProcessResult(1, "secret", "secret"),
            process.ProcessTimeout("secret"),
            process.OutputLimitExceeded("secret"),
            process.ExecutableUnavailable("secret"),
        ):
            with self.subTest(failure=type(failure).__name__):
                options = (
                    {"side_effect": failure}
                    if isinstance(failure, Exception)
                    else {"return_value": failure}
                )
                with patch("harness_secrets.onepassword.process.run", **options):
                    result = resolve((A,), client=FakeClient({A: "fresh"}), cache=cache)
                self.assertEqual(result.values, {A: SecretValue("fresh")})
                self.assertEqual(result.failures, {})
                self.assertEqual(
                    result.cache_failure, "Keychain cache could not be written"
                )

    def test_resolution_reuses_one_cache_read_on_hit_and_stale_refresh(self) -> None:
        cache = self.cache(lock_dir=self.fake.root / "locks")
        clock = "harness_secrets.onepassword.time.time"
        with patch(clock, return_value=1000):
            cache.put("personal", "service-token", "Vault", {A: "cached"}, "vault-id")
        for now, client, expected in (
            (1100, NoClient(), "cached"),
            (5000, FakeClient({A: "fresh"}), "fresh"),
        ):
            with self.subTest(now=now), patch(clock, return_value=now):
                self.fake.log.write_text("")
                result = resolve((A,), client=client, cache=cache)
                self.assertEqual(result.values, {A: SecretValue(expected)})
                self.assertEqual(self.fake.log.read_text().count("--read"), 1)

    def test_resolution_rechecks_once_after_lock_contention(self) -> None:
        cache = self.cache(lock_dir=self.fake.root / "locks")
        clock = "harness_secrets.onepassword.time.time"
        with patch(clock, return_value=1000):
            cache.put("personal", "service-token", "Vault", {A: "stale"}, "vault-id")
        self.fake.log.write_text("")
        original_flock = fcntl.flock
        attempts = 0

        def contended_once(descriptor, operation):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise BlockingIOError(errno.EWOULDBLOCK, "busy")
            return original_flock(descriptor, operation)

        with (
            patch(
                "harness_secrets.onepassword.fcntl.flock", side_effect=contended_once
            ),
            patch(clock, return_value=5000),
        ):
            result = resolve((A,), client=FakeClient({A: "fresh"}), cache=cache)
        self.assertEqual(result.values, {A: SecretValue("fresh")})
        self.assertEqual(self.fake.log.read_text().count("--read"), 2)

    def test_lock_recheck_uses_another_refresh_and_sessions_are_independent(
        self,
    ) -> None:
        cache = self.cache(lock_dir=self.fake.root / "locks")
        client = FakeClient({A: "fresh"})
        original_read = client.read
        reading = threading.Event()
        release = threading.Event()

        def paused_read(token, reference):
            reading.set()
            if not release.wait(5):
                raise AssertionError("Test refresh did not finish")
            return original_read(token, reference)

        client.read = paused_read
        results = []
        first = threading.Thread(
            target=lambda: results.append(resolve((A,), client=client, cache=cache))
        )
        second = threading.Thread(
            target=lambda: results.append(resolve((A,), client=NoClient(), cache=cache))
        )
        original_flock = fcntl.flock
        contended = threading.Event()

        def flock(descriptor, operation):
            try:
                return original_flock(descriptor, operation)
            except BlockingIOError:
                contended.set()
                raise

        with patch("harness_secrets.onepassword.fcntl.flock", side_effect=flock):
            first.start()
            try:
                self.assertTrue(reading.wait(5))
                second.start()
                self.assertTrue(contended.wait(5))
            finally:
                release.set()
                first.join(5)
                if second.ident is not None:
                    second.join(5)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(
            [result.values for result in results], [{A: SecretValue("fresh")}] * 2
        )
        self.assertEqual(self.fake.log.read_text().count("--read"), 3)
        self.assertIsNone(cache._entries)

    def test_session_checks_expiry_again_and_does_not_outlive_resolution(self) -> None:
        cache = self.cache()
        clock = "harness_secrets.onepassword.time.time"
        with patch(clock, return_value=1000):
            cache.put("personal", "service-token", "Vault", {A: "cached"}, "vault-id")
        with cache._session() as session:
            with patch(clock, return_value=1100):
                self.assertEqual(
                    session.get("personal", "service-token", "Vault", (A,)),
                    {A: "cached"},
                )
            with patch(clock, return_value=5000):
                self.assertEqual(
                    session.get("personal", "service-token", "Vault", (A,)), {}
                )
                self.assertIsNone(
                    session.vault_id("personal", "service-token", "Vault")
                )
        self.assertEqual(session._entries, {})
        self.assertIsNone(cache._entries)


class OpClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fake = FakeExecutables(self)

    def test_token_reaches_only_a_minimal_child_environment(self) -> None:
        op = self.fake.op("printf 'value with trailing space '")
        ambient = {
            "OP_ACCOUNT": "wrong-account",
            "OP_CONNECT_TOKEN": "wrong-connect-token",
            "OP_SERVICE_ACCOUNT_TOKEN": "wrong-service-token",
            "HTTPS_PROXY": "http://proxy.invalid:3128",
            "UNRELATED_SECRET": "ambient-secret",
            "APPROVED": "yes",
        }

        with patch.dict(os.environ, ambient):
            value = OpOnePasswordClient(
                op_path=op, use_cli_cache=False, extra_env_vars=("APPROVED",)
            ).read("selected-token", "op://vault-id/item/field")

        environment = self.fake.environment()
        self.assertEqual(value, "value with trailing space ")
        self.assertEqual(environment["OP_SERVICE_ACCOUNT_TOKEN"], "selected-token")
        self.assertEqual(environment["HTTPS_PROXY"], "http://proxy.invalid:3128")
        self.assertEqual(environment["OP_CACHE"], "false")
        self.assertEqual(environment["APPROVED"], "yes")
        self.assertEqual(environment["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")
        for name in ("OP_ACCOUNT", "OP_CONNECT_TOKEN", "UNRELATED_SECRET"):
            self.assertNotIn(name, environment)
        self.assertEqual(
            self.fake.log.read_text(), "read --no-newline op://vault-id/item/field\n"
        )

    def test_vault_ids_and_authentication(self) -> None:
        client = OpOnePasswordClient(
            op_path=self.fake.op(
                """case "$1" in
  vault) echo '{"id":"vault-id"}' ;;
  whoami) exit 1 ;;
esac"""
            )
        )

        self.assertEqual(client.vault_id("token", "Vault"), "vault-id")
        self.assertFalse(client.authenticate("token"))

    def test_failures_are_redacted_and_classified(self) -> None:
        for body, error, reason in (
            (
                "echo 'Too many requests. rate-limited secret-value' >&2; exit 1",
                OnePasswordRateLimited,
                "1Password request limit has been reached",
            ),
            (
                "echo 'secret-value' >&2; exit 1",
                OnePasswordCommandFailed,
                "reference is unreadable",
            ),
            ("sleep 5", OnePasswordError, "1Password CLI timed out"),
            (
                "head -c 2000000 /dev/zero",
                OnePasswordError,
                "1Password CLI output exceeded the limit",
            ),
        ):
            with self.subTest(reason=reason):
                client = OpOnePasswordClient(op_path=self.fake.op(body), timeout=1)
                with self.assertRaises(error) as raised:
                    client.read("token", "op://vault-id/item/field")
                self.assertEqual(raised.exception.reason, reason)
                self.assertNotIn("secret-value", str(raised.exception))

    def test_untrusted_or_missing_executables_are_unavailable(self) -> None:
        writable = self.fake.op("exit 0")
        os.chmod(writable, 0o777)

        for path in (writable, str(self.fake.root / "absent"), "op"):
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(
                    OnePasswordError, "1Password CLI is unavailable"
                ),
            ):
                OpOnePasswordClient(op_path=path).read("token", "op://v/i/f")


if __name__ == "__main__":
    unittest.main()
