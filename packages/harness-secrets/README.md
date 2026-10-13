# harness-secrets

Store ordinary secrets in the macOS Keychain, or read 1Password references with a service-account token kept there and cache results locally so routine reads make no 1Password requests. It imports only the Python 3.12+ standard library, so CLIs can depend on it.

- `MacOSKeychainStore` reads, writes, deletes, and lists ordinary generic-password items through one Swift identity, with Keychain interaction disabled.
- `OnePasswordProfile` names a service account by its Keychain account and the vault it reads.
- `resolve_profile` returns `SecretValue`s and fixed failure reasons per reference, plus a `cache_failure` reason when the cache could not be written.
- `MacOSKeychainCredentialStore` reads service-account tokens from the login Keychain through the bundled Swift helper. A missing item is `None`; a locked Keychain or unavailable helper raises `KeychainUnavailable` with a fixed reason.
- `OpOnePasswordClient` runs `op` with the token only in a minimal child environment.
- `MacOSKeychainSecretCache` keeps resolved values and the vault ID in one Keychain item per profile, reads and writes through the bundled Swift helper (`KEYCHAIN_STORE_HELPER`), and takes its Keychain service, label, TTL, and lock directory from the caller.

Callers supply every identifier, such as Keychain service names, labels, and lock directories.

## Ordinary Keychain secrets

`MacOSKeychainStore(service=..., label=..., swift_path=None, store_helper=None)` provides a service-scoped store. `None` selects `/usr/bin/swift` and the bundled `KEYCHAIN_STORE_HELPER`. Every operation uses the same Swift identity; Python never calls the Security framework directly. Item labels are `LABEL: ACCOUNT`.

- `get(account) -> SecretValue | None` returns an exact secret, including an empty string or trailing newlines. A missing item returns `None`.
- `put(account, value)` accepts a `str` or `SecretValue`, passes it only on stdin, and verifies the stored bytes before returning. Empty values and trailing newlines are preserved.
- `delete(account)` unconditionally deletes through the Swift helper. A missing item is harmless; use guarded deletion when sweeping a cache.
- `list(service=None) -> tuple[KeychainItemMetadata, ...]` lists the given service, defaulting to the store's own service. Each immutable metadata record has `account`, `created_at`, `modified_at`, `has_access_control`, `synchronizable`, and `persistent_ref`. Dates are timezone-aware UTC `datetime` objects. `has_access_control` reports the presence of Apple's `kSecAttrAccessControl`, not the ordinary file-based Keychain ACL (`kSecAttrAccess`), and does not decode protection flags or prove an item is readable. `synchronizable` reports `kSecAttrSynchronizable`. The opaque, nonempty `bytes` reference is excluded from `repr`; pass it back unchanged on the same machine. Results are sorted by account, timestamps, and reference, and no matches return `()`. Listing requests both synchronization states and returns metadata without secret data.
- `inspect(persistent_ref, *, service=None) -> KeychainItemMetadata | None` requests only metadata for that reference, scoped to the given service or the store's own service. A missing reference or service mismatch returns `None`; it never falls back to an account lookup and never requests the secret.
- `delete_if_unchanged(expected, *, service=None) -> bool` rechecks the captured reference's account, creation and modification timestamps, access-control presence, synchronization status, and reference before deleting by that same reference. Both the recheck and deletion run in one helper invocation without requesting the value. It returns `True` only when deletion succeeds; missing, changed, protected, synchronized, or incomplete metadata returns `False`. The method always preserves items with access control or synchronization enabled. To sweep entries from `list(other_service)`, pass the same service to inspection and guarded deletion.

Guarded deletion is **not an atomic compare-and-delete guarantee**: another writer can refresh or change protection after the recheck and before `SecItemDelete`. Changes within the Keychain timestamps' resolution may also be indistinguishable (file-based Keychain dates can have only second precision). In native tests, a deleted and recreated file-based item reused the same persistent reference; comparing creation and modification times preserved the replacement. References alone are not generation identifiers. Use a lock shared with writers if that race or timestamp ambiguity is unacceptable. References to synchronized items may also stop resolving after remote changes; the guard preserves synchronized items regardless. See Apple's [`kSecAttrSynchronizable` documentation](https://developer.apple.com/documentation/security/ksecattrsynchronizable) for reference limitations.

The helper now emits metadata schema version 2. Version 1 metadata from custom older helpers remains readable, with `None` for the three new fields; it cannot authorize guarded deletion. Update custom helpers before using `inspect` or `delete_if_unchanged`. Unsupported versions, unknown fields, malformed dates, invalid flags or references, and inconsistent inspection responses fail with a fixed redacted reason.

All operations are non-interactive and bounded. A locked or inaccessible item, timeout, output-limit failure, failed verification, or invalid helper output raises `KeychainUnavailable("Keychain is locked or unavailable")`; a missing or untrusted Swift executable or failure to start retains the historical reason `macOS security CLI is unavailable`; a missing or untrusted helper raises `KeychainUnavailable("Keychain helper is missing or untrusted")` without starting a child. Errors contain no item values or child output. `list` may read metadata without unlocking an item; it never requests its value. Secrets are returned only as `SecretValue` and must be explicitly revealed when needed.

The general store does not assign a TTL or sweep automatically. Callers own cache policy and can delete stale items without reading their values:

```python
from datetime import datetime, timedelta, timezone
from harness_secrets import MacOSKeychainStore

store = MacOSKeychainStore(service="com.example.cli.cache", label="CLI cache")
store.put("account", token)  # token is a str or SecretValue supplied by the caller.
cached = store.get("account")

cutoff = datetime.now(timezone.utc) - timedelta(days=1)
for item in store.list():
    if (
        item.modified_at < cutoff
        and item.has_access_control is False
        and item.synchronizable is False
    ):
        store.delete_if_unchanged(item)  # False means missing or skipped.
```

Protected enrollment, user-presence reads, and interpreting detailed access-control policies remain the caller's responsibility. This API implements ordinary, non-interactive generic-password storage and value-free metadata inspection. `MacOSKeychainCredentialStore` and `MacOSKeychainSecretCache` delegate storage to it while retaining the 1Password interfaces, failure reasons, expiry, binding, and refresh coordination described below.

## References

A reference must be `op://VAULT/ITEM/[SECTION/]FIELD`, optionally followed by a query such as `?attribute=otp`, and must name its profile's vault. Malformed and cross-vault references fail before the Keychain, the cache, or 1Password is consulted. Reads go through the vault's resolved ID. This is defense in depth: grant each service account read access to only the vaults it needs.

## Caching

- A cache hit for every requested reference makes no 1Password request, not even `whoami` or a vault lookup.
- Each value and the vault ID carry their own expiry, set when fetched. Reads never extend it, and a refresh of some references leaves the others' expiry unchanged. Entries are bound to a fingerprint of the token and to the profile's vault, so replacing the credential or changing the vault invalidates them. A shortened TTL also bounds existing entries.
- Each `resolve_profile` call loads the cache item at most once, reusing the loaded entry for value lookup, vault ID lookup, and merging a write. Only lock contention causes a second load to pick up another process's refresh. The snapshot belongs to that call, so concurrent resolutions do not share it and later calls read the Keychain again. Expiry is checked again whenever the snapshot is used.
- On a miss, `resolve_profile` holds a per-profile lock file in `lock_dir`, rechecks the snapshot (reloading after contention) so concurrent processes share one refresh, and reads only missing references. Without `lock_dir` refreshes are not coordinated. Waiting for the lock is bounded; on timeout the refresh proceeds after the recheck.
- A miss reads straight away with the cached vault ID, or resolves it with one `op vault get`. `whoami` runs only to explain a failed vault lookup.
- A rate limit keeps the values already read and caches them; the rest fail with the rate-limit reason. Expired entries are never served, and a failed refresh never extends them.
- Cache hits skip remote validation, so upstream revocation or rotation shows only after expiry, `bypass_cache=True`, or `clear(profile)`. Expired entries are dropped from the item on the next write but stay stored until then.
- Entries from the 0.1 cache format are misses and are replaced on the next write.

## Processes

`swift` and `op` come from fixed absolute paths (`/usr/bin/swift` and `/opt/homebrew/bin/op` or `/usr/local/bin/op`), or from paths the caller passes. Either way the resolved file must be an executable regular file, owned by root or the current user and not writable by group or others, in a directory with the same properties; otherwise it is treated as unavailable. Children run with a fixed `PATH`, the base variables (`HOME`, `USER`, `LOGNAME`, `TMPDIR`, `LANG`, `LC_ALL`, `LC_CTYPE`), and only what each needs: `op` also gets proxy and certificate settings, `XDG_CONFIG_HOME`, `OP_CONFIG_DIR`, the caller's `extra_env_vars`, and the token. Each child has a deadline and an output limit, is killed with its process group when it exceeds them, and its output never appears in errors. `op read --no-newline` keeps values exact.

All Keychain operations run `/usr/bin/swift KEYCHAIN_STORE_HELPER`: `--read SERVICE ACCOUNT` calls `SecItemCopyMatching` and writes the exact value to stdout without adding a newline; `--put SERVICE ACCOUNT LABEL` takes an exact value only on stdin and verifies it after storage; `--delete SERVICE ACCOUNT` calls `SecItemDelete`; `--list SERVICE` requests attributes and persistent references without values and emits a versioned JSON metadata envelope. `--inspect SERVICE` receives a schema-2 JSON request containing the base64 reference on stdin and returns the same envelope with one item. `--delete-if-unchanged SERVICE` receives schema-2 expected metadata on stdin, inspects without values, then uses `kSecValuePersistentRef` to delete. Guarded deletion exits 44 when missing and 45 when changed or protected; Python maps both to `False`. It never retries deletion by account name. The existing `SERVICE ACCOUNT LABEL` setup interface remains available with its original newline trimming and rejection of empty input. All modes use the same Swift identity, avoiding the `apple:` versus `apple-tool:` partition mismatch with `security find-generic-password`. This costs a Swift startup for each operation but does not require the login password or broaden any ACL. Swift receives only the base environment and toolchain variables (`DEVELOPER_DIR`, `SDKROOT`, `TOOLCHAINS`); its deadline is 120 seconds and its combined output limit is 1 MiB. Keychain interaction is disabled: locked or inaccessible item values fail without a password dialog. A missing read, list, or inspection exits 44; Python maps that to a missing credential, cache miss, empty metadata tuple, or `None`. Cache read failures remain misses and failed writes report `cache_failure`.

All Keychain classes accept `swift_path` and `store_helper`; use the same executable and helper for setup and access. The helper is held to the same rule as executables, except that it need not be executable: it must resolve to a regular file owned by root or the current user and not writable by group or others, in a directory with the same properties, and Swift runs its resolved path. The 1Password classes retain `security_path` for source compatibility, but it no longer controls any operation: `clear` now delegates to the general store's same-identity deletion.

The helper updates only `kSecAttrLabel` and `kSecValueData` through [`SecItemUpdate`](https://developer.apple.com/documentation/security/secitemupdate(_:_:)), without deleting and recreating the item or explicitly replacing its access settings. Nevertheless, native testing on macOS 27.0.1 showed that macOS regenerates the partition list as `apple:` for Swift on update. A stopgap `security set-generic-password-partition-list -S apple-tool:,apple: ...` is therefore undone by a later helper write on that system. Using Swift for both reads and writes avoids depending on that stopgap. The opt-in native regression checks this on a disposable Keychain, including fresh cache and token items, exact writes and reads, reference inspection, guarded deletion, refreshed/recreated items, service/account isolation, missing items, a partition-list change, a value update, and locked or unavailable Keychain failures. Controlled Security API doubles additionally check current protection/synchronization changes and enforce value-free queries and deletion by the original reference. Run it on macOS with `HARNESS_SECRETS_TEST_KEYCHAIN=1 uv run --active python -m unittest discover -s packages/harness-secrets/tests -t packages/harness-secrets/tests -p test_keychain_macos.py`. It creates a uniquely named test Keychain under `~/Library/Keychains` (where macOS enables partition ACLs), uses the helper's optional `--keychain PATH` prefix to isolate every operation from login Keychain items, and removes the test Keychain afterward.

The shared `harness_secrets.process.run(arguments, environment=, timeout=, input_text=None, limit=1024 * 1024)` accepts an argv list and an explicit child environment, runs without a shell, and returns a `ProcessResult` containing `returncode`, `stdout`, and `stderr`. Output is decoded as UTF-8 with invalid bytes replaced. stdin is closed unless `input_text` is supplied. The deadline covers communication and process exit, and the byte limit covers combined stdout and stderr, including descendants that retain the pipes. A failure to start raises `ExecutableUnavailable`; exceeding the deadline or byte limit raises `ProcessTimeout` or `OutputLimitExceeded`. These exceptions omit arguments and captured output. Non-zero exits are returned for callers to classify. Callers must keep secrets out of command arguments and avoid logging captured output.

`harness_factory.exports` uses this runner for both preferred manifest imports and legacy lockdown/instructions exports, with `child_environment()`, a 15-second deadline, and the default 1 MiB output limit. The importer discards stderr, rejects non-zero exits, and wraps process failures in `ExportError` naming the CLI before any imports are applied. The runner remains standard-library only.

## Security model

Keychain items are created by `/usr/bin/swift`, so any Swift program run as the same macOS user can likely read them without a prompt, including scripts written by agents. This protects secrets from other users and from plain-text files, not from code you run yourself.

## Secret values

`SecretValue` shows `<redacted>` in `str`, `repr`, and format strings, and refuses JSON encoding and pickling; `reveal()` returns the value. This prevents accidental disclosure only: any Python caller can reveal the value, and its memory is not erased.

## Migrating from 0.1

- `ResolvedSecret` (a `str` subclass) is replaced by `SecretValue`; call `reveal()` where the plain value is needed.
- `OnePasswordClient.can_read_vault` is replaced by `vault_id`, and failures raise `OnePasswordError` subclasses with a fixed `reason`.
- `OnePasswordSecretCache` returns partial hits from `get`, adds `vault_id`, `refreshing`, and `clear`, and `put` takes the fetched values and vault ID instead of a complete reference set.
