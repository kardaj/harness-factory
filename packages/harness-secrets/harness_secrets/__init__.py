"""Dependency-free secret retrieval for harnesses and the CLIs they configure.

Only the standard library is imported; the ``swift`` and ``op``
executables are taken from trusted absolute paths at runtime; the bundled Swift
helper ``KEYCHAIN_STORE_HELPER`` reads Keychain items to stdout and stores them
from stdin, using the same executable identity for both operations.
"""

from harness_secrets.keychain import (
    KEYCHAIN_STORE_HELPER,
    KeychainItemMetadata,
    KeychainUnavailable,
    MacOSKeychainStore,
)
from harness_secrets.onepassword import (
    CONFLICTING_OP_ENV_VARS,
    CacheWriteError,
    CredentialStore,
    MacOSKeychainCredentialStore,
    MacOSKeychainSecretCache,
    OnePasswordCliUnavailable,
    OnePasswordClient,
    OnePasswordCommandFailed,
    OnePasswordError,
    OnePasswordProfile,
    OnePasswordRateLimited,
    OnePasswordSecretCache,
    OpOnePasswordClient,
    ProfileResolution,
    RefreshLock,
    reference_path,
    resolve_profile,
)
from harness_secrets.process import trusted_executable
from harness_secrets.values import SecretValue

__all__ = [
    "CONFLICTING_OP_ENV_VARS",
    "KEYCHAIN_STORE_HELPER",
    "CacheWriteError",
    "CredentialStore",
    "KeychainItemMetadata",
    "KeychainUnavailable",
    "MacOSKeychainCredentialStore",
    "MacOSKeychainSecretCache",
    "MacOSKeychainStore",
    "OnePasswordCliUnavailable",
    "OnePasswordClient",
    "OnePasswordCommandFailed",
    "OnePasswordError",
    "OnePasswordProfile",
    "OnePasswordRateLimited",
    "OnePasswordSecretCache",
    "OpOnePasswordClient",
    "ProfileResolution",
    "RefreshLock",
    "SecretValue",
    "reference_path",
    "resolve_profile",
    "trusted_executable",
]
