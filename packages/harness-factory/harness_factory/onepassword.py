"""Resolve tracked 1Password declarations without exposing machine credentials."""

from __future__ import annotations

import warnings
from dataclasses import dataclass, replace

from harness_factory.models import Environment, EnvVar
from harness_factory.onepassword_config import OnePasswordConfig, OnePasswordSecret
from harness_secrets import (
    CredentialStore,
    OnePasswordClient,
    OnePasswordSecretCache,
    OpOnePasswordClient,
    SecretValue,
    resolve_profile,
)


@dataclass(frozen=True)
class SecretResolutionIssue:
    environment: str
    variable: str
    profile: str
    reference: str
    reason: str

    def describe(self) -> str:
        return (
            f"{self.environment}.{self.variable} via profile {self.profile!r} "
            f"and reference {self.reference!r}: {self.reason}"
        )


class SecretResolutionError(RuntimeError):
    """Aggregate required-secret failures without retaining secret values."""

    def __init__(self, issues: tuple[SecretResolutionIssue, ...]):
        self.issues = issues
        details = "\n".join(f"- {issue.describe()}" for issue in issues)
        super().__init__(
            f"required 1Password secrets could not be resolved:\n{details}"
        )


def resolve_onepassword_environments(
    environments: tuple[Environment, ...],
    config: OnePasswordConfig,
    *,
    credential_store: CredentialStore,
    client: OnePasswordClient | None = None,
    cache: OnePasswordSecretCache | None = None,
    bypass_cache: bool = False,
    update_cache: bool = True,
) -> tuple[Environment, ...]:
    """Resolve every composed 1Password EnvVar before adapters write output."""

    secrets_by_location = {secret.location: secret for secret in config.secrets}
    secret_env_vars: list[tuple[Environment, EnvVar, OnePasswordSecret]] = []
    for environment in environments:
        for env_var in environment.env_vars:
            if env_var.source != "1password":
                continue
            location = f"environments.{environment.name}.secrets.{env_var.name}"
            secret = secrets_by_location.get(location)
            if secret is not None:
                secret_env_vars.append((environment, env_var, secret))
    if not secret_env_vars:
        return environments

    onepassword = client or OpOnePasswordClient(use_cli_cache=not bypass_cache)
    profiles = {profile.name: profile for profile in config.profiles}
    values: dict[tuple[str, str], SecretValue] = {}
    failures: dict[tuple[str, str], str] = {}

    variables_by_profile: dict[
        str, list[tuple[Environment, EnvVar, OnePasswordSecret]]
    ] = {}
    for environment, env_var, secret in secret_env_vars:
        variables_by_profile.setdefault(secret.profile, []).append(
            (environment, env_var, secret)
        )

    for profile_name, variables in variables_by_profile.items():
        profile = profiles.get(profile_name)
        references = tuple(sorted({secret.reference for _, _, secret in variables}))
        if profile is None:
            for reference in references:
                failures[(profile_name, reference)] = "profile is not declared"
            continue
        resolution = resolve_profile(
            profile,
            references,
            credential_store=credential_store,
            client=onepassword,
            cache=cache,
            bypass_cache=bypass_cache,
            update_cache=update_cache,
        )
        if resolution.cache_failure is not None:
            warnings.warn(
                f"1Password profile {profile_name!r}: {resolution.cache_failure}; "
                "later runs will read 1Password again",
                RuntimeWarning,
                stacklevel=2,
            )
        values.update(
            {(profile_name, ref): value for ref, value in resolution.values.items()}
        )
        failures.update(
            {(profile_name, ref): reason for ref, reason in resolution.failures.items()}
        )

    issues: list[SecretResolutionIssue] = []
    resolved_environments: list[Environment] = []
    for environment in environments:
        resolved_env_vars: list[EnvVar] = []
        for env_var in environment.env_vars:
            if env_var.source != "1password":
                resolved_env_vars.append(env_var)
                continue
            location = f"environments.{environment.name}.secrets.{env_var.name}"
            secret = secrets_by_location[location]
            profile_name = secret.profile
            reference = secret.reference
            key = (profile_name, reference)
            if key in values:
                resolved_env_vars.append(replace(env_var, value=values[key]))
                continue
            if env_var.required:
                issues.append(
                    SecretResolutionIssue(
                        environment=environment.name,
                        variable=env_var.name,
                        profile=profile_name,
                        reference=reference,
                        reason=failures.get(key, "reference was not resolved"),
                    )
                )
            else:
                resolved_env_vars.append(replace(env_var, value=None))
        resolved_environments.append(
            replace(environment, env_vars=tuple(resolved_env_vars))
        )

    if issues:
        raise SecretResolutionError(tuple(issues))
    return tuple(resolved_environments)


def secret_variable_names(
    environments: tuple[Environment, ...],
) -> dict[str, tuple[str, ...]]:
    """Return 1Password-backed variable names grouped by environment."""

    return {
        environment.name: tuple(
            env_var.name
            for env_var in environment.env_vars
            if env_var.source == "1password"
        )
        for environment in environments
        if any(env_var.source == "1password" for env_var in environment.env_vars)
    }
