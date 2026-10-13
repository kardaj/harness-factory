"""Load and validate tracked 1Password harness configuration."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from harness_factory.models import Environment, EnvVar
from harness_secrets import OnePasswordProfile

import tomllib

PROFILE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


class OnePasswordConfigError(ValueError):
    """Raised when the tracked 1Password configuration is invalid."""


@dataclass(frozen=True)
class OnePasswordSecret:
    environment: str
    variable: str
    profile: str
    reference: str
    required: bool = True

    @property
    def location(self) -> str:
        return f"environments.{self.environment}.secrets.{self.variable}"


@dataclass(frozen=True)
class OnePasswordConfig:
    profiles: tuple[OnePasswordProfile, ...]
    secrets: tuple[OnePasswordSecret, ...]

    @property
    def active_profiles(self) -> tuple[OnePasswordProfile, ...]:
        active_names = {secret.profile for secret in self.secrets}
        return tuple(
            profile for profile in self.profiles if profile.name in active_names
        )


def load_onepassword_config(path: Path) -> OnePasswordConfig:
    try:
        with path.open("rb") as config_file:
            raw = tomllib.load(config_file)
    except FileNotFoundError as error:
        raise OnePasswordConfigError(f"missing 1Password config: {path}") from error
    except tomllib.TOMLDecodeError as error:
        raise OnePasswordConfigError(f"invalid TOML in {path}: {error}") from error

    profiles = _load_profiles(raw)
    secrets = _load_secrets(raw, {profile.name for profile in profiles})
    return OnePasswordConfig(profiles=profiles, secrets=secrets)


def compose_onepassword_environments(
    environments: tuple[Environment, ...], config: OnePasswordConfig
) -> tuple[Environment, ...]:
    """Validate and normalize Python EnvVar links to tracked declarations."""

    by_name = {environment.name: environment for environment in environments}
    if len(by_name) != len(environments):
        raise OnePasswordConfigError("Python environment names must be unique")

    secrets_by_location = {secret.location: secret for secret in config.secrets}
    for secret in config.secrets:
        environment = by_name.get(secret.environment)
        if environment is None:
            raise OnePasswordConfigError(
                f"secret {secret.environment}.{secret.variable} references unknown "
                f"environment {secret.environment!r}"
            )
        authored = [
            env_var
            for env_var in environment.env_vars
            if env_var.name == secret.variable
        ]
        if not authored:
            raise OnePasswordConfigError(
                f"{secret.location} is not linked from the Python environment model"
            )
        if len(authored) != 1 or authored[0].source != "1password":
            raise OnePasswordConfigError(
                f"{secret.location} conflicts with the Python environment variable "
                "declaration"
            )
        if authored[0].value != secret.location:
            raise OnePasswordConfigError(
                f"1Password env var {secret.environment}.{secret.variable} must use "
                f"value={secret.location!r}"
            )

    composed: list[Environment] = []
    for environment in environments:
        normalized_env_vars: list[EnvVar] = []
        for env_var in environment.env_vars:
            if env_var.source != "1password":
                normalized_env_vars.append(env_var)
                continue
            expected_location = (
                f"environments.{environment.name}.secrets.{env_var.name}"
            )
            if env_var.value != expected_location:
                raise OnePasswordConfigError(
                    f"1Password env var {environment.name}.{env_var.name} must use "
                    f"value={expected_location!r}"
                )
            secret = secrets_by_location.get(expected_location)
            if secret is None:
                raise OnePasswordConfigError(
                    f"1Password env var {environment.name}.{env_var.name} references "
                    f"missing tracked declaration {expected_location}"
                )
            normalized_env_vars.append(replace(env_var, required=secret.required))
        composed.append(replace(environment, env_vars=tuple(normalized_env_vars)))
    return tuple(composed)


def _load_profiles(raw: dict[str, Any]) -> tuple[OnePasswordProfile, ...]:
    onepassword = _mapping(raw.get("onepassword"), "onepassword")
    raw_profiles = _mapping(onepassword.get("profiles"), "onepassword.profiles")
    if not raw_profiles:
        raise OnePasswordConfigError("onepassword.profiles must not be empty")

    profiles: list[OnePasswordProfile] = []
    for name, value in raw_profiles.items():
        if not isinstance(name, str) or not PROFILE_NAME_PATTERN.fullmatch(name):
            raise OnePasswordConfigError(f"invalid 1Password profile name: {name!r}")
        profile = _mapping(value, f"onepassword.profiles.{name}")
        description = _nonempty_string(
            profile.get("description"), f"onepassword.profiles.{name}.description"
        )
        vault = _nonempty_string(
            profile.get("vault"), f"onepassword.profiles.{name}.vault"
        )
        profiles.append(
            OnePasswordProfile(name=name, description=description, vault=vault)
        )
    return tuple(profiles)


def _load_secrets(
    raw: dict[str, Any], profile_names: set[str]
) -> tuple[OnePasswordSecret, ...]:
    raw_environments = raw.get("environments", {})
    environments = _mapping(raw_environments, "environments")
    secrets: list[OnePasswordSecret] = []
    for environment_name, environment_value in environments.items():
        if not isinstance(environment_name, str) or not PROFILE_NAME_PATTERN.fullmatch(
            environment_name
        ):
            raise OnePasswordConfigError(
                f"invalid environment name: {environment_name!r}"
            )
        environment = _mapping(environment_value, f"environments.{environment_name}")
        raw_secrets = environment.get("secrets", {})
        environment_secrets = _mapping(
            raw_secrets, f"environments.{environment_name}.secrets"
        )
        for variable, secret_value in environment_secrets.items():
            if not isinstance(variable, str) or not PROFILE_NAME_PATTERN.fullmatch(
                variable
            ):
                raise OnePasswordConfigError(
                    f"invalid environment variable name: {variable!r}"
                )
            location = f"environments.{environment_name}.secrets.{variable}"
            secret = _mapping(secret_value, location)
            profile = _nonempty_string(secret.get("profile"), f"{location}.profile")
            if profile not in profile_names:
                raise OnePasswordConfigError(
                    f"{location}.profile references undeclared profile {profile!r}"
                )
            reference = _nonempty_string(
                secret.get("reference"), f"{location}.reference"
            )
            if not reference.startswith("op://"):
                raise OnePasswordConfigError(
                    f"{location}.reference must start with 'op://'"
                )
            required = secret.get("required", True)
            if not isinstance(required, bool):
                raise OnePasswordConfigError(f"{location}.required must be a boolean")
            secrets.append(
                OnePasswordSecret(
                    environment=str(environment_name),
                    variable=str(variable),
                    profile=profile,
                    reference=reference,
                    required=required,
                )
            )
    return tuple(secrets)


def _mapping(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OnePasswordConfigError(f"{location} must be a table")
    return value


def _nonempty_string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OnePasswordConfigError(f"{location} must be a non-empty string")
    return value
