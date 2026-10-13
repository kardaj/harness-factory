"""Preserve agent-flow user settings while deploying provider home defaults."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from tempfile import NamedTemporaryFile

import tomlkit


def sync_provider_homes(
    settings_path: Path,
    *,
    codex_home: Path,
    claude_home: Path,
    apply: bool = True,
) -> bool:
    """Merge the two managed defaults; return whether an update is needed.

    Inspection leaves the filesystem untouched. Writes are atomic and private,
    and preserve other settings and comments. No provider or workflow is run.
    """
    if not codex_home.is_absolute() or not claude_home.is_absolute():
        raise ValueError("Provider homes must be absolute paths")
    if settings_path.is_symlink():
        raise ValueError("Agent-flow settings must not be a symlink")
    original = settings_path.read_text() if settings_path.exists() else ""
    try:
        document = tomlkit.parse(original)
    except ValueError:
        # Parser errors can quote personal settings, including credentials.
        raise ValueError("Invalid TOML in agent-flow user settings") from None

    work_home = document.get("work_home")
    if work_home is not None and (
        not isinstance(work_home, str) or not Path(work_home).is_absolute()
    ):
        raise ValueError("Invalid work_home in agent-flow user settings")
    adapters = document.setdefault("adapters", tomlkit.table())
    if not isinstance(adapters, Mapping):
        raise ValueError("Invalid adapters table in agent-flow user settings")
    for provider, variable, home in (
        ("codex", "CODEX_HOME", codex_home),
        ("claude", "CLAUDE_CONFIG_DIR", claude_home),
    ):
        adapter = adapters.setdefault(provider, tomlkit.table())
        if not isinstance(adapter, Mapping):
            raise ValueError(f"Invalid adapters.{provider} table")
        environment = adapter.setdefault("env", tomlkit.table())
        if not isinstance(environment, Mapping) or any(
            not key
            or "=" in key
            or "\0" in key
            or not isinstance(value, str)
            or "\0" in value
            for key, value in environment.items()
        ):
            raise ValueError(f"Invalid adapters.{provider}.env table")
        if environment.get(variable) != str(home):
            environment[variable] = str(home)

    expected = document.as_string()
    changed = original != expected or settings_path.stat().st_mode & 0o777 != 0o600
    if not changed or not apply:
        return changed
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(
        mode="w",
        dir=settings_path.parent,
        prefix=f".{settings_path.name}.",
        delete=False,
    ) as temporary:
        temporary_path = Path(temporary.name)
        try:
            temporary.write(expected)
            temporary.flush()
            # Do not overwrite settings edited since the merge was planned.
            current = settings_path.read_text() if settings_path.exists() else ""
            if settings_path.is_symlink() or current != original:
                raise ValueError("Agent-flow settings changed during deployment; retry")
            os.replace(temporary_path, settings_path)
        finally:
            temporary_path.unlink(missing_ok=True)
    return True
