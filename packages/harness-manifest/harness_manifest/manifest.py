"""Portable tool manifests: how a CLI is installed, configured, explained, and locked down.

A CLI may publish its own manifest; harness applications decide which
environments apply it and supply the values of the variables it names.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal, get_args

from harness_manifest import checks

from harness_manifest.instructions import InstructionSet
from harness_manifest.rules import RuleSet
from harness_manifest.skills import Skill

HarnessName = Literal["codex", "claude"]
InstallManager = Literal["uv", "bun", "brew", "cask"]


@dataclass(frozen=True)
class HarnessScopedValue:
    """A value that applies only to selected harness adapters."""

    default: Any = None
    codex: Any = None
    claude: Any = None

    def resolve(self, harness: HarnessName) -> Any:
        value = getattr(self, harness)
        return self.default if value is None else value


def codex_only(value: Any) -> HarnessScopedValue:
    return HarnessScopedValue(codex=value)


def claude_only(value: Any) -> HarnessScopedValue:
    return HarnessScopedValue(claude=value)


WritableRoot = Path | HarnessScopedValue


def writable_root_paths(root: WritableRoot) -> tuple[Path, ...]:
    """Return every path a root names, for any harness."""
    if isinstance(root, Path):
        return (root,)
    return tuple(
        value for value in (root.default, root.codex, root.claude) if value is not None
    )


def has_relative_root(roots: tuple[WritableRoot, ...]) -> bool:
    return any(
        not isinstance(path, Path) or not path.is_absolute()
        for root in roots
        for path in writable_root_paths(root)
    )


@dataclass(frozen=True)
class ToolInstall:
    """A persistent installation the application's bootstrap is expected to provide."""

    manager: InstallManager
    name: str
    source: str
    commands: tuple[str, ...]
    python: str | None = None
    required: bool = True
    replaces: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        checks.one_of(self.manager, get_args(InstallManager), "install manager")
        checks.string(self.name, "install name")
        checks.string(self.source, f"install {self.name!r} source")
        checks.strings(self.commands, f"install {self.name!r} commands")
        checks.optional_string(self.python, f"install {self.name!r} python")
        checks.boolean(self.required, f"install {self.name!r} required")
        checks.strings(self.replaces, f"install {self.name!r} replaces")
        if not self.commands or not all(self.commands):
            raise ValueError(f"install {self.name!r} requires commands")
        if self.python is not None and self.manager != "uv":
            raise ValueError(f"only uv installs select a Python for {self.name!r}")
        if self.name in self.replaces:
            raise ValueError(f"install {self.name!r} cannot replace itself")
        if self.manager in ("brew", "cask") and (not self.required or self.replaces):
            raise ValueError(
                f"Homebrew install {self.name!r} cannot be optional or replace packages"
            )


@dataclass(frozen=True)
class ToolManifest:
    """Everything an environment needs to let agents use one CLI."""

    name: str
    installs: tuple[ToolInstall, ...] = ()
    vars: tuple[str, ...] = ()
    rules: RuleSet | None = None
    writable_roots: tuple[WritableRoot, ...] = ()
    network_domains: tuple[str, ...] = ()
    instructions: InstructionSet | None = None
    optional_vars: tuple[str, ...] = ()
    skills: tuple[Skill, ...] = ()

    def __post_init__(self) -> None:
        checks.string(self.name, "tool name")
        checks.instances(self.skills, Skill, f"tool {self.name!r} skills")
        names = [skill.name for skill in self.skills]
        if len(set(names)) != len(names):
            raise ValueError(f"tool {self.name!r} skills must have unique names")
        checks.instances(self.installs, ToolInstall, f"tool {self.name!r} installs")
        checks.identifiers(self.vars, f"tool {self.name!r} vars")
        checks.identifiers(self.optional_vars, f"tool {self.name!r} optional_vars")
        checks.optional_instance(self.rules, RuleSet, f"tool {self.name!r} rules")
        if (
            self.rules is not None
            and not self.rules.rules
            and not self.rules.sandbox_excluded_commands
        ):
            raise ValueError(
                f"tool {self.name!r} has an empty rule set; omit rules "
                "(use null in JSON or no [rules] table in TOML)"
            )
        checks.instances(
            self.writable_roots,
            (Path, HarnessScopedValue),
            f"tool {self.name!r} writable_roots",
        )
        checks.domains(self.network_domains, f"tool {self.name!r} network_domains")
        checks.optional_instance(
            self.instructions, InstructionSet, f"tool {self.name!r} instructions"
        )
        for root in self.writable_roots:
            for path in writable_root_paths(root):
                _validate_root(path, self.vars + self.optional_vars)
        for field in ("vars", "optional_vars"):
            names = getattr(self, field)
            if len(set(names)) != len(names):
                raise ValueError(f"tool {self.name!r} {field} must be unique names")
        if set(self.vars) & set(self.optional_vars):
            raise ValueError(
                f"tool {self.name!r} vars and optional_vars must not overlap"
            )


_VARIABLE_ROOT = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}(?:/|$)")


def _validate_root(path: Path, variables: tuple[str, ...]) -> None:
    if not isinstance(path, Path):
        raise ValueError("writable roots must be paths")
    if path.is_absolute():
        return
    text = str(path)
    variable = _VARIABLE_ROOT.match(text)
    if text == "~" or text.startswith("~/"):
        suffix = text[2:]
    elif variable and variable[1] in variables:
        suffix = text[variable.end() :]
    else:
        raise ValueError(
            "writable roots must be absolute, ~/ paths, or roots from declared vars"
        )
    if ".." in Path(suffix).parts or "$" in suffix:
        raise ValueError(
            "portable writable roots cannot contain parent traversal or nested variables"
        )


def resolve_manifest(
    manifest: ToolManifest, *, home: Path, variables: Mapping[str, str]
) -> ToolManifest:
    """Resolve portable roots using caller-supplied values, without reading the host.

    Variable values must be absolute paths or ~/ paths. No shell evaluation,
    recursive substitution, filesystem lookup, or secret-source loading occurs.
    Roots using an optional variable absent from ``variables`` are omitted;
    supplied optional values must still be valid paths.
    """
    if not home.is_absolute():
        raise ValueError("manifest home must be absolute")

    def resolve(path: Path) -> Path | None:
        text = str(path)
        if path.is_absolute():
            return path
        if variable := _VARIABLE_ROOT.match(text):
            if variable[1] in manifest.optional_vars and variable[1] not in variables:
                return None
            value = variables.get(variable[1])
            if not isinstance(value, str) or not value:
                raise ValueError(
                    f"writable root variable {variable[1]!r} requires a path value"
                )
            base = Path(value)
            _validate_root(base, ())
            if not base.is_absolute():
                base = home / str(base)[2:]
            return base / text[variable.end() :]
        return home / text[2:]

    roots: list[WritableRoot] = []
    for root in manifest.writable_roots:
        if isinstance(root, Path):
            if (resolved := resolve(root)) is not None:
                roots.append(resolved)
        else:
            values = {
                harness: resolve(value)
                for harness in ("default", "codex", "claude")
                if (value := getattr(root, harness)) is not None
            }
            if None in values.values():
                # Dropping an override must not expose its default to that
                # harness. Materialize the effective per-harness roots instead.
                values = {
                    harness: resolved
                    for harness in ("codex", "claude")
                    if (value := root.resolve(harness)) is not None
                    and (resolved := resolve(value)) is not None
                }
            if values:
                roots.append(HarnessScopedValue(**values))
    return replace(manifest, writable_roots=tuple(roots))
