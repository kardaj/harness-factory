"""Environment files: one TOML file per environment, named after it by the stem.

A file holds ``Environment`` fields under their own names plus
``schema_version`` and an optional ``extends``. Rule sets, instruction sets, and
tools are referenced by name; ``env_vars`` and ``base_mcp_servers`` are tables
keyed by name; ``${NAME}`` in any string or key takes a caller-supplied value
the files cannot compute, such as the checkout path.

An environment that extends another merges each of its own fields into the
base: scalars and ``sandbox`` scalars override; named entries (``env_vars``,
``base_mcp_servers``, ``rules``, ``instruction_sets``) replace the base entry of
the same name in its place or append; other lists, including ``sandbox`` lists,
append without repeats; ``harness_overrides`` merge recursively, with lists
replaced. A rule set or instruction set a base's tool contributed belongs to
that tool, so a file may only list the identical set. Each file then applies
its own tools, so a base's tools keep their place in render order.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import fields, replace
from pathlib import Path
from typing import Any

import tomllib

from harness_factory.models import (
    EnvVar,
    Environment,
    HomeFile,
    SandboxPolicy,
    ToolServer,
    TrustedProject,
    TrustedProjectChildren,
)
from harness_factory.tools import apply_tools, tool_owners
from harness_manifest import (
    HarnessScopedValue,
    InstructionSet,
    RuleSet,
    ToolManifest,
    instructions,
    markdown,
    sandbox_exclusions,
)

SCHEMA_VERSION = 1
_VARIABLE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_SCALARS = (
    "reasoning_tier",
    "context_window_size",
    "web_search",
    "personality",
    "approval_policy",
    "retired_notification",
)
_NAMED = ("env_vars", "base_mcp_servers", "rules", "instruction_sets")
_HARNESS_KEYS = ("default", "codex", "claude")
_TOOL_OWNED = {
    "rules": lambda tool: tool.rules,
    "instruction_sets": lambda tool: tool.instructions,
}


def load_instruction_sets(path: Path, *, root: Path) -> dict[str, InstructionSet]:
    """Load named sets of markdown files, optionally ending with sandbox exclusions.

    Relative markdown paths resolve against ``root``, not the working directory.
    """
    data = _load(path, {})
    sets = {}
    for name, value in data.items():
        location = f"{path}: instruction set {name!r}"
        value = _table(value, location, ("harnesses", "markdown", "sandbox_exclusions"))
        blocks = [markdown(root / file) for file in value.get("markdown", [])]
        if value.get("sandbox_exclusions", False):
            blocks.append(sandbox_exclusions())
        sets[name] = instructions(
            name, *blocks, harnesses=tuple(value.get("harnesses", ("codex", "claude")))
        )
    return sets


def load_environments(
    directory: Path,
    *,
    rule_sets: Mapping[str, RuleSet],
    instruction_sets: Mapping[str, InstructionSet],
    tools: Mapping[str, ToolManifest],
    variables: Mapping[str, str],
) -> dict[str, Environment]:
    """Load every ``*.toml`` environment in a directory, keyed by file stem."""
    files = {
        path.stem: _load(path, variables) for path in sorted(directory.glob("*.toml"))
    }
    loaded: dict[str, Environment] = {}

    def build(name: str, chain: tuple[str, ...]) -> Environment:
        if name in loaded:
            return loaded[name]
        if name in chain:
            raise ValueError(f"environment {name!r} extends itself: {chain}")
        if name not in files:
            raise ValueError(f"unknown environment {name!r} in {directory}")
        data = dict(files[name])
        location = f"{directory / name}.toml"
        base_name = data.pop("extends", None)
        try:
            layer_tools = [
                _named(tools, tool, "tool") for tool in data.pop("tools", [])
            ]
            layer = _layer(data, rule_sets, instruction_sets)
            if base_name is None:
                environment = _create(name, layer)
            else:
                environment = _extend(build(base_name, (*chain, name)), name, layer)
            loaded[name] = apply_tools(environment, *layer_tools)
        except (TypeError, ValueError) as error:
            raise ValueError(f"{location}: {error}") from error
        return loaded[name]

    return {name: build(name, ()) for name in files}


def _load(path: Path, variables: Mapping[str, str]) -> dict[str, Any]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        raise ValueError(f"invalid TOML in {path}: {error}") from error
    version = data.pop("schema_version", None)
    if type(version) is not int or version != SCHEMA_VERSION:
        raise ValueError(
            f"{path}: unsupported schema_version {version!r} "
            f"(supported: {SCHEMA_VERSION})"
        )
    return _substitute(data, variables, path)


def _substitute(value: Any, variables: Mapping[str, str], path: Path) -> Any:
    if isinstance(value, str):

        def lookup(match: re.Match[str]) -> str:
            if match.group(1) not in variables:
                raise ValueError(f"{path}: unknown variable ${{{match.group(1)}}}")
            return variables[match.group(1)]

        return _VARIABLE.sub(lookup, value)
    if isinstance(value, list):
        return [_substitute(item, variables, path) for item in value]
    if isinstance(value, dict):
        return {
            _substitute(key, variables, path): _substitute(item, variables, path)
            for key, item in value.items()
        }
    return value


def _layer(
    data: dict[str, Any],
    rule_sets: Mapping[str, RuleSet],
    instruction_sets: Mapping[str, InstructionSet],
) -> dict[str, Any]:
    """Convert one file's fields to ``Environment`` values without merging."""
    known = {field.name for field in fields(Environment)} - {"name", "tools"}
    unsupported = {"agents", "modes", "notification"}
    unknown = sorted(set(data) - (known - unsupported))
    if unknown:
        raise ValueError(f"unknown or unsupported fields: {unknown}")
    layer: dict[str, Any] = {}
    for key, value in data.items():
        if key in ("context_window_size", "web_search"):
            layer[key] = _scoped(value)
        elif key == "rules":
            layer[key] = tuple(_named(rule_sets, name, "rule set") for name in value)
        elif key == "instruction_sets":
            layer[key] = tuple(
                _named(instruction_sets, name, "instruction set") for name in value
            )
        elif key == "env_vars":
            layer[key] = tuple(_env_var(name, spec) for name, spec in value.items())
        elif key == "base_mcp_servers":
            layer[key] = tuple(_server(name, spec) for name, spec in value.items())
        elif key == "sandbox":
            layer[key] = _sandbox_fields(value)
        elif key == "home_files":
            layer[key] = tuple(_home_file(spec) for spec in value)
        elif key == "trusted_projects":
            layer[key] = tuple(_trusted_project(spec) for spec in value)
        elif key == "harness_overrides":
            layer[key] = _table(value, key, ("codex", "claude"))
        elif isinstance(value, list):
            layer[key] = tuple(value)
        else:
            layer[key] = value
    return layer


def _create(name: str, layer: dict[str, Any]) -> Environment:
    sandbox = layer.pop("sandbox", {})
    return Environment(name=name, sandbox=SandboxPolicy(**sandbox), **layer)


def _extend(base: Environment, name: str, layer: dict[str, Any]) -> Environment:
    merged: dict[str, Any] = {"name": name}
    for key, value in layer.items():
        current = getattr(base, key)
        if key == "sandbox":
            merged[key] = replace(
                current,
                **{
                    field: (
                        tuple(dict.fromkeys(getattr(current, field) + item))
                        if isinstance(item, tuple)
                        else item
                    )
                    for field, item in value.items()
                },
            )
        elif key == "harness_overrides":
            merged[key] = _merge_nested(current, value)
        elif key in _SCALARS:
            merged[key] = value
        elif key in _NAMED:
            if key in _TOOL_OWNED:
                _check_tool_owned(base, key, value)
            merged[key] = _upsert(current, value)
        else:
            merged[key] = tuple(dict.fromkeys(current + value))
    return replace(base, **merged)


def _check_tool_owned(base: Environment, key: str, value: tuple[Any, ...]) -> None:
    owners = tool_owners(base, _TOOL_OWNED[key])
    current = {item.name: item for item in getattr(base, key)}
    for item in value:
        if item.name in owners and current.get(item.name) != item:
            raise ValueError(
                f"{key} entry {item.name!r} is owned by tool {owners[item.name]!r}"
            )


def _upsert(current: tuple[Any, ...], new: tuple[Any, ...]) -> tuple[Any, ...]:
    by_name = {item.name: item for item in new}
    kept = tuple(by_name.pop(item.name, item) for item in current)
    return kept + tuple(by_name.values())


def _merge_nested(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(left)
    for key, value in right.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_nested(merged[key], value)
        else:
            merged[key] = deepcopy(value)
    return merged


def _named(values: Mapping[str, Any], name: str, kind: str) -> Any:
    if name not in values:
        raise ValueError(f"unknown {kind} {name!r}")
    return values[name]


def _table(value: Any, location: str, allowed: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{location} must be a table")
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise ValueError(f"{location} has unknown fields: {unknown}")
    return value


def _scoped(value: Any) -> Any:
    if isinstance(value, dict):
        return HarnessScopedValue(**_table(value, "scoped value", _HARNESS_KEYS))
    return value


def _env_var(name: str, spec: Any) -> EnvVar:
    if not isinstance(spec, dict):
        return EnvVar(name, value=spec)
    spec = _table(spec, f"env var {name!r}", ("value", "source", "required"))
    return EnvVar(
        name,
        **{
            **spec,
            "value": _scoped(spec.get("value")),
            "source": _scoped(spec.get("source", "literal")),
        },
    )


def _server(name: str, spec: Any) -> ToolServer:
    spec = _table(
        spec,
        f"MCP server {name!r}",
        tuple(field.name for field in fields(ToolServer) if field.name != "name"),
    )
    if "args" in spec:
        spec["args"] = tuple(spec["args"])
    if "cwd" in spec:
        spec["cwd"] = Path(spec["cwd"])
    return ToolServer(name=name, **spec)


def _sandbox_fields(spec: Any) -> dict[str, Any]:
    spec = _table(spec, "sandbox", tuple(field.name for field in fields(SandboxPolicy)))
    converted: dict[str, Any] = {}
    for key, value in spec.items():
        if key == "writable_roots":
            converted[key] = tuple(
                Path(root)
                if isinstance(root, str)
                else HarnessScopedValue(
                    **{
                        harness: Path(path)
                        for harness, path in _table(
                            root, "writable root", _HARNESS_KEYS
                        ).items()
                    }
                )
                for root in value
            )
        elif key == "network_allowed_unix_sockets":
            converted[key] = tuple(Path(socket) for socket in value)
        elif isinstance(value, list):
            converted[key] = tuple(value)
        else:
            converted[key] = value
    return converted


def _home_file(spec: Any) -> HomeFile:
    spec = _table(spec, "home file", tuple(field.name for field in fields(HomeFile)))
    return HomeFile(
        **{
            **spec,
            "relative_path": Path(spec["relative_path"]),
            "source_path": Path(spec["source_path"]),
            **({"harnesses": tuple(spec["harnesses"])} if "harnesses" in spec else {}),
        }
    )


def _trusted_project(spec: Any) -> TrustedProject | TrustedProjectChildren:
    if isinstance(spec, dict) and "path" in spec:
        spec = _table(spec, "trusted project", ("path",))
        return TrustedProject(Path(spec["path"]))
    spec = _table(
        spec, "trusted project", ("root", "only_git_repos", "devcontainer_mirror")
    )
    return TrustedProjectChildren(
        root=Path(spec["root"]),
        only_git_repos=spec.get("only_git_repos", True),
        devcontainer_mirror=(
            Path(spec["devcontainer_mirror"]) if "devcontainer_mirror" in spec else None
        ),
    )
