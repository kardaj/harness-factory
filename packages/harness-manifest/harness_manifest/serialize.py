"""Versioned JSON form of a tool manifest, the contract between CLIs and harnesses.

A CLI prints ``to_json(manifest)`` from its ``manifest`` command; a
harness reads it back with ``from_json``. Unknown versions and unknown fields
fail instead of being ignored, and omitted fields take their model defaults.
Instruction files are local to one checkout, so manifests carry inline blocks.
"""

from __future__ import annotations

import json
from dataclasses import asdict, fields
from pathlib import Path
from typing import Any

from harness_manifest.instructions import (
    InstructionBlock,
    InstructionSet,
    SandboxExclusions,
)
from harness_manifest.manifest import (
    HarnessScopedValue,
    ToolInstall,
    ToolManifest,
    WritableRoot,
    has_relative_root,
)
from harness_manifest.rules import Choice, Rule, RulePart, RuleSet, ShellCommand
from harness_manifest.skills import Skill

SCHEMA_VERSION = 4


def to_json(manifest: ToolManifest) -> str:
    return json.dumps(to_dict(manifest), indent=2) + "\n"


def from_json(text: str) -> ToolManifest:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError(f"tool manifest is not valid JSON: {error}") from error
    return from_dict(data)


def to_dict(manifest: ToolManifest) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "name": manifest.name,
        "installs": [
            {
                "manager": install.manager,
                "name": install.name,
                "source": install.source,
                "commands": list(install.commands),
                "python": install.python,
                "required": install.required,
                "replaces": list(install.replaces),
            }
            for install in manifest.installs
        ],
        "vars": list(manifest.vars),
        "optional_vars": list(manifest.optional_vars),
        "skills": [asdict(skill) for skill in manifest.skills],
        "rules": None if manifest.rules is None else rule_set_to_dict(manifest.rules),
        "writable_roots": [_root_value(root) for root in manifest.writable_roots],
        "network_domains": list(manifest.network_domains),
        "instructions": (
            None
            if manifest.instructions is None
            else _instruction_set_dict(manifest.instructions)
        ),
    }


def from_dict(data: Any) -> ToolManifest:
    try:
        return _manifest(data)
    except TypeError as error:
        raise ValueError(f"invalid tool manifest: {error}") from error


def _manifest(data: Any) -> ToolManifest:
    data = _object(data, "manifest", ToolManifest, extra=("schema_version",))
    version = data.pop("schema_version", None)
    if type(version) is not int or version not in (1, 2, 3, SCHEMA_VERSION):
        raise ValueError(
            f"unsupported tool manifest schema_version {version!r} "
            f"(supported: 1, 2, 3, {SCHEMA_VERSION})"
        )
    if version < 4 and "skills" in data:
        raise ValueError(
            f"schema_version {version} has unknown fields: ['skills']; "
            "migrate to schema_version 4"
        )
    if version < 3 and "optional_vars" in data:
        raise ValueError(
            f"schema_version {version} has unknown fields: ['optional_vars']; "
            "migrate to schema_version 3"
        )
    location = f"manifest {data.get('name')!r}"
    if "skills" in data:
        data["skills"] = tuple(
            Skill(**_object(item, f"{location} skill", Skill))
            for item in _list(data["skills"], f"{location} skills")
        )
    if "installs" in data:
        data["installs"] = tuple(
            ToolInstall(**_tuples(_object(item, f"{location} install", ToolInstall)))
            for item in _list(data["installs"], f"{location} installs")
        )
    if data.get("rules") is not None:
        rules = data["rules"]
        if isinstance(rules, dict):
            rules = {"rules": [], **rules}
        data["rules"] = _rule_set(rules, f"{location} rules")
    if "writable_roots" in data:
        data["writable_roots"] = tuple(
            _root(item, location)
            for item in _list(data["writable_roots"], f"{location} writable_roots")
        )
    if version == 1 and has_relative_root(data.get("writable_roots", ())):
        raise ValueError(
            "schema_version 1 writable roots must be absolute; migrate to schema_version 2"
        )
    if data.get("instructions") is not None:
        data["instructions"] = _instruction_set(data["instructions"], location)
    return ToolManifest(**_tuples(data))


def rule_set_to_dict(rule_set: RuleSet) -> dict[str, Any]:
    """Return the JSON-compatible form shared by manifests and rule set files."""
    return {
        "name": rule_set.name,
        "description": rule_set.description,
        "tags": list(rule_set.tags),
        "sandbox_excluded_commands": list(rule_set.sandbox_excluded_commands),
        "sandbox_exclusion_reason": rule_set.sandbox_exclusion_reason,
        "rules": [
            {
                "effect": rule.effect,
                "command": [_part_value(part) for part in rule.target.parts],
                "justification": rule.justification,
                "match": list(rule.match),
                "not_match": list(rule.not_match),
                "tags": list(rule.tags),
            }
            for rule in rule_set.rules
        ],
    }


def rule_set_from_dict(value: Any, location: str = "rule set") -> RuleSet:
    """Parse the form written by ``rule_set_to_dict``, rejecting unknown fields."""
    try:
        return _rule_set(value, location)
    except TypeError as error:
        raise ValueError(f"invalid {location}: {error}") from error


def _rule_set(value: Any, location: str) -> RuleSet:
    data = _object(value, location, RuleSet)
    data["rules"] = tuple(
        _rule(item, location) for item in _list(data.get("rules"), f"{location} rules")
    )
    return RuleSet(**_tuples(data))


def _rule(value: Any, location: str) -> Rule:
    data = _object(
        value, f"{location} rule", Rule, extra=("command",), omit=("target",)
    )
    parts = _list(data.pop("command", None), f"{location} rule command")
    data["target"] = ShellCommand(tuple(_part(part, location) for part in parts))
    return Rule(**_tuples(data))


def _part_value(part: RulePart) -> str | list[str]:
    return list(part.values) if isinstance(part, Choice) else part


def _part(value: Any, location: str) -> RulePart:
    if isinstance(value, str):
        return value
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return Choice(tuple(value))
    raise ValueError(
        f"{location} rule command parts must be strings or arrays of string choices"
    )


def _root_value(root: WritableRoot) -> str | dict[str, str]:
    if isinstance(root, Path):
        return str(root)
    return {
        harness: str(value)
        for harness in ("default", "codex", "claude")
        if (value := getattr(root, harness)) is not None
    }


def _root(value: Any, location: str) -> WritableRoot:
    if isinstance(value, str):
        return Path(value)
    if (
        isinstance(value, dict)
        and value
        and set(value) <= {"default", "codex", "claude"}
        and all(isinstance(path, str) for path in value.values())
    ):
        return HarnessScopedValue(**{key: Path(path) for key, path in value.items()})
    raise ValueError(
        f"{location} writable roots must be paths or harness-scoped path objects"
    )


def _instruction_set_dict(instruction_set: InstructionSet) -> dict[str, Any]:
    blocks: list[dict[str, Any]] = []
    for source in instruction_set.blocks:
        if isinstance(source, InstructionBlock):
            blocks.append({"title": source.title, "body": source.body})
        elif isinstance(source, SandboxExclusions):
            blocks.append({"sandbox_exclusions": True})
        else:
            raise ValueError(
                f"instruction set {instruction_set.name!r} must inline its files "
                "as blocks before export"
            )
    return {
        "name": instruction_set.name,
        "harnesses": list(instruction_set.harnesses),
        "blocks": blocks,
    }


def _instruction_set(value: Any, location: str) -> InstructionSet:
    data = _object(value, f"{location} instructions", InstructionSet)
    blocks: list[InstructionBlock | SandboxExclusions] = []
    for item in _list(data.get("blocks"), f"{location} instruction blocks"):
        if item == {"sandbox_exclusions": True}:
            blocks.append(SandboxExclusions())
        else:
            blocks.append(
                InstructionBlock(
                    **_object(item, f"{location} instruction block", InstructionBlock)
                )
            )
    data["blocks"] = tuple(blocks)
    return InstructionSet(**_tuples(data))


def _object(
    value: Any,
    location: str,
    model: type,
    *,
    extra: tuple[str, ...] = (),
    omit: tuple[str, ...] = (),
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{location} must be a JSON object")
    known = {field.name for field in fields(model)} - set(omit) | set(extra)
    unknown = sorted(set(value) - known)
    if unknown:
        raise ValueError(f"{location} has unknown fields: {unknown}")
    return dict(value)


def _list(value: Any, location: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{location} must be a JSON array")
    return value


def _tuples(data: dict[str, Any]) -> dict[str, Any]:
    return {
        key: tuple(value) if isinstance(value, list) else value
        for key, value in data.items()
    }
