"""Tool files: one TOML file per tool manifest, named after the tool.

A file holds the fields of ``harness_manifest.to_dict`` with the same
``schema_version``. ``rules`` is either an inline rule set table, named after
the tool unless it says otherwise, or the name of a rule set the caller loaded
from its rule set files, so one rule set file can stay the single source.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from harness_manifest.manifest import ToolManifest
from harness_manifest.rules import RuleSet
from harness_manifest.serialize import from_dict, rule_set_to_dict

import tomllib


def load_manifest(path: Path, rule_sets: Mapping[str, RuleSet] = {}) -> ToolManifest:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        raise ValueError(f"invalid TOML in {path}: {error}") from error
    if path.name == "tool-manifest.toml":
        if not data.get("name"):
            raise ValueError(f"{path}: tool-manifest.toml requires an explicit name")
    elif data.setdefault("name", path.stem) != path.stem:
        raise ValueError(f"{path}: tool name {data['name']!r} must match the file name")
    rules = data.get("rules")
    if isinstance(rules, str):
        if rules not in rule_sets:
            raise ValueError(f"{path}: unknown rule set {rules!r}")
        data["rules"] = rule_set_to_dict(rule_sets[rules])
    elif isinstance(rules, dict):
        rules.setdefault("name", data["name"])
    try:
        return from_dict(data)
    except ValueError as error:
        raise ValueError(f"{path}: {error}") from error


def load_manifests(
    directory: Path, rule_sets: Mapping[str, RuleSet] = {}
) -> dict[str, ToolManifest]:
    """Load every ``*.toml`` tool file in a directory, keyed by file stem."""
    return {
        path.stem: load_manifest(path, rule_sets)
        for path in sorted(directory.glob("*.toml"))
    }
