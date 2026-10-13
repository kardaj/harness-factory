"""Rule set files: one TOML file per rule set, named after the rule set by default.

A file holds the fields of ``harness_manifest.rule_set_to_dict`` plus
``schema_version``. ``name`` is omitted when it equals the file stem, so two
environments' variants of one rule set can live side by side under different
file names. ``dump_rule_set`` writes the canonical layout that ``load_rule_set``
reads back to an equal ``RuleSet``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from harness_manifest.rules import RuleSet
from harness_manifest.serialize import rule_set_from_dict, rule_set_to_dict

import tomllib

RULE_FILE_SCHEMA_VERSION = 1
LINE_LENGTH = 88


def load_rule_set(path: Path) -> RuleSet:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        raise ValueError(f"invalid TOML in {path}: {error}") from error
    version = data.pop("schema_version", None)
    if type(version) is not int or version != RULE_FILE_SCHEMA_VERSION:
        raise ValueError(
            f"{path}: unsupported rule file schema_version {version!r} "
            f"(supported: {RULE_FILE_SCHEMA_VERSION})"
        )
    data.setdefault("name", path.stem)
    return rule_set_from_dict(data, str(path))


def load_rule_sets(directory: Path) -> dict[str, RuleSet]:
    """Load every ``*.toml`` rule set in a directory, keyed by file stem."""
    return {path.stem: load_rule_set(path) for path in sorted(directory.glob("*.toml"))}


def dump_rule_set(rule_set: RuleSet, stem: str) -> str:
    data = rule_set_to_dict(rule_set)
    if data["name"] == stem:
        del data["name"]
    rules = data.pop("rules")
    lines = [f"schema_version = {RULE_FILE_SCHEMA_VERSION}"]
    lines.extend(_fields(data))
    for rule in rules:
        lines.extend(("", "[[rules]]", *_fields(rule)))
    return "\n".join(lines) + "\n"


def _fields(data: dict[str, Any]) -> list[str]:
    return [
        _assignment(key, value)
        for key, value in data.items()
        if value is not None and value != []
    ]


def _assignment(key: str, value: Any) -> str:
    inline = f"{key} = {_inline(value)}"
    if len(inline) <= LINE_LENGTH or not isinstance(value, list):
        return inline
    items = "".join(f"  {_wrapped(item)},\n" for item in value)
    return f"{key} = [\n{items}]"


def _wrapped(value: Any) -> str:
    inline = _inline(value)
    if len(inline) + 3 <= LINE_LENGTH or not isinstance(value, list):
        return inline
    items = "".join(f"    {_inline(item)},\n" for item in value)
    return f"[\n{items}  ]"


def _inline(value: Any) -> str:
    if isinstance(value, list):
        return f"[{', '.join(_inline(item) for item in value)}]"
    return json.dumps(value, ensure_ascii=False)
