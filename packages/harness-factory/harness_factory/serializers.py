"""Small config serializers used by harness adapters."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def dump_json(data: dict[str, Any], path: Path) -> None:
    _write_private(path, json.dumps(data, indent=2, sort_keys=True) + "\n")


def dumps_toml(data: dict[str, Any]) -> str:
    """Serialize a limited TOML subset.

    The serializer intentionally supports only the primitive structures emitted
    by this package: nested tables, strings, booleans, numbers, arrays of
    primitives, and arrays of inline primitive dicts.
    """

    lines: list[str] = []
    _write_table(lines, [], data)
    return "\n".join(lines).rstrip() + "\n"


def dump_toml(data: dict[str, Any], path: Path) -> None:
    _write_private(path, dumps_toml(data))


def _write_private(path: Path, text: str) -> None:
    """Atomically replace path with a file that is private from creation.

    Rendered configs may contain resolved secrets, so missing directories are
    created ``0o700`` and the file never exists with a mode wider than ``0o600``.
    """
    missing = [
        directory
        for directory in (path.parent, *path.parent.parents)
        if not directory.exists()
    ]
    for directory in reversed(missing):
        directory.mkdir(mode=0o700, exist_ok=True)
    if path.is_symlink():
        raise ValueError(f"Refusing to write config through symlink: {path}")
    # mkstemp creates the file with mode 0o600 in the target's directory.
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(text)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _write_table(lines: list[str], prefix: list[str], table: dict[str, Any]) -> None:
    scalars: dict[str, Any] = {}
    subtables: dict[str, dict[str, Any]] = {}

    for key, value in table.items():
        if value is None:
            continue
        if isinstance(value, dict):
            subtables[key] = value
        else:
            scalars[key] = value

    for key, value in scalars.items():
        lines.append(f"{_quote_key(key)} = {_format_value(value)}")

    for key, value in subtables.items():
        if lines and lines[-1] != "":
            lines.append("")
        next_prefix = [*prefix, key]
        lines.append(f"[{'.'.join(_quote_key(part) for part in next_prefix)}]")
        _write_table(lines, next_prefix, value)


def _format_value(value: Any) -> str:
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, Path):
        return json.dumps(str(value))
    if isinstance(value, list | tuple):
        return "[" + ", ".join(_format_value(item) for item in value) + "]"
    if isinstance(value, dict):
        pairs = ", ".join(
            f"{_quote_key(key)} = {_format_value(item)}" for key, item in value.items()
        )
        return "{ " + pairs + " }"
    raise TypeError(f"unsupported TOML value: {value!r}")


def _quote_key(key: str) -> str:
    if key.replace("_", "").replace("-", "").isalnum() and key[0].isalpha():
        return key
    return json.dumps(key)
