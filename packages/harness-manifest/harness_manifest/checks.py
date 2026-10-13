"""Field checks shared by the manifest dataclasses and the lockdown parser.

The dataclasses validate themselves, so manifests built in Python and parsed
from JSON or TOML are held to the same contract.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

# Shell metacharacters would turn a literal command part into a pattern or a
# second command in some harnesses' permission syntax.
UNSAFE_PART_CHARACTERS = "*?[];|&<>`$\\\"'"


def command_part(value: Any, field: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or any(character.isspace() for character in value)
        or any(character in value for character in UNSAFE_PART_CHARACTERS)
    ):
        raise ValueError(
            f"{field} parts must be nonempty strings without whitespace or "
            f"shell metacharacters, got {value!r}"
        )


def command_pattern(value: Any, field: str) -> None:
    """Accept literal command parts separated by spaces, optionally ending in ``*``."""
    parts = value.split(" ") if isinstance(value, str) else [None]
    if parts[-1] == "*":
        parts.pop()
    if not parts:
        raise ValueError(f"{field} must start with a literal command, got {value!r}")
    for part in parts:
        command_part(part, field)


def line(value: Any, field: str) -> None:
    """Accept a nonempty single-line string, which renders inside one bullet."""
    string(value, field)
    if "\n" in value or "\r" in value:
        raise ValueError(f"{field} must be a single line, got {value!r}")


def identifiers(value: Any, field: str) -> None:
    strings(value, field)
    for item in value:
        if not item.isidentifier():
            raise ValueError(f"{field} must be identifiers, got {item!r}")


def domains(value: Any, field: str) -> None:
    """Accept host names, optionally behind a ``*.`` subdomain wildcard."""
    strings(value, field)
    for item in value:
        host = item.removeprefix("*.")
        if (
            not host
            or "*" in host
            or any(character.isspace() or character in "/:@" for character in host)
        ):
            raise ValueError(f"{field} must be host names, got {item!r}")


def string(value: Any, field: str, *, empty: bool = False) -> None:
    if not isinstance(value, str) or (not empty and not value):
        raise ValueError(f"{field} must be a nonempty string, got {value!r}")


def optional_string(value: Any, field: str) -> None:
    if value is not None:
        string(value, field, empty=True)


def strings(value: Any, field: str) -> None:
    if not isinstance(value, tuple) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be a tuple of strings, got {value!r}")


def boolean(value: Any, field: str) -> None:
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a boolean, got {value!r}")


def one_of(value: Any, options: Iterable[str], field: str) -> None:
    options = tuple(options)
    if value not in options:
        raise ValueError(f"{field} must be one of {list(options)}, got {value!r}")


def instances(value: Any, kinds: type | tuple[type, ...], field: str) -> None:
    if not isinstance(value, tuple) or not all(
        isinstance(item, kinds) for item in value
    ):
        raise ValueError(f"{field} must be a tuple of {_names(kinds)}, got {value!r}")


def optional_instance(value: Any, kind: type, field: str) -> None:
    if value is not None and not isinstance(value, kind):
        raise ValueError(f"{field} must be a {kind.__name__}, got {value!r}")


def _names(kinds: type | tuple[type, ...]) -> str:
    kinds = kinds if isinstance(kinds, tuple) else (kinds,)
    return " or ".join(kind.__name__ for kind in kinds)
