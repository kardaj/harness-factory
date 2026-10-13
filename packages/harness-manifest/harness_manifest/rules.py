"""Portable permission policy primitives.

Rules in this module describe policy intent. Harness adapters are responsible
for lowering that intent into Codex rules or Claude permission strings.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from typing import Literal, get_args

from harness_manifest import checks

RuleEffect = Literal["allow", "ask", "deny"]
RuleTool = Literal["shell"]


@dataclass(frozen=True)
class Choice:
    """A set of alternatives for a single command-position match."""

    values: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.values, tuple) or not self.values:
            raise ValueError("Choice requires a tuple of at least one value")
        for value in self.values:
            checks.command_part(value, "command")


RulePart = str | Choice


@dataclass(frozen=True)
class ShellCommand:
    """A shell command prefix pattern."""

    parts: tuple[RulePart, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.parts, tuple) or not self.parts:
            raise ValueError("ShellCommand requires a tuple of at least one part")
        for part in self.parts:
            if not isinstance(part, Choice):
                checks.command_part(part, "command")


@dataclass(frozen=True)
class Rule:
    """A single portable permission rule."""

    effect: RuleEffect
    target: ShellCommand
    justification: str | None = None
    match: tuple[str, ...] = ()
    not_match: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        checks.one_of(self.effect, get_args(RuleEffect), "rule effect")
        if not isinstance(self.target, ShellCommand):
            raise ValueError(f"rule target must be a ShellCommand, got {self.target!r}")
        checks.optional_string(self.justification, "rule justification")
        for field in ("match", "not_match", "tags"):
            checks.strings(getattr(self, field), f"rule {field}")


@dataclass(frozen=True)
class RuleSet:
    """A named, composable group of portable permission rules."""

    name: str
    rules: tuple[Rule, ...]
    description: str | None = None
    tags: tuple[str, ...] = ()
    sandbox_excluded_commands: tuple[str, ...] = ()
    sandbox_exclusion_reason: str | None = None

    def __post_init__(self) -> None:
        checks.string(self.name, "rule set name")
        checks.instances(self.rules, Rule, f"rule set {self.name!r} rules")
        checks.optional_string(self.description, f"rule set {self.name!r} description")
        checks.strings(self.tags, f"rule set {self.name!r} tags")
        checks.strings(
            self.sandbox_excluded_commands,
            f"rule set {self.name!r} sandbox_excluded_commands",
        )
        for command in self.sandbox_excluded_commands:
            checks.command_pattern(
                command, f"rule set {self.name!r} sandbox_excluded_commands"
            )
            if not command.endswith(" *"):
                raise ValueError(
                    f"rule set {self.name!r} sandbox_excluded_commands must end in ' *' "
                    f"after a command prefix, got {command!r}"
                )
        if self.sandbox_exclusion_reason is not None:
            checks.line(
                self.sandbox_exclusion_reason,
                f"rule set {self.name!r} sandbox_exclusion_reason",
            )
        if bool(self.sandbox_excluded_commands) != bool(self.sandbox_exclusion_reason):
            raise ValueError(
                "RuleSet sandbox exclusions require a reason, and a reason requires exclusions"
            )


def choice(*values: str) -> Choice:
    return Choice(tuple(values))


def shell(*parts: RulePart) -> ShellCommand:
    return ShellCommand(tuple(parts))


def allow(target: ShellCommand, **kwargs: object) -> Rule:
    return _rule("allow", target, **kwargs)


def ask(target: ShellCommand, **kwargs: object) -> Rule:
    return _rule("ask", target, **kwargs)


def deny(target: ShellCommand, **kwargs: object) -> Rule:
    return _rule("deny", target, **kwargs)


def expand_shell_command(command: ShellCommand) -> tuple[tuple[str, ...], ...]:
    """Expand command choices into concrete command prefixes."""

    options: list[tuple[str, ...]] = []
    for part in command.parts:
        if isinstance(part, Choice):
            options.append(part.values)
        else:
            options.append((part,))
    return tuple(tuple(parts) for parts in product(*options))


def _rule(effect: RuleEffect, target: ShellCommand, **kwargs: object) -> Rule:
    allowed = {"justification", "match", "not_match", "tags"}
    unknown = set(kwargs) - allowed
    if unknown:
        raise TypeError(f"unknown rule arguments: {sorted(unknown)}")
    return Rule(
        effect=effect,
        target=target,
        justification=_optional_str(kwargs.get("justification")),
        match=_string_tuple(kwargs.get("match")),
        not_match=_string_tuple(kwargs.get("not_match")),
        tags=_string_tuple(kwargs.get("tags")),
    )


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError("expected a string")
    return value


def _string_tuple(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        raise TypeError("expected an iterable of strings, not a string")
    return tuple(value)  # type: ignore[arg-type]
