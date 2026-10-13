"""Apply portable tool manifests to environments.

A manifest owns its named contributions. Applying it records the manifest on
the environment and lowers its contributions. Reapplying a tool replaces its
earlier version and that version's rule set and instruction set in their place,
whatever the new ones are named, and drops them when the new version has none,
so reapplication is idempotent and render order stays stable. A tool may not
claim a rule set or instruction set the environment or another tool owns,
unless it is the identical set, so a manifest cannot silently drop someone
else's policy. Environments choose their tools; manifests never name
environments.

A manifest names the variables its tool needs; each environment that applies
it supplies their values, and check_tool_vars proves none is missing.
"""

from __future__ import annotations

from collections.abc import Callable, Hashable
from dataclasses import replace
from typing import Any, TypeVar

from harness_factory.models import Environment
from harness_manifest import ToolInstall, ToolManifest

T = TypeVar("T")


def apply_tools(environment: Environment, *tools: ToolManifest) -> Environment:
    """Lower tool manifests into an environment; conflicting tools fail first."""
    for kind, key in (
        ("tool", lambda tool: (tool.name,)),
        ("rule set", lambda tool: (tool.rules.name,) if tool.rules else ()),
        (
            "instruction set",
            lambda tool: (tool.instructions.name,) if tool.instructions else (),
        ),
    ):
        names = [name for tool in tools for name in key(tool)]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise ValueError(f"tools declare the same {kind}: {duplicates}")
    previous = {tool.name: tool for tool in environment.tools}
    _check_ownership(
        environment, tools, "rule set", _rules, environment.rules, previous
    )
    _check_ownership(
        environment,
        tools,
        "instruction set",
        _instructions,
        environment.instruction_sets,
        previous,
    )

    sandbox = environment.sandbox
    sandbox = replace(
        sandbox,
        writable_roots=tuple(
            dict.fromkeys(
                sandbox.writable_roots
                + tuple(root for tool in tools for root in tool.writable_roots)
            )
        ),
        network_allowed_domains=tuple(
            dict.fromkeys(
                sandbox.network_allowed_domains
                + tuple(domain for tool in tools for domain in tool.network_domains)
            )
        ),
    )
    return replace(
        environment,
        tools=_upsert(environment.tools, tools, lambda tool: tool.name),
        sandbox=sandbox,
        rules=_lower(environment.rules, tools, previous, _rules),
        instruction_sets=_lower(
            environment.instruction_sets, tools, previous, _instructions
        ),
    )


def tool_owners(
    environment: Environment, contribution: Callable[[ToolManifest], Any]
) -> dict[str, str]:
    """Map each contributed set name to the name of the tool that owns it."""
    return {
        contributed.name: tool.name
        for tool in environment.tools
        if (contributed := contribution(tool)) is not None
    }


def _rules(tool: ToolManifest) -> Any:
    return tool.rules


def _instructions(tool: ToolManifest) -> Any:
    return tool.instructions


def _check_ownership(
    environment: Environment,
    tools: tuple[ToolManifest, ...],
    kind: str,
    contribution: Callable[[ToolManifest], Any],
    present: tuple[Any, ...],
    previous: dict[str, ToolManifest],
) -> None:
    owners = tool_owners(environment, contribution)
    present_by_name = {item.name: item for item in present}
    for tool in tools:
        contributed = contribution(tool)
        if contributed is None or contributed.name not in present_by_name:
            continue
        owner = owners.get(contributed.name)
        if owner == tool.name:
            continue
        if owner is None and present_by_name[contributed.name] == contributed:
            continue
        raise ValueError(
            f"tool {tool.name!r} cannot replace {kind} {contributed.name!r} "
            f"owned by {'the environment' if owner is None else repr(owner)}"
        )


def _lower(
    existing: tuple[T, ...],
    tools: tuple[ToolManifest, ...],
    previous: dict[str, ToolManifest],
    contribution: Callable[[ToolManifest], Any],
) -> tuple[T, ...]:
    """Put each tool's contribution where its earlier version's was, or append it."""
    slots: dict[str, Any] = {}
    for tool in tools:
        new = contribution(tool)
        old = contribution(previous[tool.name]) if tool.name in previous else None
        if old is not None or new is not None:
            slots[(old or new).name] = new
    lowered = []
    for item in existing:
        if item.name in slots:
            if (new := slots.pop(item.name)) is not None:
                lowered.append(new)
        else:
            lowered.append(item)
    return (*lowered, *(new for new in slots.values() if new is not None))


def check_tool_vars(environment: Environment) -> None:
    """Fail unless the environment defines every required variable (``vars``).

    Run it on final environments: a shared base may apply a tool whose values
    each derived environment supplies. Undefined ``optional_vars`` are left
    out; this check never adds variables or resolves their values.
    """
    defined = {env_var.name for env_var in environment.env_vars}
    missing = [
        f"{tool.name}: {', '.join(names)}"
        for tool in environment.tools
        if (names := [name for name in tool.vars if name not in defined])
    ]
    if missing:
        raise ValueError(
            f"environment {environment.name!r} must define its tools' vars "
            f"({'; '.join(missing)})"
        )


def collect_installs(*environments: Environment) -> tuple[ToolInstall, ...]:
    """Return every install the environments select, sorted by manager and name.

    Machines may run any environment, so bootstrap installs the union. One
    package declared differently by two tools fails instead of picking one.
    """
    installs: dict[tuple[str, str], ToolInstall] = {}
    for environment in environments:
        for tool in environment.tools:
            for install in tool.installs:
                key = (install.manager, install.name)
                if installs.setdefault(key, install) != install:
                    raise ValueError(
                        f"conflicting {install.manager} installs for {install.name!r}"
                    )
    return tuple(installs[key] for key in sorted(installs))


def _upsert(
    existing: tuple[T, ...], new: tuple[T, ...], key: Callable[[T], Hashable]
) -> tuple[T, ...]:
    by_key = {key(item): item for item in new}
    replaced = tuple(by_key.pop(key(item), item) for item in existing)
    return replaced + tuple(by_key.values())
