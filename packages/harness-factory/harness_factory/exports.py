"""Complete applied tool manifests from their installed CLIs' exports.

Prefer a CLI's versioned ``manifest`` export, combined with the application's
local manifest. Legacy ``lockdown`` and ``instructions`` exports replace the
local fallbacks. Optional CLIs that are not installed keep those fallbacks.

An exported policy may deny anything, but its allow and ask rules and its
sandbox exclusions must start with one of the export's own commands, so a CLI
cannot widen access to other tools.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from harness_factory.models import Environment
from harness_factory.tools import apply_tools
from harness_manifest import (
    Choice,
    HarnessScopedValue,
    InstructionSet,
    RuleSet,
    ToolManifest,
    WritableRoot,
    block,
    from_json,
    has_relative_root,
    instructions,
    resolve_manifest,
)
from harness_manifest.command_policy import parse_command_policy
from harness_secrets.process import (
    ExecutableUnavailable,
    OutputLimitExceeded,
    ProcessTimeout,
    child_environment,
    run,
    trusted_executable,
)


class ExportError(RuntimeError):
    """An installed CLI cannot provide a supported harness integration."""


@dataclass(frozen=True)
class Export:
    """How to read and check one CLI's exports.

    ``commands`` are the command names the exported policy may allow or
    exclude from the sandbox; an export without them provides only
    instructions. ``body`` validates and returns the instruction text, and
    ``check_policy`` adds CLI-specific policy checks.
    """

    executable: str
    title: str
    required: bool
    body: Callable[[str], str]
    commands: tuple[str, ...] = ()
    check_policy: Callable[[RuleSet], None] | None = None
    instruction_set: str | None = None
    harnesses: tuple[str, ...] = ("codex", "claude")


@dataclass(frozen=True)
class ManifestExport:
    """Read ``executable manifest`` and combine it with an applied local tool.

    ``commands`` is the application's trust boundary for exported allow/ask
    rules and sandbox exclusions. It is independent of either manifest's name
    or installs. Roots and domains default to the exported values; a tuple
    replaces those values (including an empty tuple to drop them). Local roots
    and domains are always appended. ``check_policy`` checks only CLI policy,
    before combining it with the local rule set.
    """

    executable: str
    commands: tuple[str, ...]
    required: bool = True
    writable_roots: tuple[WritableRoot, ...] | None = None
    network_domains: tuple[str, ...] | None = None
    check_policy: Callable[[RuleSet], None] | None = None


def bullets(output: str) -> str:
    """Accept instructions that are a nonempty Markdown bullet list."""
    body = output.strip()
    if not body or any(not line.startswith("- ") for line in body.splitlines()):
        raise ValueError("instructions must be a nonempty Markdown bullet list")
    return body


def apply_exports(
    environment: Environment,
    exports: Mapping[str, Export | ManifestExport],
    *,
    bin_dir: Path,
    home: Path | None = None,
    variables: Mapping[str, str | HarnessScopedValue] = {},
) -> Environment:
    """Import the exports of every applied tool, keyed by tool name in ``exports``.

    Exports apply in mapping order, which is the render order of new instruction
    sets. Missing or untrusted required CLIs fail and name the CLI; optional
    ones keep their fallbacks. Portable roots use ``home`` and ``variables``;
    no host values or secret sources are read. Call this before secret
    resolution and rendering; the entire batch is validated before applying it.
    Start each render from the application's local tools, not the result of a
    previous import, so removed CLI contributions do not become local entries.
    """
    applied = {tool.name: tool for tool in environment.tools}
    completed = []
    for name, export in exports.items():
        if name not in applied:
            continue
        executable_path = trusted_executable((bin_dir / export.executable,))
        if executable_path is None:
            if not export.required:
                continue
            command = (
                "manifest" if isinstance(export, ManifestExport) else "integration"
            )
            raise ExportError(
                f"Cannot read {export.executable} {command}; required CLI is missing or untrusted."
            )
        executable = Path(executable_path)
        rules = applied[name].rules
        try:
            if isinstance(export, ManifestExport):
                manifest = from_json(_run(executable, "manifest"))
                if manifest.rules is not None:
                    _check_bounds(manifest.rules, export.commands)
                    if export.check_policy is not None:
                        export.check_policy(manifest.rules)
                completed.append(
                    _combine_manifest(applied[name], manifest, export, home, variables)
                )
                continue
            if export.commands:
                rules = parse_command_policy(_run(executable, "lockdown"), name=name)
                _check_bounds(rules, export.commands)
                if export.check_policy is not None:
                    export.check_policy(rules)
            body = export.body(_run(executable, "instructions"))
        except ValueError as error:
            raise ExportError(
                f"Invalid {export.executable} integration: {error}"
            ) from error
        completed.append(
            replace(
                applied[name],
                rules=rules,
                instructions=instructions(
                    export.instruction_set or name,
                    block(export.title, body),
                    harnesses=export.harnesses,
                ),
            )
        )
    return apply_tools(environment, *completed)


def _combine_manifest(
    local: ToolManifest,
    imported: ToolManifest,
    export: ManifestExport,
    home: Path | None,
    variables: Mapping[str, str | HarnessScopedValue],
) -> ToolManifest:
    required = tuple(dict.fromkeys(imported.vars + local.vars))
    optional = tuple(
        name
        for name in dict.fromkeys(imported.optional_vars + local.optional_vars)
        if name not in required
    )
    roots = (
        imported.writable_roots
        if export.writable_roots is None
        else export.writable_roots
    )
    domains = (
        imported.network_domains
        if export.network_domains is None
        else export.network_domains
    )
    manifest = replace(
        local,
        vars=required,
        optional_vars=optional,
        writable_roots=tuple(dict.fromkeys(roots + local.writable_roots)),
        network_domains=tuple(dict.fromkeys(domains + local.network_domains)),
        rules=_combine_rules(imported.rules, local.rules),
        instructions=_combine_instructions(imported.instructions, local.instructions),
        skills=imported.skills + local.skills,
    )
    if has_relative_root(manifest.writable_roots):
        if home is None:
            raise ValueError("manifest import with portable roots requires home")
        manifest = _resolve_roots(manifest, home=home, variables=variables)
        manifest = replace(
            manifest, writable_roots=tuple(dict.fromkeys(manifest.writable_roots))
        )
    return manifest


def _resolve_roots(
    manifest: ToolManifest,
    *,
    home: Path,
    variables: Mapping[str, str | HarnessScopedValue],
) -> ToolManifest:
    if not any(isinstance(value, HarnessScopedValue) for value in variables.values()):
        return resolve_manifest(manifest, home=home, variables=variables)
    values = {
        harness: {
            name: resolved
            for name, value in variables.items()
            if (
                resolved := value.resolve(harness)
                if isinstance(value, HarnessScopedValue)
                else value
            )
            is not None
        }
        for harness in ("codex", "claude")
    }
    roots: list[WritableRoot] = []
    for root in manifest.writable_roots:
        paths: dict[str, Path] = {}
        for harness in ("codex", "claude"):
            path = root if isinstance(root, Path) else root.resolve(harness)
            if path is None:
                continue
            try:
                resolved = resolve_manifest(
                    replace(manifest, writable_roots=(path,)),
                    home=home,
                    variables=values[harness],
                )
            except ValueError as error:
                raise ValueError(f"{harness}: {error}") from error
            if resolved.writable_roots:
                paths[harness] = resolved.writable_roots[0]
        if not paths:
            continue
        if isinstance(root, Path) and paths.get("codex") == paths.get("claude"):
            roots.append(paths["codex"])
        else:
            roots.append(HarnessScopedValue(**paths))
    return replace(manifest, writable_roots=tuple(roots))


def _combine_rules(imported: RuleSet | None, local: RuleSet | None) -> RuleSet | None:
    if imported is None or local is None:
        return local if imported is None else imported
    reasons = tuple(
        dict.fromkeys(
            reason
            for reason in (
                imported.sandbox_exclusion_reason,
                local.sandbox_exclusion_reason,
            )
            if reason
        )
    )
    if len(reasons) > 1:
        sentences = []
        for reason in reasons:
            sentence = reason.strip()
            if not sentence.endswith((".", "!", "?")):
                sentence += "."
            sentences.append(sentence)
        reasons = tuple(dict.fromkeys(sentences))
    return replace(
        local,
        rules=tuple(dict.fromkeys(imported.rules + local.rules)),
        tags=tuple(dict.fromkeys(imported.tags + local.tags)),
        sandbox_excluded_commands=tuple(
            dict.fromkeys(
                imported.sandbox_excluded_commands + local.sandbox_excluded_commands
            )
        ),
        sandbox_exclusion_reason=" ".join(reasons) or None,
    )


def _combine_instructions(
    imported: InstructionSet | None, local: InstructionSet | None
) -> InstructionSet | None:
    if imported is None or local is None:
        return local if imported is None else imported
    if set(imported.harnesses) != set(local.harnesses):
        raise ValueError("combined instruction sets must target the same harnesses")
    return replace(local, blocks=tuple(dict.fromkeys(imported.blocks + local.blocks)))


def _check_bounds(policy: RuleSet, commands: tuple[str, ...]) -> None:
    if any(
        rule.effect != "deny"
        and any(
            command not in commands
            for command in (
                rule.target.parts[0].values
                if isinstance(rule.target.parts[0], Choice)
                else (rule.target.parts[0],)
            )
        )
        for rule in policy.rules
    ):
        raise ValueError(f"only {list(commands)} commands may be allowed")
    if any(
        command.split(" ", 1)[0] not in commands
        for command in policy.sandbox_excluded_commands
    ):
        raise ValueError(f"only {list(commands)} commands may bypass the sandbox")


def _run(executable: Path, command: str) -> str:
    try:
        result = run(
            [str(executable), command], environment=child_environment(), timeout=15
        )
    except (ExecutableUnavailable, ProcessTimeout, OutputLimitExceeded):
        raise ExportError(
            f"Cannot read {executable.name} {command}; restore the managed tool "
            "before rendering."
        ) from None
    if result.returncode != 0:
        raise ExportError(
            f"Cannot read {executable.name} {command}; restore the managed tool "
            "before rendering."
        )
    return result.stdout
