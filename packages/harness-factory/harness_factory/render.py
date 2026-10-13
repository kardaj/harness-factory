"""Reusable rendering helpers for portable harness environments."""

from __future__ import annotations

from pathlib import Path

from harness_factory.adapters import ClaudeAdapter, CodexAdapter
from harness_factory.check import CheckResult, check_output_dir
from harness_factory.managed_files import write_managed_files_manifest
from harness_factory.models import Environment, retired_agent_files


class HarnessValidationError(RuntimeError):
    """Raised when one or more generated harness homes fail validation."""

    def __init__(self, results: tuple[CheckResult, ...]):
        self.results = results
        super().__init__("generated harness output failed validation")


def write_harness_homes(
    output_dir: Path,
    *,
    environments: tuple[Environment, ...],
    runtime_output_dir: Path | None = None,
) -> None:
    """Render Codex and Claude homes for every supplied environment."""

    adapters = (CodexAdapter(), ClaudeAdapter())
    for environment in environments:
        for adapter in adapters:
            relative_home = Path(adapter.name) / environment.name
            config_path = adapter.write(
                environment,
                output_dir / relative_home,
                runtime_output_dir=(
                    None
                    if runtime_output_dir is None
                    else runtime_output_dir / relative_home
                ),
            )
            write_managed_files_manifest(output_dir / relative_home)
            # The config is written 0o600 from creation; an existing home keeps
            # its mode until tightened here.
            if environment.has_secret_sources:
                config_path.parent.chmod(0o700)


def validate_harness_output(output_dir: Path) -> None:
    """Validate rendered homes with every available harness CLI."""

    results = check_output_dir(output_dir)
    failed = [result for result in results if not result.ok]
    if failed:
        raise HarnessValidationError(tuple(results))


def retired_config_keys(
    environments: tuple[Environment, ...],
) -> dict[Path, tuple[tuple[str, ...], ...]]:
    """Return retired managed keys to prune from a complete rendered tree."""

    removals: dict[Path, tuple[tuple[str, ...], ...]] = {}
    for environment in environments:
        codex_removals = (
            tuple(("mcp_servers", name) for name in environment.retired_mcp_servers)
            + tuple(
                ("shell_environment_policy", "set", name)
                for name in environment.retired_env_vars
            )
            + tuple(("agents", name) for name in environment.retired_agents)
        )
        claude_mcp_removals = tuple(
            ("mcpServers", name) for name in environment.retired_mcp_servers
        )
        claude_settings_removals = tuple(
            ("env", name) for name in environment.retired_env_vars
        )
        if environment.retired_notification:
            codex_removals += (("notify",), ("tui", "notifications"))
            claude_settings_removals += (("hooks", "Notification"),)
        if codex_removals:
            removals[Path("codex") / environment.name / "config.toml"] = codex_removals
        if environment.retired_mcp_servers:
            retired_agent_mcp = tuple(
                ("mcp_servers", name) for name in environment.retired_mcp_servers
            )
            for agent in environment.agents:
                agent_path = agent.config_file or Path("agents") / f"{agent.name}.toml"
                removals[Path("codex") / environment.name / agent_path] = (
                    retired_agent_mcp
                )
        if claude_mcp_removals:
            removals[Path("claude") / environment.name / ".mcp.json"] = (
                claude_mcp_removals
            )
        if claude_settings_removals:
            removals[Path("claude") / environment.name / "settings.json"] = (
                claude_settings_removals
            )
    return removals


def retired_home_files(environments: tuple[Environment, ...]) -> frozenset[Path]:
    """Return explicitly retired definitions to archive, preserving all other files."""
    return frozenset(
        Path(harness) / environment.name / path
        for environment in environments
        for harness in ("codex", "claude")
        for path in retired_agent_files(environment, harness)
    )


def secret_config_redactions(
    environments: tuple[Environment, ...],
) -> dict[Path, tuple[tuple[str, ...], ...]]:
    """Return wildcard redactions for rendered environment maps."""

    redactions: dict[Path, tuple[tuple[str, ...], ...]] = {}
    for environment in environments:
        redactions[Path("codex") / environment.name / "config.toml"] = (
            ("shell_environment_policy", "set", "*"),
        )
        redactions[Path("claude") / environment.name / "settings.json"] = (
            ("env", "*"),
        )
    return redactions


def secret_managed_modes(
    environments: tuple[Environment, ...],
) -> dict[Path, int]:
    """Return private modes for generated homes containing resolved secrets."""

    modes: dict[Path, int] = {}
    for environment in environments:
        if not environment.has_secret_sources:
            continue
        codex_home = Path("codex") / environment.name
        claude_home = Path("claude") / environment.name
        modes[codex_home] = 0o700
        modes[codex_home / "config.toml"] = 0o600
        modes[claude_home] = 0o700
        modes[claude_home / "settings.json"] = 0o600
    return modes
