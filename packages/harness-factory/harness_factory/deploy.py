"""Reusable deployment of rendered harness homes."""

from __future__ import annotations

from pathlib import Path

from harness_factory.managed_files import (
    ManagedFilesManifestError,
    load_managed_files_manifest,
)
from harness_factory.models import Environment, HarnessName, retired_agent_files
from harness_factory.tree_diff import sync_tree

CODEX_RUNTIME_PATHS = (Path("computer-use"),)


class RenderedHomeMissingError(FileNotFoundError):
    """Raised when a requested rendered harness home does not exist."""


class RenderedHomeManifestError(RenderedHomeMissingError):
    """Raised when a rendered harness home lacks a valid ownership manifest."""


def deploy_rendered_home(
    environment: Environment,
    harness: HarnessName,
    rendered_output_dir: Path,
    target_home: Path,
    *,
    excluded_paths: tuple[Path, ...] = (),
) -> int:
    """Overlay one rendered harness home without deleting unmanaged files."""

    expected_home = rendered_output_dir / harness / environment.name
    if not expected_home.is_dir():
        raise RenderedHomeMissingError(
            f"Rendered harness home is missing: {expected_home}"
        )
    try:
        managed_files = load_managed_files_manifest(expected_home)
    except ManagedFilesManifestError as error:
        raise RenderedHomeManifestError(str(error)) from error

    config_name = "config.toml" if harness == "codex" else "settings.json"
    config_redactions = (
        {Path(config_name): (("shell_environment_policy", "set", "*"),)}
        if harness == "codex"
        else {Path(config_name): (("env", "*"),)}
    )
    private_modes = (
        {Path("."): 0o700, Path(config_name): 0o600}
        if environment.has_secret_sources
        else {}
    )
    diffs = sync_tree(
        target_home,
        expected_home,
        excluded_path_prefixes=(
            (CODEX_RUNTIME_PATHS if harness == "codex" else ()) + excluded_paths
        ),
        config_key_removals=_retired_config_keys(environment, harness),
        config_key_redactions=config_redactions,
        managed_modes=private_modes,
        included_paths=managed_files,
        retired_paths=retired_agent_files(environment, harness),
    )
    return len({diff.path for diff in diffs})


def _retired_config_keys(
    environment: Environment, harness: HarnessName
) -> dict[Path, tuple[tuple[str, ...], ...]]:
    if harness == "codex":
        removals = (
            tuple(("mcp_servers", name) for name in environment.retired_mcp_servers)
            + tuple(
                ("shell_environment_policy", "set", name)
                for name in environment.retired_env_vars
            )
            + tuple(("agents", name) for name in environment.retired_agents)
        )
        if environment.retired_notification:
            removals += (("notify",), ("tui", "notifications"))
        retired: dict[Path, tuple[tuple[str, ...], ...]] = {}
        if removals:
            retired[Path("config.toml")] = removals
        if environment.retired_mcp_servers:
            agent_removals = tuple(
                ("mcp_servers", name) for name in environment.retired_mcp_servers
            )
            for agent in environment.agents:
                agent_path = agent.config_file or Path("agents") / f"{agent.name}.toml"
                retired[agent_path] = agent_removals
        return retired

    removals: dict[Path, tuple[tuple[str, ...], ...]] = {}
    if environment.retired_mcp_servers:
        removals[Path(".mcp.json")] = tuple(
            ("mcpServers", name) for name in environment.retired_mcp_servers
        )
    settings_removals = tuple(("env", name) for name in environment.retired_env_vars)
    if environment.retired_notification:
        settings_removals += (("hooks", "Notification"),)
    if settings_removals:
        removals[Path("settings.json")] = settings_removals
    return removals
