"""Portable configuration model for agent harnesses.

The dataclasses in this module describe intent. Harness-specific adapters lower
that intent into config files for Codex, Claude, or future tools.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, get_args

from harness_secrets import SecretValue
from harness_manifest import (
    HarnessName,
    HarnessScopedValue,
    InstructionSet,
    RuleSet,
    Skill,
    WritableRoot,
    has_relative_root,
)

if TYPE_CHECKING:
    from harness_manifest import ToolManifest

ApprovalPolicy = Literal["never", "on-failure", "on-request"]
EnvSource = Literal["literal", "host", "1password", "keychain", "file"]
ReasoningTier = Literal["best", "balanced", "cheapest"]
SandboxMode = Literal["workspace-write"]
ToolApprovalMode = Literal["ask", "approve", "deny"]
ToolServerKind = Literal["stdio", "http"]
WebSearchMode = Literal["disabled", "cached", "live"]


@dataclass(frozen=True)
class SandboxPolicy:
    """Portable sandbox intent shared by harness adapters."""

    mode: SandboxMode = "workspace-write"
    allow_tmp: bool = True
    writable_roots: tuple[WritableRoot, ...] = ()
    network: bool = False
    network_allowed_domains: tuple[str, ...] = ()
    network_allowed_mach_lookups: tuple[str, ...] = ()
    network_allowed_unix_sockets: tuple[Path, ...] = ()

    def __post_init__(self) -> None:
        if self.mode != "workspace-write":
            raise ValueError("SandboxPolicy only supports workspace-write mode")
        if has_relative_root(self.writable_roots):
            raise ValueError("SandboxPolicy writable roots must be absolute paths")
        if any(
            not socket.is_absolute() for socket in self.network_allowed_unix_sockets
        ):
            raise ValueError("SandboxPolicy Unix sockets must be absolute paths")

    def writable_roots_for(self, harness: HarnessName) -> tuple[Path, ...]:
        """Resolve harness-scoped roots, dropping those for other harnesses."""
        resolved = (
            root if isinstance(root, Path) else root.resolve(harness)
            for root in self.writable_roots
        )
        return tuple(root for root in resolved if root is not None)


@dataclass(frozen=True)
class EnvVar:
    """Environment variable intent.

    Values are rendered directly by default. Other sources describe expected
    runtime inputs and should avoid committing secret values. A harness-scoped
    source may only choose between ``literal`` and ``host``, so one entry can
    pass a host value through in one harness and set it in another.
    """

    name: str
    value: str | SecretValue | HarnessScopedValue | None = None
    source: EnvSource | HarnessScopedValue = "literal"
    required: bool = True

    def __post_init__(self) -> None:
        if isinstance(self.source, HarnessScopedValue):
            for harness in ("codex", "claude"):
                source = self.source.resolve(harness)
                if source not in (None, "literal", "host"):
                    raise ValueError(
                        f"env var {self.name!r} may only scope literal or host sources"
                    )
                if source == "literal" and (
                    _resolve_value(self.value, harness) is None
                ):
                    raise ValueError(
                        f"literal env var {self.name!r} requires a {harness} value"
                    )
        elif self.source not in get_args(EnvSource):
            raise ValueError(
                f"env var {self.name!r} source must be one of "
                f"{list(get_args(EnvSource))}, got {self.source!r}"
            )
        elif self.source == "literal" and self.value is None:
            raise ValueError(f"literal env var {self.name!r} requires a value")
        if self.source == "1password":
            if self.value is None and self.required:
                raise ValueError(
                    f"required 1Password env var {self.name!r} requires a config location"
                )
            if self.value is not None and not isinstance(
                self.value, (str, SecretValue)
            ):
                raise ValueError(
                    f"1Password env var {self.name!r} requires a string config location"
                )

    def __repr__(self) -> str:
        value = "<redacted>" if self.source == "1password" else self.value
        return (
            f"EnvVar(name={self.name!r}, value={value!r}, source={self.source!r}, "
            f"required={self.required!r})"
        )

    def source_for(self, harness: HarnessName) -> EnvSource | None:
        """Return this harness's source, or None when the variable skips it."""
        if isinstance(self.source, HarnessScopedValue):
            return self.source.resolve(harness)
        return self.source

    @property
    def is_secret_source(self) -> bool:
        """Return whether this source may materialize a secret into a config file."""

        return self.source in ("1password", "keychain", "file")


def _resolve_value(value: Any, harness: HarnessName) -> Any:
    return value.resolve(harness) if isinstance(value, HarnessScopedValue) else value


@dataclass(frozen=True)
class ToolApproval:
    """Portable per-tool approval policy for MCP servers."""

    tool: str
    mode: ToolApprovalMode = "ask"
    reason: str | None = None

    def __post_init__(self) -> None:
        if not self.tool:
            raise ValueError("ToolApproval requires a tool name")


def approve_tool(tool: str, *, reason: str | None = None) -> ToolApproval:
    return ToolApproval(tool=tool, mode="approve", reason=reason)


def ask_tool(tool: str, *, reason: str | None = None) -> ToolApproval:
    return ToolApproval(tool=tool, mode="ask", reason=reason)


def deny_tool(tool: str, *, reason: str | None = None) -> ToolApproval:
    return ToolApproval(tool=tool, mode="deny", reason=reason)


@dataclass(frozen=True)
class ToolServer:
    """Portable MCP or harness tool-server definition."""

    name: str
    kind: ToolServerKind
    command: str | None = None
    args: tuple[str, ...] = ()
    url: str | None = None
    cwd: Path | None = None
    env: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    env_headers: dict[str, str] = field(default_factory=dict)
    tools: dict[str, Any] = field(default_factory=dict)
    tool_approvals: tuple[ToolApproval, ...] = ()

    def __post_init__(self) -> None:
        if self.kind == "stdio" and not self.command:
            raise ValueError(f"stdio tool server {self.name!r} requires command")
        if self.kind == "http" and not self.url:
            raise ValueError(f"http tool server {self.name!r} requires url")


@dataclass(frozen=True)
class Agent:
    """Portable subagent definition."""

    name: str
    description: str
    developer_instructions: str = ""
    reasoning_tier: ReasoningTier = "balanced"
    sandbox: SandboxPolicy = field(default_factory=SandboxPolicy)
    mcp_servers: tuple[ToolServer, ...] = ()
    notifications: bool = False
    instruction_sets: tuple[InstructionSet, ...] = ()
    config_file: Path | None = None
    tools: tuple[str, ...] = ()
    rules: tuple[RuleSet, ...] = ()
    harness_overrides: dict[HarnessName, dict[str, Any]] = field(default_factory=dict)


@dataclass(frozen=True)
class HomeFile:
    """A static file materialized into a generated harness home."""

    relative_path: Path
    source_path: Path
    executable: bool = False
    harnesses: tuple[HarnessName, ...] = ("codex", "claude")

    def __post_init__(self) -> None:
        if self.relative_path.is_absolute():
            raise ValueError("HomeFile.relative_path must be relative")


@dataclass(frozen=True)
class Notification:
    """Portable notification intent for harnesses that can alert the user."""

    enabled: bool = True
    script: HomeFile = field(default_factory=lambda: _bundled_home_file("notify.sh"))


def _bundled_home_file(relative_path: str, *, executable: bool = True) -> HomeFile:
    return HomeFile(
        relative_path=Path(relative_path),
        source_path=Path(__file__).resolve().parent / "assets" / relative_path,
        executable=executable,
    )


@dataclass(frozen=True)
class TrustedProject:
    """A project path and trust decision."""

    path: Path
    trust_level: Literal["trusted"] = "trusted"


@dataclass(frozen=True)
class TrustedProjectChildren:
    """Trust immediate child repositories under a local root."""

    root: Path
    only_git_repos: bool = True
    devcontainer_mirror: Path | None = None
    trust_level: Literal["trusted"] = "trusted"


TrustedProjectSource = TrustedProject | TrustedProjectChildren


def trust(path: str | Path) -> TrustedProject:
    return TrustedProject(Path(path))


def trust_children(
    root: str | Path,
    *,
    only_git_repos: bool = True,
    devcontainer_mirror: str | Path | None = None,
) -> TrustedProjectChildren:
    return TrustedProjectChildren(
        root=Path(root),
        only_git_repos=only_git_repos,
        devcontainer_mirror=(
            Path(devcontainer_mirror) if devcontainer_mirror is not None else None
        ),
    )


@dataclass(frozen=True)
class Mode:
    """A task/domain layer, such as webdev, rn, ios, hugo, or copywriter."""

    name: str
    context_window_size: int | HarnessScopedValue | None = None
    web_search: WebSearchMode | HarnessScopedValue | None = None
    instruction_sets: tuple[InstructionSet, ...] = ()
    mcp_servers: tuple[ToolServer, ...] = ()
    agents: tuple[Agent, ...] = ()
    rules: tuple[RuleSet, ...] = ()
    trusted_projects: tuple[TrustedProjectSource, ...] = ()
    reasoning_tier: ReasoningTier | None = None
    harness_overrides: dict[HarnessName, dict[str, Any]] = field(default_factory=dict)


@dataclass(frozen=True)
class Environment:
    """An identity/account/state boundary, such as work or personal."""

    name: str
    reasoning_tier: ReasoningTier = "best"
    context_window_size: int | HarnessScopedValue | None = None
    web_search: WebSearchMode | HarnessScopedValue | None = None
    personality: str = "pragmatic"
    approval_policy: ApprovalPolicy = "on-request"
    sandbox: SandboxPolicy = field(default_factory=SandboxPolicy)
    env_vars: tuple[EnvVar, ...] = ()
    trusted_projects: tuple[TrustedProjectSource, ...] = ()
    instruction_sets: tuple[InstructionSet, ...] = ()
    base_mcp_servers: tuple[ToolServer, ...] = ()
    retired_mcp_servers: tuple[str, ...] = ()
    retired_env_vars: tuple[str, ...] = ()
    agents: tuple[Agent, ...] = ()
    rules: tuple[RuleSet, ...] = ()
    notification: Notification | None = None
    retired_notification: bool = False
    home_files: tuple[HomeFile, ...] = ()
    modes: tuple[Mode, ...] = ()
    harness_overrides: dict[HarnessName, dict[str, Any]] = field(default_factory=dict)
    retired_agents: tuple[str, ...] = ()
    # Applied manifests, recorded for install planning; adapters render only
    # what apply_tools lowered into the other fields.
    tools: tuple[ToolManifest, ...] = ()
    skills: tuple[Skill, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.skills, tuple) or not all(
            isinstance(skill, Skill) for skill in self.skills
        ):
            raise ValueError("environment skills must be a tuple of Skill")
        for name in self.retired_agents:
            if (
                not name
                or name in (".", "..")
                or "/" in name
                or "\\" in name
                or "\0" in name
            ):
                raise ValueError("retired agent names must be safe filename stems")
        active = {agent.name for agent in self.agents}
        active.update(agent.name for mode in self.modes for agent in mode.agents)
        if active.intersection(self.retired_agents):
            raise ValueError("an agent cannot be both active and retired")
        # Adapters write one file or key per name, so a repeat would silently
        # drop an entry.
        for kind, items in (
            ("env var", self.env_vars),
            ("MCP server", self.base_mcp_servers),
            ("rule set", self.rules),
            ("instruction set", self.instruction_sets),
            ("tool", self.tools),
            ("skill", self.skills),
        ):
            names = [item.name for item in items]
            repeated = sorted({name for name in names if names.count(name) > 1})
            if repeated:
                raise ValueError(
                    f"environment {self.name!r} repeats {kind} names: {repeated}"
                )

    @property
    def has_secret_sources(self) -> bool:
        """Return whether generated configs for this environment require privacy."""

        return any(env_var.is_secret_source for env_var in self.env_vars)

    def mode_named(self, name: str) -> Mode:
        for mode in self.modes:
            if mode.name == name:
                return mode
        raise KeyError(f"unknown mode {name!r} for environment {self.name!r}")


def retired_agent_files(
    environment: Environment, harness: HarnessName
) -> frozenset[Path]:
    suffix = "toml" if harness == "codex" else "md"
    return frozenset(
        Path("agents") / f"{name}.{suffix}" for name in environment.retired_agents
    )
