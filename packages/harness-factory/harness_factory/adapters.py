"""Harness-specific renderers for portable environment definitions."""

from __future__ import annotations

import json
import shlex
from abc import ABC, abstractmethod
from collections.abc import Iterable
from itertools import chain
from pathlib import Path
from typing import Any, Literal

from harness_manifest.instructions import (
    InstructionBlock,
    InstructionFile,
    InstructionSet,
    InstructionSource,
    SandboxExclusions,
)
from harness_factory.models import (
    Agent,
    Environment,
    EnvVar,
    HarnessName,
    HarnessScopedValue,
    HomeFile,
    Mode,
    Notification,
    ReasoningTier,
    SandboxPolicy,
    ToolServer,
    TrustedProject,
    TrustedProjectChildren,
    TrustedProjectSource,
    WebSearchMode,
)
from harness_manifest.rules import Choice, Rule, RulePart, RuleSet, expand_shell_command
from harness_factory.serializers import dump_json, dump_toml
from harness_secrets import SecretValue

CODEX_MODEL_BY_TIER: dict[ReasoningTier, tuple[str, str]] = {
    "best": ("gpt-6-sol", "high"),
    "balanced": ("gpt-5.5", "medium"),
    "cheapest": ("gpt-5.4-mini", "medium"),
}
CLAUDE_MODEL_BY_TIER: dict[ReasoningTier, tuple[str, str]] = {
    "best": ("claude-opus-4-8", "high"),
    "balanced": ("sonnet", "high"),
    "cheapest": ("haiku", "high"),
}

# Codex's core variables across Unix and Windows. Host inputs need `all` plus
# an allowlist because include filters cannot restore variables removed by core.
CODEX_CORE_ENV_VARS = (
    "PATH",
    "SHELL",
    "TMPDIR",
    "TEMP",
    "TMP",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LOGNAME",
    "USER",
    "PATHEXT",
    "COMSPEC",
    "SYSTEMROOT",
    "WINDIR",
    "SYSTEMDRIVE",
    "USERNAME",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMW6432",
    "PROGRAMDATA",
    "LOCALAPPDATA",
    "APPDATA",
    "POWERSHELL",
    "PWSH",
)


class HarnessAdapter(ABC):
    """Base interface for harness adapters."""

    name: Literal["codex", "claude"]

    @abstractmethod
    def render(
        self, environment: Environment, mode: Mode | None = None
    ) -> dict[str, Any]:
        """Return a harness-native config object."""

    @abstractmethod
    def write(
        self,
        environment: Environment,
        output_dir: Path,
        mode: Mode | None = None,
        *,
        runtime_output_dir: Path | None = None,
    ) -> Path:
        """Write rendered config files and return the main config path."""

    @staticmethod
    def _merged_mcp_servers(
        environment: Environment, mode: Mode | None
    ) -> tuple[ToolServer, ...]:
        return environment.base_mcp_servers + (() if mode is None else mode.mcp_servers)

    @staticmethod
    def _merged_agents(
        environment: Environment, mode: Mode | None
    ) -> tuple[Agent, ...]:
        return environment.agents + (() if mode is None else mode.agents)

    @staticmethod
    def _merged_rules(
        environment: Environment, mode: Mode | None
    ) -> tuple[RuleSet, ...]:
        return environment.rules + (() if mode is None else mode.rules)

    def _merged_instruction_sets(
        self, environment: Environment, mode: Mode | None
    ) -> tuple[InstructionSet, ...]:
        instruction_sets = environment.instruction_sets + (
            () if mode is None else mode.instruction_sets
        )
        return tuple(
            instruction_set
            for instruction_set in instruction_sets
            if self.name in instruction_set.harnesses
        )

    @staticmethod
    def _materialized_env(
        env_vars: tuple[EnvVar, ...], harness: HarnessName
    ) -> dict[str, str]:
        rendered: dict[str, str] = {}
        for env_var in env_vars:
            if env_var.source_for(harness) not in ("literal", "1password"):
                continue
            value = _resolve_harness_value(env_var.value, harness)
            if (
                env_var.source == "1password"
                and value is not None
                and not isinstance(value, SecretValue)
            ):
                raise ValueError(
                    f"1Password env var {env_var.name!r} has not been resolved"
                )
            if value is None:
                if env_var.source == "1password" and env_var.required:
                    raise ValueError(
                        f"required 1Password env var {env_var.name!r} is unresolved"
                    )
                continue
            if isinstance(value, SecretValue):
                value = value.reveal()
            if not isinstance(value, str):
                raise TypeError(f"env var {env_var.name} must resolve to a string")
            rendered[env_var.name] = value
        return rendered

    @staticmethod
    def _host_env_names(
        env_vars: tuple[EnvVar, ...], harness: HarnessName
    ) -> list[str]:
        return [
            env_var.name
            for env_var in env_vars
            if env_var.source_for(harness) == "host"
        ]


class CodexAdapter(HarnessAdapter):
    """Render portable definitions into Codex config.toml."""

    name = "codex"

    def render(
        self, environment: Environment, mode: Mode | None = None
    ) -> dict[str, Any]:
        model, model_reasoning_effort = CODEX_MODEL_BY_TIER[
            _reasoning_tier(environment, mode)
        ]

        config: dict[str, Any] = {
            "model": model,
            "personality": environment.personality,
            "approval_policy": environment.approval_policy,
            "sandbox_mode": environment.sandbox.mode,
            "sandbox_workspace_write": self._render_sandbox_workspace_write(
                environment.sandbox
            ),
            "shell_environment_policy": self._render_shell_environment(
                environment.env_vars
            ),
            "mcp_servers": self._render_mcp_servers(
                self._merged_mcp_servers(environment, mode)
            ),
            "agents": self._render_agents(self._merged_agents(environment, mode)),
            "projects": self._render_projects(environment, mode),
        }

        if model_reasoning_effort:
            config["model_reasoning_effort"] = model_reasoning_effort
        context_window_size = _context_window_size(environment, mode, "codex")
        if context_window_size is not None:
            config["model_context_window"] = context_window_size
        web_search = _web_search_mode(environment, mode, "codex")
        if web_search is not None:
            config["web_search"] = web_search
        network_proxy = self._render_network_proxy(environment.sandbox)
        if network_proxy:
            config.setdefault("features", {})["network_proxy"] = network_proxy
        if environment.notification is not None and environment.notification.enabled:
            config["notify"] = self._render_notification(environment.notification)
            config.setdefault("tui", {})["notifications"] = True

        config = _deep_merge(config, environment.harness_overrides.get("codex", {}))
        if mode is not None:
            config = _deep_merge(config, mode.harness_overrides.get("codex", {}))

        return _remove_empty(config)

    def write(
        self,
        environment: Environment,
        output_dir: Path,
        mode: Mode | None = None,
        *,
        runtime_output_dir: Path | None = None,
    ) -> Path:
        # Kept for adapter interface parity; Codex notification paths are
        # runtime-relative.
        _ = runtime_output_dir
        config_path = output_dir / "config.toml"
        dump_toml(self.render(environment, mode), config_path)
        _write_home_files(_home_files(environment), output_dir, self.name)
        self._write_instructions(environment, output_dir, mode)
        self._write_agent_configs(environment, output_dir, mode)
        self._write_rule_sets(environment, output_dir, mode)
        return config_path

    def write_policy_preview(
        self,
        environment: Environment,
        output_dir: Path,
        mode: Mode | None = None,
    ) -> None:
        """Write current Codex instructions and command rules only."""

        output_dir.mkdir(parents=True, exist_ok=True)
        self._write_instructions(environment, output_dir, mode)
        self._write_rule_sets(environment, output_dir, mode)

    @staticmethod
    def _render_sandbox_workspace_write(sandbox: SandboxPolicy) -> dict[str, Any]:
        return {
            "exclude_slash_tmp": not sandbox.allow_tmp,
            "exclude_tmpdir_env_var": not sandbox.allow_tmp,
            "writable_roots": _sorted_unique(
                str(root) for root in sandbox.writable_roots_for("codex")
            ),
            "network_access": sandbox.network or bool(sandbox.network_allowed_domains),
        }

    @staticmethod
    def _render_network_proxy(sandbox: SandboxPolicy) -> dict[str, Any]:
        if not sandbox.network_allowed_domains:
            return {}
        return {
            "enabled": True,
            "domains": dict.fromkeys(
                _sorted_unique(sandbox.network_allowed_domains), "allow"
            ),
        }

    def _render_shell_environment(self, env_vars: tuple[EnvVar, ...]) -> dict[str, Any]:
        rendered: dict[str, Any] = {"inherit": "core"}
        literal_env = self._materialized_env(env_vars, "codex")
        host_env = self._host_env_names(env_vars, "codex")
        if literal_env:
            rendered["set"] = literal_env
        if host_env:
            rendered["inherit"] = "all"
            rendered["include_only"] = _sorted_unique(
                (*CODEX_CORE_ENV_VARS, *host_env, *literal_env)
            )
        return rendered

    @staticmethod
    def _render_mcp_servers(servers: tuple[ToolServer, ...]) -> dict[str, Any]:
        rendered: dict[str, Any] = {}
        for server in servers:
            if server.kind == "stdio":
                value: dict[str, Any] = {
                    "command": server.command,
                    "args": list(server.args),
                }
                if server.cwd:
                    value["cwd"] = str(server.cwd)
                if server.env:
                    value["env"] = server.env
            else:
                value = {"url": server.url}
                if server.headers:
                    value["http_headers"] = server.headers
                if server.env_headers:
                    value["env_http_headers"] = server.env_headers
            tools = _render_tool_config(server)
            if tools:
                value["tools"] = tools
            rendered[server.name] = value
        return rendered

    @staticmethod
    def _render_agents(agents: tuple[Agent, ...]) -> dict[str, Any]:
        rendered: dict[str, Any] = {}
        for agent in agents:
            value: dict[str, Any] = {"description": agent.description}
            value["config_file"] = str(
                agent.config_file or Path("agents") / f"{agent.name}.toml"
            )
            if agent.tools:
                value["tools"] = list(agent.tools)
            rendered[agent.name] = value
        return rendered

    def _write_agent_configs(
        self, environment: Environment, output_dir: Path, mode: Mode | None
    ) -> None:
        for agent in self._merged_agents(environment, mode):
            path = output_dir / (
                agent.config_file or Path("agents") / f"{agent.name}.toml"
            )
            dump_toml(self._render_agent_config(agent), path)

    def _write_instructions(
        self, environment: Environment, output_dir: Path, mode: Mode | None
    ) -> None:
        instruction_sets = self._merged_instruction_sets(environment, mode)
        if instruction_sets:
            path = output_dir / "AGENTS.md"
            path.write_text(
                _render_instruction_file(
                    instruction_sets=instruction_sets,
                    format="codex",
                ),
                encoding="utf-8",
            )

    def _write_rule_sets(
        self, environment: Environment, output_dir: Path, mode: Mode | None
    ) -> None:
        for rule_set in self._merged_rules(environment, mode):
            path = output_dir / "rules" / f"{rule_set.name}.rules"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(self.render_rule_set(rule_set), encoding="utf-8")

    @staticmethod
    def render_rule_set(rule_set: RuleSet) -> str:
        """Lower one portable rule set to native Codex policy text."""
        lines: list[str] = []
        if rule_set.description:
            lines.append(f"# {rule_set.description}")
        lines.extend(_render_codex_rule(rule) for rule in rule_set.rules)
        return "\n\n".join(lines) + "\n"

    def _render_agent_config(self, agent: Agent) -> dict[str, Any]:
        model, model_reasoning_effort = CODEX_MODEL_BY_TIER[agent.reasoning_tier]
        config: dict[str, Any] = {
            "name": agent.name,
            "model": model,
            "model_reasoning_effort": model_reasoning_effort,
            "sandbox_mode": agent.sandbox.mode,
            "tui": {"notifications": agent.notifications},
            "mcp_servers": self._render_mcp_servers(agent.mcp_servers),
            "developer_instructions": agent.developer_instructions,
        }
        return _remove_empty(
            _deep_merge(config, agent.harness_overrides.get("codex", {}))
        )

    @staticmethod
    def _render_projects(environment: Environment, mode: Mode | None) -> dict[str, Any]:
        sources = environment.trusted_projects + (
            () if mode is None else mode.trusted_projects
        )
        return {
            str(project.path): {"trust_level": project.trust_level}
            for project in _expand_trusted_projects(sources)
        }

    @staticmethod
    def _render_notification(notification: Notification) -> list[str]:
        script = notification.script.relative_path.as_posix()
        return ["bash", "-lc", f"${{CODEX_HOME:-$HOME/.codex}}/{script}"]


class ClaudeAdapter(HarnessAdapter):
    """Render portable definitions into Claude Code native files."""

    name = "claude"

    def render(
        self, environment: Environment, mode: Mode | None = None
    ) -> dict[str, Any]:
        model, reasoning_effort = CLAUDE_MODEL_BY_TIER[
            _reasoning_tier(environment, mode)
        ]
        config = {
            "model": model,
            "effortLevel": reasoning_effort,
            "permissions": self._render_permissions(
                self._merged_rules(environment, mode),
                self._merged_mcp_servers(environment, mode),
                web_search=_web_search_mode(environment, mode, "claude"),
            ),
            "env": self._render_env(environment.env_vars),
        }
        context_window_size = _context_window_size(environment, mode, "claude")
        if context_window_size is not None:
            config["autoCompactWindow"] = context_window_size
        sandbox = self._render_sandbox(
            environment.sandbox, self._merged_rules(environment, mode)
        )
        if sandbox:
            config["sandbox"] = sandbox
        config = _deep_merge(config, environment.harness_overrides.get("claude", {}))
        if mode is not None:
            config = _deep_merge(config, mode.harness_overrides.get("claude", {}))
        return _remove_empty(config)

    def _render_factory_config(
        self, environment: Environment, mode: Mode | None = None
    ) -> dict[str, Any]:
        factory_metadata: dict[str, Any] = {}
        trusted_projects = _trusted_project_manifest(environment, mode)
        if trusted_projects:
            factory_metadata["trustedProjects"] = trusted_projects
        if factory_metadata:
            return {"_harnessFactory": factory_metadata}
        return {}

    def _render_mcp_config(
        self, environment: Environment, mode: Mode | None = None
    ) -> dict[str, Any]:
        mcp_servers = self._render_mcp_servers(
            self._merged_mcp_servers(environment, mode)
        )
        if not mcp_servers:
            return {}
        return {"mcpServers": mcp_servers}

    def write(
        self,
        environment: Environment,
        output_dir: Path,
        mode: Mode | None = None,
        *,
        runtime_output_dir: Path | None = None,
    ) -> Path:
        settings_path = output_dir / "settings.json"
        settings = self.render(environment, mode)
        if environment.notification is not None and environment.notification.enabled:
            settings = _deep_merge(
                settings,
                self._render_notification(
                    environment.notification, runtime_output_dir or output_dir
                ),
            )
        dump_json(settings, settings_path)
        factory_config = self._render_factory_config(environment, mode)
        if factory_config:
            dump_json(factory_config, output_dir / "claude.config.json")
        mcp_config = self._render_mcp_config(environment, mode)
        if mcp_config:
            dump_json(mcp_config, output_dir / ".mcp.json")
        _write_home_files(_home_files(environment), output_dir, self.name)
        self._write_instructions(environment, output_dir, mode)
        self._write_agent_configs(environment, output_dir, mode)
        return settings_path

    def write_policy_preview(
        self,
        environment: Environment,
        output_dir: Path,
        mode: Mode | None = None,
    ) -> None:
        """Write current Claude instructions and non-secret execution policy."""

        output_dir.mkdir(parents=True, exist_ok=True)
        settings = {
            "permissions": self._render_permissions(
                self._merged_rules(environment, mode),
                web_search=_web_search_mode(environment, mode, "claude"),
            ),
            "sandbox": self._render_sandbox(
                environment.sandbox, self._merged_rules(environment, mode)
            ),
        }
        dump_json(settings, output_dir / "settings.json")
        self._write_instructions(environment, output_dir, mode)

    @staticmethod
    def _render_permissions(
        rule_sets: tuple[RuleSet, ...] = (),
        mcp_servers: tuple[ToolServer, ...] = (),
        web_search: WebSearchMode | None = None,
    ) -> dict[str, Any]:
        permissions: dict[str, Any] = {"defaultMode": "acceptEdits"}
        rendered_rules = render_claude_rules(rule_sets)
        if rendered_rules:
            _merge_permission_entries(permissions, rendered_rules)
        rendered_tool_approvals = _render_claude_tool_approvals(mcp_servers)
        if rendered_tool_approvals:
            _merge_permission_entries(permissions, rendered_tool_approvals)
        if web_search == "disabled":
            _merge_permission_entries(permissions, {"deny": ["WebSearch"]})
        elif web_search in ("cached", "live"):
            _merge_permission_entries(permissions, {"allow": ["WebSearch"]})
        for effect in ("allow", "ask", "deny"):
            if effect in permissions:
                permissions[effect] = _sorted_unique(permissions[effect])
        return permissions

    @staticmethod
    def _render_sandbox(
        sandbox: SandboxPolicy, rule_sets: tuple[RuleSet, ...] = ()
    ) -> dict[str, Any]:
        rendered: dict[str, Any] = {
            "enabled": True,
            "autoAllowBashIfSandboxed": True,
            "allowUnsandboxedCommands": False,
        }
        allow_write = (["/tmp"] if sandbox.allow_tmp else []) + [
            str(root) for root in sandbox.writable_roots_for("claude")
        ]
        if allow_write:
            rendered["filesystem"] = {"allowWrite": _sorted_unique(allow_write)}
        network: dict[str, Any] = {}
        if sandbox.network_allowed_domains:
            network["allowedDomains"] = _sorted_unique(sandbox.network_allowed_domains)
        if sandbox.network_allowed_mach_lookups:
            network["allowMachLookup"] = _sorted_unique(
                sandbox.network_allowed_mach_lookups
            )
        if sandbox.network_allowed_unix_sockets:
            network["allowUnixSockets"] = _sorted_unique(
                str(socket) for socket in sandbox.network_allowed_unix_sockets
            )
        if network:
            rendered["network"] = network
        excluded_commands = [
            command
            for rule_set in rule_sets
            for command in rule_set.sandbox_excluded_commands
        ]
        if excluded_commands:
            rendered["excludedCommands"] = _sorted_unique(excluded_commands)
        return rendered

    def _render_env(self, env_vars: tuple[EnvVar, ...]) -> dict[str, Any]:
        return self._materialized_env(env_vars, "claude")

    @staticmethod
    def _render_mcp_servers(servers: tuple[ToolServer, ...]) -> dict[str, Any]:
        rendered: dict[str, Any] = {}
        for server in servers:
            if server.kind == "stdio":
                value: dict[str, Any] = {
                    "command": server.command,
                    "args": list(server.args),
                }
                if server.cwd:
                    value["cwd"] = str(server.cwd)
                if server.env:
                    value["env"] = server.env
            else:
                value = {"type": "http", "url": server.url}
                if server.headers:
                    value["headers"] = server.headers
                if server.env_headers:
                    value["envHeaders"] = server.env_headers
            if server.tools:
                value["tools"] = server.tools
            rendered[server.name] = value
        return rendered

    @staticmethod
    def _render_notification(
        notification: Notification, output_dir: Path
    ) -> dict[str, Any]:
        script_path = (output_dir / notification.script.relative_path).resolve()
        return {
            "hooks": {
                "Notification": [
                    {
                        "matcher": "",
                        "hooks": [
                            {
                                "type": "command",
                                "command": f"bash {shlex.quote(str(script_path))}",
                            }
                        ],
                    }
                ]
            }
        }

    def _write_agent_configs(
        self, environment: Environment, output_dir: Path, mode: Mode | None
    ) -> None:
        for agent in self._merged_agents(environment, mode):
            path = output_dir / "agents" / f"{agent.name}.md"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(self._render_agent_config(agent), encoding="utf-8")

    def _write_instructions(
        self, environment: Environment, output_dir: Path, mode: Mode | None
    ) -> None:
        instruction_sets = self._merged_instruction_sets(environment, mode)
        if instruction_sets:
            path = output_dir / "CLAUDE.md"
            path.write_text(
                _render_instruction_file(
                    instruction_sets=instruction_sets,
                    format="claude",
                    sandbox_exclusions=_claude_sandbox_exclusion_block(
                        self._merged_rules(environment, mode)
                    ),
                ),
                encoding="utf-8",
            )

    def _render_agent_config(self, agent: Agent) -> str:
        model, reasoning_effort = CLAUDE_MODEL_BY_TIER[agent.reasoning_tier]
        frontmatter: dict[str, Any] = {
            "name": agent.name,
            "description": agent.description,
            "model": model,
            "effort": reasoning_effort,
        }
        if agent.tools:
            frontmatter["tools"] = list(agent.tools)
        frontmatter = _deep_merge(
            frontmatter, agent.harness_overrides.get("claude", {})
        )
        lines = ["---"]
        for key, value in frontmatter.items():
            lines.extend(_render_yaml_field(key, value))
        lines.append("---")
        lines.append("")
        lines.append(agent.developer_instructions.strip())
        lines.append("")
        return "\n".join(lines)


def _remove_empty(value: dict[str, Any]) -> dict[str, Any]:
    cleaned: dict[str, Any] = {}
    for key, item in value.items():
        if item is None:
            continue
        if isinstance(item, dict):
            nested = _remove_empty(item)
            if nested:
                cleaned[key] = nested
            continue
        if item == []:
            continue
        cleaned[key] = item
    return cleaned


def _write_home_files(
    home_files: tuple[HomeFile, ...], output_dir: Path, harness: HarnessName
) -> None:
    for home_file in home_files:
        if harness not in home_file.harnesses:
            continue
        destination = output_dir / home_file.relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(home_file.source_path.read_bytes())
        if home_file.executable:
            destination.chmod(destination.stat().st_mode | 0o111)


def _home_files(environment: Environment) -> tuple[HomeFile, ...]:
    files = list(environment.home_files)
    if environment.notification is not None:
        files.append(environment.notification.script)
    return tuple(files)


def _render_yaml_field(key: str, value: Any) -> list[str]:
    if key in ("tools", "disallowedTools", "skills") and isinstance(
        value, (list, tuple)
    ):
        return [f"{key}: {', '.join(str(item) for item in value)}"]
    if isinstance(value, dict):
        return [f"{key}: {json.dumps(value, sort_keys=True)}"]
    if isinstance(value, (list, tuple)):
        return [f"{key}: {json.dumps(list(value))}"]
    if isinstance(value, bool):
        return [f"{key}: {'true' if value else 'false'}"]
    if value is None:
        return [f"{key}: null"]
    if isinstance(value, (int, float)):
        return [f"{key}: {value}"]
    return [f"{key}: {json.dumps(str(value))}"]


def _reasoning_tier(environment: Environment, mode: Mode | None) -> ReasoningTier:
    if mode is not None and mode.reasoning_tier is not None:
        return mode.reasoning_tier
    return environment.reasoning_tier


def _context_window_size(
    environment: Environment, mode: Mode | None, harness: HarnessName
) -> int | None:
    value = (
        mode.context_window_size
        if mode is not None and mode.context_window_size is not None
        else environment.context_window_size
    )
    resolved = _resolve_harness_value(value, harness)
    if resolved is None:
        return None
    if not isinstance(resolved, int):
        raise TypeError("context_window_size must resolve to an integer")
    return resolved


def _web_search_mode(
    environment: Environment, mode: Mode | None, harness: HarnessName
) -> WebSearchMode | None:
    value = (
        mode.web_search
        if mode is not None and mode.web_search is not None
        else environment.web_search
    )
    resolved = _resolve_harness_value(value, harness)
    if resolved is None:
        return None
    if resolved not in ("disabled", "cached", "live"):
        raise ValueError("web_search must be one of: disabled, cached, live")
    return resolved


def _resolve_harness_value(value: Any, harness: HarnessName) -> Any:
    if isinstance(value, HarnessScopedValue):
        return value.resolve(harness)
    return value


def _expand_trusted_projects(
    sources: tuple[TrustedProjectSource, ...],
) -> tuple[TrustedProject, ...]:
    projects: dict[Path, TrustedProject] = {}
    for source in sources:
        for project in _expand_trusted_project_source(source):
            projects[project.path] = project
    return tuple(projects[path] for path in sorted(projects))


def _trusted_project_sources(
    environment: Environment, mode: Mode | None
) -> tuple[TrustedProjectSource, ...]:
    return environment.trusted_projects + (
        () if mode is None else mode.trusted_projects
    )


def _trusted_project_manifest(
    environment: Environment, mode: Mode | None
) -> list[dict[str, str]]:
    return [
        {"path": str(project.path), "trustLevel": project.trust_level}
        for project in _expand_trusted_projects(
            _trusted_project_sources(environment, mode)
        )
    ]


def _expand_trusted_project_source(
    source: TrustedProjectSource,
) -> tuple[TrustedProject, ...]:
    if isinstance(source, TrustedProject):
        return (source,)
    return _expand_trusted_project_children(source)


def _expand_trusted_project_children(
    source: TrustedProjectChildren,
) -> tuple[TrustedProject, ...]:
    if not source.root.is_dir():
        return ()

    projects: list[TrustedProject] = []
    for child in sorted(path for path in source.root.iterdir() if path.is_dir()):
        if source.only_git_repos and not _is_git_repo(child):
            continue
        projects.append(TrustedProject(child, trust_level=source.trust_level))
        if source.devcontainer_mirror is not None and _has_devcontainer(child):
            projects.append(
                TrustedProject(
                    source.devcontainer_mirror / child.name,
                    trust_level=source.trust_level,
                )
            )
    return tuple(projects)


def _is_git_repo(path: Path) -> bool:
    return (path / ".git").exists()


def _has_devcontainer(path: Path) -> bool:
    devcontainer_dir = path / ".devcontainer"
    return (
        (devcontainer_dir / "devcontainer.json").is_file()
        or (path / ".devcontainer.json").is_file()
        or any(devcontainer_dir.glob("*/devcontainer.json"))
    )


def _sorted_unique(values: Iterable[str]) -> list[str]:
    """Render an order-insensitive list in a stable, diff-friendly order."""
    return sorted(set(values))


def _deep_merge(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    merged = dict(left)
    for key, right_value in right.items():
        left_value = merged.get(key)
        if isinstance(left_value, dict) and isinstance(right_value, dict):
            merged[key] = _deep_merge(left_value, right_value)
        else:
            merged[key] = right_value
    return merged


def _render_tool_config(server: ToolServer) -> dict[str, Any]:
    tools = dict(server.tools)
    for approval in server.tool_approvals:
        existing = tools.get(approval.tool, {})
        if not isinstance(existing, dict):
            existing = {}
        value = {**existing, "approval_mode": approval.mode}
        if approval.reason:
            value["reason"] = approval.reason
        tools[approval.tool] = value
    return tools


def _render_codex_rule(rule: Rule) -> str:
    decision = {
        "allow": "allow",
        "ask": "prompt",
        "deny": "forbidden",
    }[rule.effect]
    fields = [
        ("pattern", _codex_pattern(rule.target.parts)),
        ("decision", decision),
    ]
    if rule.justification:
        fields.append(("justification", rule.justification))
    if rule.match:
        fields.append(("match", list(rule.match)))
    if rule.not_match:
        fields.append(("not_match", list(rule.not_match)))

    if len(fields) == 2:
        pattern = json.dumps(fields[0][1])
        decision = json.dumps(fields[1][1])
        return f"prefix_rule(pattern={pattern}, decision={decision})"

    rendered = ["prefix_rule("]
    for key, value in fields:
        rendered.append(f"  {key} = {json.dumps(value)},")
    rendered.append(")")
    return "\n".join(rendered)


def _codex_pattern(parts: tuple[RulePart, ...]) -> list[Any]:
    pattern: list[Any] = []
    for part in parts:
        if isinstance(part, Choice):
            pattern.append(list(part.values))
        else:
            pattern.append(part)
    return pattern


def render_claude_rules(rule_sets: tuple[RuleSet, ...]) -> dict[str, list[str]]:
    """Lower portable rules without adding home-level permission defaults."""
    rendered: dict[str, list[str]] = {}
    rules = tuple(chain.from_iterable(rule_set.rules for rule_set in rule_sets))
    for effect in ("allow", "ask", "deny"):
        values = [
            _claude_shell_rule(parts)
            for rule in rules
            if rule.effect == effect
            for parts in expand_shell_command(rule.target)
        ]
        if values:
            rendered[effect] = values
    return rendered


def _render_claude_tool_approvals(
    servers: tuple[ToolServer, ...],
) -> dict[str, list[str]]:
    rendered: dict[str, list[str]] = {}
    mode_to_effect = {
        "approve": "allow",
        "ask": "ask",
        "deny": "deny",
    }
    for server in servers:
        for approval in server.tool_approvals:
            effect = mode_to_effect[approval.mode]
            rendered.setdefault(effect, []).append(
                f"mcp__{server.name}__{approval.tool}"
            )
    return rendered


def _merge_permission_entries(
    target: dict[str, Any], source: dict[str, list[str]]
) -> None:
    for effect, entries in source.items():
        existing = target.setdefault(effect, [])
        if not isinstance(existing, list):
            raise TypeError(f"permissions.{effect} must be a list")
        existing.extend(entries)


def _claude_shell_rule(parts: tuple[str, ...]) -> str:
    return f"Bash({' '.join(parts)} *)"


CLAUDE_PROJECT_INSTRUCTIONS = """## Project Instructions

When working inside a project, check whether the project has an `AGENTS.md`.
If it exists, read it and follow it in addition to these home-level instructions."""


CLAUDE_SANDBOX_EXCLUSION_INTRO = (
    "These commands run outside the sandbox only when the entire command matches "
    "an exclusion pattern. Run each as a standalone command: no `cd` prefix, "
    "pipes, redirection, or chaining with `;`, `&&`, or `||`."
)


def _claude_sandbox_exclusion_block(
    rule_sets: tuple[RuleSet, ...],
) -> InstructionBlock | None:
    entries = dict.fromkeys(
        f"- {', '.join(f'`{command}`' for command in rule_set.sandbox_excluded_commands)}"
        f": {rule_set.sandbox_exclusion_reason}"
        for rule_set in rule_sets
        if rule_set.sandbox_excluded_commands
    )
    if not entries:
        return None
    body = "\n".join((CLAUDE_SANDBOX_EXCLUSION_INTRO, "", *entries))
    return InstructionBlock(title="Sandbox-Excluded Commands", body=body)


def _render_instruction_file(
    *,
    instruction_sets: tuple[InstructionSet, ...],
    format: Literal["codex", "claude"],
    sandbox_exclusions: InstructionBlock | None = None,
) -> str:
    body = _render_instruction_sets(instruction_sets, sandbox_exclusions)
    if format == "codex":
        return f"{body}\n"
    return f"{CLAUDE_PROJECT_INSTRUCTIONS}\n\n{body}\n"


def _render_instruction_sets(
    instruction_sets: tuple[InstructionSet, ...],
    sandbox_exclusions: InstructionBlock | None = None,
) -> str:
    chunks: list[str] = []
    for instruction_set in instruction_sets:
        for source in instruction_set.blocks:
            instruction_block = _resolve_instruction_source(source, sandbox_exclusions)
            if instruction_block is not None:
                chunks.append(
                    f"## {instruction_block.title}\n\n{instruction_block.body.strip()}"
                )
    return "\n\n".join(chunks)


def _resolve_instruction_source(
    source: InstructionSource, sandbox_exclusions: InstructionBlock | None
) -> InstructionBlock | None:
    if isinstance(source, SandboxExclusions):
        return sandbox_exclusions
    if isinstance(source, InstructionBlock):
        return source
    return _load_instruction_file(source)


def _load_instruction_file(source: InstructionFile) -> InstructionBlock:
    text = source.path.read_text(encoding="utf-8").strip()
    lines = text.splitlines()
    if not lines or not lines[0].startswith("# "):
        raise ValueError(
            f"instruction file {source.path} must start with a '# ' heading"
        )
    invalid_headings = [
        line for line in lines[1:] if line.startswith("# ") or line.startswith("## ")
    ]
    if invalid_headings:
        raise ValueError(
            f"instruction file {source.path} body headings must use '###' or deeper"
        )
    title = lines[0].removeprefix("# ").strip()
    body = "\n".join(lines[1:]).strip()
    return InstructionBlock(title=title, body=body)
