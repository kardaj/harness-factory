"""Repository identity and non-destructive project policy deployment.

Callers supply their registry and discovery roots. No Git state is changed and
project policies never render home defaults, credentials, or device policy.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import tomlkit

from harness_factory.adapters import CodexAdapter, render_claude_rules
from harness_factory.project_sandbox import (
    ProjectSandboxPolicy,
    current_value,
    load_ownership,
    preview as sandbox_preview,
    reconcile,
)
from harness_factory.models import HarnessName
from harness_factory.serializers import dumps_toml
from harness_manifest.rules import RuleSet

SETTINGS_PATH = Path(".claude/settings.local.json")


@dataclass(frozen=True)
class ProjectOwner:
    """The deployer whose ownership files and header mark what it manages.

    ``name`` names the ownership record and rule file in each project, and
    ``managed_by`` is the tool named in generated file headers.
    """

    name: str
    managed_by: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", self.name):
            raise ValueError(f"project owner name must be a slug, got {self.name!r}")
        if not self.managed_by or "\n" in self.managed_by:
            raise ValueError("project owner managed_by must be one nonempty line")

    @property
    def state_path(self) -> Path:
        return Path(f".codex/{self.name}-project.json")

    @property
    def rules_path(self) -> Path:
        return Path(f".codex/rules/{self.name}-project.rules")

    @property
    def header(self) -> str:
        return f"# Managed by {self.managed_by}.\n"


def github_slug(value: str) -> str | None:
    """Normalize a GitHub slug, HTTPS URL, or SSH remote; reject other hosts."""
    value = value.strip()
    scp = re.fullmatch(r"git@github\.com:(.+)", value, flags=re.IGNORECASE)
    if scp:
        path = scp.group(1)
    elif "://" in value:
        parsed = urlsplit(value)
        if parsed.hostname != "github.com" or parsed.scheme not in ("https", "ssh"):
            return None
        if parsed.query or parsed.fragment:
            return None
        path = parsed.path.lstrip("/")
    else:
        path = value
    path = path.rstrip("/").removesuffix(".git")
    if not re.fullmatch(r"[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+", path):
        return None
    owner, repository = path.split("/")
    if repository in (".", ".."):
        return None
    return f"{owner}/{repository}".lower()


@dataclass(frozen=True)
class ProjectPolicy:
    """One portable project overlay identified by explicit GitHub origins."""

    name: str
    repositories: tuple[str, ...]
    rules: tuple[RuleSet, ...] = ()
    sandbox: ProjectSandboxPolicy = field(default_factory=ProjectSandboxPolicy)

    def __post_init__(self) -> None:
        if not isinstance(self.sandbox, ProjectSandboxPolicy):
            raise ValueError("ProjectPolicy.sandbox must be a ProjectSandboxPolicy")
        if not self.name or not self.repositories:
            raise ValueError("ProjectPolicy requires a name and repositories")
        if any(github_slug(repository) is None for repository in self.repositories):
            raise ValueError("ProjectPolicy repositories must be GitHub slugs or URLs")


@dataclass(frozen=True)
class ProjectRepository:
    root: Path
    slug: str | None


def inspect_repository(path: Path) -> ProjectRepository:
    """Inspect the enclosing checkout, including worktrees, using read-only Git."""
    root = Path(_git(path, "rev-parse", "--show-toplevel").strip()).resolve()
    result = subprocess.run(
        ["git", "-C", str(root), "config", "--get-all", "remote.origin.url"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode not in (0, 1):
        raise ValueError(f"Cannot inspect origin in {root}")
    # Never match an upstream of a fork, or guess between multiple origins.
    urls = result.stdout.splitlines()
    slugs = {github_slug(url) for url in urls}
    slug = slugs.pop() if len(slugs) == 1 else None
    return ProjectRepository(root, slug)


def match_project(
    repository: ProjectRepository, policies: tuple[ProjectPolicy, ...]
) -> ProjectPolicy | None:
    matches = [
        policy
        for policy in policies
        if repository.slug is not None
        and repository.slug in {github_slug(value) for value in policy.repositories}
    ]
    if len(matches) > 1:
        raise ValueError(f"Multiple project policies match {repository.slug}")
    return matches[0] if matches else None


def discover_repositories(roots: tuple[Path, ...]) -> tuple[Path, ...]:
    """Find checkouts through grouping directories; stop at each checkout."""
    found: set[Path] = set()
    ignored = {"Build", "node_modules", ".venv", ".cache"}
    for root in roots:
        # An explicitly selected root may be a user-owned alias (e.g. ~/Projects
        # on an external volume); skip symlinked children during traversal.
        root = root.resolve()
        if not root.is_dir():
            continue
        for directory, children, _ in os.walk(root, followlinks=False):
            path = Path(directory)
            if (path / ".git").exists():
                found.add(path.resolve())
                children.clear()
                continue
            children[:] = sorted(
                child
                for child in children
                if not child.startswith(".")
                and child not in ignored
                and not (path / child).is_symlink()
            )
    return tuple(sorted(found))


@dataclass(frozen=True)
class ProjectFileChange:
    path: Path
    before: str | None
    after: str
    diff: str


@dataclass(frozen=True)
class ProjectPlan:
    root: Path
    changes: tuple[ProjectFileChange, ...]

    def apply(self) -> None:
        """Recheck the whole plan before writing; atomically replace each file."""
        for change in self.changes:
            if _read(self.root, change.path) != change.before:
                raise ValueError(f"Project file changed during planning: {change.path}")
        for change in self.changes:
            target = self.root / change.path
            _validate_path(self.root, change.path)
            target.parent.mkdir(parents=True, exist_ok=True)
            mode = stat.S_IMODE(target.stat().st_mode) if target.exists() else 0o600
            descriptor, temporary = tempfile.mkstemp(
                prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
            )
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                    output.write(change.after)
                os.chmod(temporary, mode)
                os.replace(temporary, target)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)


def plan_project(
    repository: ProjectRepository,
    policy: ProjectPolicy,
    *,
    owner: ProjectOwner,
    harnesses: tuple[HarnessName, ...] = ("codex", "claude"),
) -> ProjectPlan:
    """Plan agent configuration changes without reading or writing repository prose."""
    root = repository.root
    state_text = _read(root, owner.state_path)
    state = _object(state_text, owner.state_path)
    if state_text is not None and (
        type(state.get("schema")) is not int or state["schema"] not in (1, 2)
    ):
        raise ValueError(f"Unsupported project ownership schema in {owner.state_path}")
    if state.get("schema") == 2 and set(state) != {
        "schema",
        "policy",
        "repository",
        "claude_permissions",
        "claude_exclusions",
        "sandbox_settings",
    }:
        raise ValueError(f"Invalid project ownership schema in {owner.state_path}")
    if state.get("schema") == 1 and "sandbox_settings" in state:
        raise ValueError("Project sandbox ownership requires schema 2")
    sandbox_ownership = load_ownership(state.get("sandbox_settings", {}))
    permissions = _string_lists(state.get("claude_permissions", {}), owner.state_path)
    old_exclusions = _strings(state.get("claude_exclusions", []), owner.state_path)
    changes: list[ProjectFileChange] = []

    def add(path: Path, after: str, *, preview: tuple[str, str] | None = None) -> None:
        before = _read(root, path)
        if before == after:
            return
        old, new = preview if preview is not None else (before or "", after)
        diff = "".join(
            difflib.unified_diff(
                old.splitlines(keepends=True),
                new.splitlines(keepends=True),
                fromfile=f"a/{path}",
                tofile=f"b/{path}",
                n=0,
            )
        )
        changes.append(ProjectFileChange(path, before, after, diff))

    if "codex" in harnesses:
        previous_rules = _read(root, owner.rules_path)
        if previous_rules is not None and not previous_rules.startswith(owner.header):
            raise ValueError(
                f"Refusing to replace unowned project rules: {owner.rules_path}"
            )
        rules = owner.header + "\n".join(
            CodexAdapter.render_rule_set(rule_set) for rule_set in policy.rules
        )
        add(owner.rules_path, rules)
        # Only the declared scalar is changed; comments and unrelated TOML survive.
        config_path = Path(".codex/config.toml")
        config_text = _read(root, config_path)
        local_binding = policy.sandbox.local_binding_for("codex")
        if local_binding is not None or "codex" in sandbox_ownership:
            try:
                config = tomlkit.parse(
                    config_text if config_text is not None else owner.header
                )
            except tomlkit.exceptions.ParseError as error:
                raise ValueError("Invalid project Codex configuration") from error
            before = dumps_toml(sandbox_preview(config, "codex"))
            record = reconcile(
                config, "codex", local_binding, sandbox_ownership.get("codex")
            )
            if record is None:
                sandbox_ownership.pop("codex", None)
            else:
                sandbox_ownership["codex"] = record
            add(
                config_path,
                tomlkit.dumps(config),
                preview=(before, dumps_toml(sandbox_preview(config, "codex"))),
            )
        elif config_text is None:
            add(config_path, owner.header)

    if "claude" in harnesses:
        settings_text = _read(root, SETTINGS_PATH)
        settings = _object(settings_text, SETTINGS_PATH)
        desired = render_claude_rules(policy.rules)
        desired_exclusions = list(
            dict.fromkeys(
                command
                for rule_set in policy.rules
                for command in rule_set.sandbox_excluded_commands
            )
        )
        current_permissions = settings.get("permissions", {})
        if not isinstance(current_permissions, dict):
            raise ValueError(f"Invalid permissions in {SETTINGS_PATH}")
        for effect in ("allow", "ask", "deny"):
            if effect in current_permissions:
                _strings(current_permissions[effect], SETTINGS_PATH)
        sandbox = settings.get("sandbox", {})
        if not isinstance(sandbox, dict):
            raise ValueError(f"Invalid sandbox in {SETTINGS_PATH}")
        exclusions = _strings(sandbox.get("excludedCommands", []), SETTINGS_PATH)
        local_binding = policy.sandbox.local_binding_for("claude")
        manage_binding = local_binding is not None or "claude" in sandbox_ownership
        before_binding = current_value(settings, "claude") if manage_binding else None
        before_preview = _permission_preview(
            current_permissions, exclusions, before_binding
        )
        owned: dict[str, list[str]] = {}
        for effect in ("allow", "ask", "deny"):
            if effect not in desired and effect not in permissions:
                continue
            existing = current_permissions.get(effect, [])
            updated, additions = _overlay_entries(
                existing, permissions.get(effect, []), desired.get(effect, [])
            )
            current_permissions[effect] = updated
            owned[effect] = additions
        if current_permissions:
            settings["permissions"] = current_permissions
        exclusions, owned_exclusions = _overlay_entries(
            exclusions, old_exclusions, desired_exclusions
        )
        if desired_exclusions or old_exclusions:
            sandbox["excludedCommands"] = exclusions
            settings["sandbox"] = sandbox
        if manage_binding:
            record = reconcile(
                settings, "claude", local_binding, sandbox_ownership.get("claude")
            )
            if record is None:
                sandbox_ownership.pop("claude", None)
            else:
                sandbox_ownership["claude"] = record
        after_binding = current_value(settings, "claude") if manage_binding else None
        permissions = owned
        old_exclusions = owned_exclusions
        # Diff only policy fields, never env, hooks, MCP credentials, or runtime values.
        add(
            SETTINGS_PATH,
            _json(settings),
            preview=(
                before_preview,
                _permission_preview(current_permissions, exclusions, after_binding),
            ),
        )

    add(
        owner.state_path,
        _json(
            {
                "schema": 2,
                "policy": policy.name,
                "repository": repository.slug,
                "claude_permissions": permissions,
                "claude_exclusions": old_exclusions,
                "sandbox_settings": sandbox_ownership,
            }
        ),
    )
    return ProjectPlan(root, tuple(changes))


def _git(path: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise ValueError(f"Cannot inspect Git repository at {path}")
    return result.stdout


def _validate_path(root: Path, relative: Path) -> None:
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"Invalid managed project path: {relative}")
    target = root
    for part in relative.parts:
        target /= part
        if target.is_symlink():
            raise ValueError(f"Managed project paths must not be symlinks: {relative}")
        if target != root / relative and target.exists() and not target.is_dir():
            raise ValueError(f"Managed project parent must be a directory: {relative}")
    if target.exists() and not target.is_file():
        raise ValueError(f"Managed project path must be a regular file: {relative}")


def _read(root: Path, path: Path) -> str | None:
    _validate_path(root, path)
    target = root / path
    return target.read_text(encoding="utf-8") if target.exists() else None


def _object(text: str | None, path: Path) -> dict:
    value = json.loads(text) if text is not None else {}
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return value


def _strings(value: object, path: Path) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"Expected a string list in {path}")
    return value


def _string_lists(value: object, path: Path) -> dict[str, list[str]]:
    if not isinstance(value, dict) or set(value) - {"allow", "ask", "deny"}:
        raise ValueError(f"Invalid managed permission entries in {path}")
    return {key: _strings(items, path) for key, items in value.items()}


def _overlay_entries(
    existing: list[str], owned: list[str], desired: list[str]
) -> tuple[list[str], list[str]]:
    # Entries that predated adoption remain user-owned even if also requested.
    remaining = list(existing)
    for entry in owned:
        if entry in remaining:
            remaining.remove(entry)
    additions = [entry for entry in dict.fromkeys(desired) if entry not in remaining]
    return remaining + additions, additions


def _json(value: dict) -> str:
    return json.dumps(value, indent=2) + "\n"


def _permission_preview(
    permissions: dict, exclusions: list[str], local_binding: bool | None = None
) -> str:
    return _json(
        {
            "permissions": {
                key: permissions[key]
                for key in ("allow", "ask", "deny")
                if key in permissions
            },
            "sandbox": {
                "excludedCommands": exclusions,
                **(
                    {"network": {"allowLocalBinding": local_binding}}
                    if local_binding is not None
                    else {}
                ),
            },
        }
    )
