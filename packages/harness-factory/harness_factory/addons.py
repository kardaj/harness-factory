"""Owned skill bundles and optional Claude session plugins."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from tempfile import TemporaryDirectory
from pathlib import Path

from harness_factory.models import Environment, SkillBundle
from harness_factory.skills import validate_skill_path
from harness_factory.tree_diff import sync_tree


def dumps_json(value: dict) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


ADDONS_MANIFEST = Path(".harness-factory-managed-addons.json")


@dataclass(frozen=True)
class AddonFile:
    data: bytes
    mode: int = 0o644


def bundle_contents(bundle: SkillBundle) -> dict[Path, AddonFile]:
    """Read a declared bundle without following symlinks or special files."""
    root = bundle.source_dir
    if not root.is_dir() or root.is_symlink():
        raise ValueError(f"Skill bundle source must be a real directory: {root}")
    contents = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"Skill bundle contains a symlink: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(f"Skill bundle contains a special file: {path}")
        contents[path.relative_to(root)] = AddonFile(
            path.read_bytes(), 0o755 if path.stat().st_mode & 0o111 else 0o644
        )
    if Path("SKILL.md") not in contents:
        raise ValueError(f"Skill bundle is missing SKILL.md: {root}")
    text = contents[Path("SKILL.md")].data.decode("utf-8")
    header = text.split("\n---", 1)[0]
    name = re.escape(bundle.name)
    if (
        not text.startswith("---\n")
        or re.search(rf"(?m)^name:\s*(?:{name}|\"{name}\"|'{name}')\s*$", header)
        is None
    ):
        raise ValueError("Skill bundle name must match SKILL.md frontmatter")
    return contents


def addon_contents(environment: Environment, harness: str) -> dict[Path, AddonFile]:
    """Compile additions; profiles inherit MCP servers, not another state home."""
    from harness_factory.adapters import ClaudeAdapter

    contents: dict[Path, AddonFile] = {}

    def add(path: Path, data: bytes | AddonFile) -> None:
        if path in contents:
            raise ValueError(f"Add-on files collide: {path}")
        contents[path] = (
            data
            if isinstance(data, AddonFile)
            else AddonFile(data, 0o600 if path.name == "mcp.json" else 0o644)
        )

    for bundle in environment.skill_bundles:
        if harness in bundle.harnesses:
            for path, data in bundle_contents(bundle).items():
                add(Path("skills") / bundle.name / path, data)
    if harness == "claude":
        for profile in environment.claude_profiles:
            root = Path("profiles") / profile.name
            add(
                root / ".claude-plugin/plugin.json",
                dumps_json(
                    {"name": profile.name, "description": profile.description}
                ).encode(),
            )
            servers = {
                server.name: server
                for server in environment.base_mcp_servers
                if "claude" in server.harnesses
            }
            servers.update(
                {
                    server.name: server
                    for server in profile.mcp_servers
                    if "claude" in server.harnesses
                }
            )
            add(
                root / "mcp.json",
                dumps_json(
                    {
                        "mcpServers": ClaudeAdapter._render_mcp_servers(
                            tuple(servers.values())
                        )
                    }
                ).encode(),
            )
            for bundle in profile.skill_bundles:
                if "claude" not in bundle.harnesses:
                    raise ValueError("Claude profiles require Claude-enabled bundles")
                for path, data in bundle_contents(bundle).items():
                    add(root / "skills" / bundle.name / path, data)
    return contents


def load_addon_inventory(home: Path, harness: str) -> frozenset[Path]:
    validate_skill_path(home, ADDONS_MANIFEST)
    manifest = home / ADDONS_MANIFEST
    if not manifest.exists():
        return frozenset()
    try:
        value = json.loads(manifest.read_text())
        if (
            not isinstance(value, dict)
            or set(value) != {"schema_version", "harness", "files"}
            or value["schema_version"] != 1
            or type(value["schema_version"]) is not int
            or value["harness"] != harness
            or not isinstance(value["files"], list)
        ):
            raise ValueError("unsupported inventory")
        paths = set()
        for item in value["files"]:
            if not isinstance(item, str) or not item:
                raise ValueError("invalid file name")
            path = Path(item)
            if (
                path.is_absolute()
                or ".." in path.parts
                or len(path.parts) < 3
                or path.parts[0] not in ("skills", "profiles")
                or path in paths
            ):
                raise ValueError("unsafe or duplicate file")
            validate_skill_path(home, path)
            paths.add(path)
        return frozenset(paths)
    except (ValueError, TypeError, KeyError) as error:
        raise ValueError(f"Invalid add-on inventory: {manifest}") from error


def write_addons(environment: Environment, home: Path, harness: str) -> None:
    contents = addon_contents(environment, harness)
    previous = load_addon_inventory(home, harness)
    for path in contents:
        validate_skill_path(home, path)
        if path not in previous and (home / path).exists():
            raise ValueError(f"Refusing to replace an unmanaged add-on: {home / path}")
    # Archive only previously owned files; preserve local extras within bundles.
    with TemporaryDirectory() as empty:
        sync_tree(
            home,
            Path(empty),
            included_paths=frozenset(),
            retired_paths=previous - contents.keys(),
        )
    for path, data in contents.items():
        destination = home / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data.data)
        destination.chmod(data.mode)
    (home / ADDONS_MANIFEST).write_text(
        dumps_json(
            {
                "schema_version": 1,
                "harness": harness,
                "files": sorted(path.as_posix() for path in contents),
            }
        )
    )


def addon_retirements(
    source: Path,
    target: Path,
    harness: str,
    managed_files: frozenset[Path] | None = None,
    excluded_paths: tuple[Path, ...] = (),
) -> frozenset[Path]:
    current = load_addon_inventory(source, harness)
    previous = load_addon_inventory(target, harness)
    if managed_files is not None and (
        current - managed_files or (current and ADDONS_MANIFEST not in managed_files)
    ):
        raise ValueError("Add-ons must be included in the managed-file inventory")
    for path in (
        current | previous | ({ADDONS_MANIFEST} if current or previous else set())
    ):
        if any(path == prefix or prefix in path.parents for prefix in excluded_paths):
            raise ValueError("Cannot partially exclude add-on ownership or files")
    for path in current:
        if not (source / path).is_file():
            raise ValueError(f"Managed add-on file is missing: {source / path}")
        validate_skill_path(target, path)
        if path not in previous and (target / path).exists():
            raise ValueError(
                f"Refusing to replace an unmanaged add-on: {target / path}"
            )
    return previous - current


def retired_addon_files(found: Path, expected: Path) -> frozenset[Path]:
    """Validate/retire add-ons while syncing a complete rendered tree."""
    return frozenset(
        Path(harness) / home.name / path
        for harness in ("codex", "claude")
        for home in sorted((expected / harness).glob("*"))
        if home.is_dir()
        for path in addon_retirements(home, found / harness / home.name, harness)
    )


def owned_addon_paths(home: Path, harness: str) -> frozenset[Path]:
    inventory = load_addon_inventory(home, harness)
    return inventory | (
        {ADDONS_MANIFEST} if (home / ADDONS_MANIFEST).exists() else set()
    )


def addon_tree_paths(expected: Path) -> frozenset[Path]:
    return frozenset(
        Path(harness) / home.name / path
        for harness in ("codex", "claude")
        for home in (expected / harness).glob("*")
        if home.is_dir()
        for path in owned_addon_paths(home, harness)
    )
