"""Render and validate inline skills and their managed ownership inventory.

Both provider homes discover ``skills/<name>/SKILL.md``. Codex also reads
``agents/openai.yaml`` inside each skill for its invocation policy.
"""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal

from harness_manifest import Skill, SkillInvocation
from harness_factory.tree_diff import sync_tree

Harness = Literal["codex", "claude"]
SKILLS_MANIFEST = Path(".harness-factory-managed-skills.json")


def skill_files(name: str, harness: Harness) -> frozenset[Path]:
    root = Path("skills") / name
    files = {root / "SKILL.md"}
    if harness == "codex":
        files.add(root / "agents" / "openai.yaml")
    return frozenset(files)


def _load_inventory(home: Path) -> tuple[Harness | None, dict[str, SkillInvocation]]:
    """Read only our inventory; never enumerate unrelated provider skills."""
    validate_skill_path(home, SKILLS_MANIFEST)
    path = home / SKILLS_MANIFEST
    if not path.exists():
        return None, {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if (
            not isinstance(data, dict)
            or set(data) != {"schema_version", "harness", "skills"}
            or type(data["schema_version"]) is not int
            or data["schema_version"] != 1
            or data["harness"] not in ("codex", "claude")
            or not isinstance(data["skills"], list)
        ):
            raise ValueError("unsupported schema or fields")
        inventory = {}
        for item in data["skills"]:
            if not isinstance(item, dict) or set(item) != {"name", "invocation"}:
                raise ValueError("invalid skill entry")
            skill = Skill(description="Managed skill", body="Managed skill", **item)
            if skill.name in inventory:
                raise ValueError("duplicate skill name")
            inventory[skill.name] = skill.invocation
        return data["harness"], inventory
    except (ValueError, TypeError) as error:
        raise ValueError(f"invalid managed skill inventory: {path}: {error}") from error


def load_skill_inventory(
    home: Path, harness: Harness | None = None
) -> dict[str, SkillInvocation]:
    provider, inventory = _load_inventory(home)
    if harness is not None and provider is not None and provider != harness:
        raise ValueError(
            f"managed skill inventory is for {provider}, expected {harness}"
        )
    return inventory


def managed_skill_paths(home: Path) -> frozenset[Path] | None:
    harness, inventory = _load_inventory(home)
    if harness is None:
        return None
    return frozenset(path for name in inventory for path in skill_files(name, harness))


def _markdown(skill: Skill, harness: Harness) -> str:
    fields = {
        "name": skill.name,
        "description": skill.description,
    }
    lines = ["---", *(f"{key}: {json.dumps(value)}" for key, value in fields.items())]
    if harness == "claude":
        lines.append(
            f"disable-model-invocation: {str(skill.invocation == 'user').lower()}"
        )
    return "\n".join((*lines, "---", "", skill.body, ""))


def _policy(invocation: SkillInvocation) -> str:
    return (
        f"policy:\n  allow_implicit_invocation: {str(invocation == 'auto').lower()}\n"
    )


def validate_skill_path(home: Path, relative: Path) -> None:
    """Refuse symlinked skill files and ancestors before reading or writing."""
    path = home
    for part in ("", *relative.parts):
        path /= part
        if path.is_symlink():
            raise ValueError(f"Refusing to manage skills through symlink: {path}")


def write_skills(skills: tuple[Skill, ...], home: Path, harness: Harness) -> None:
    paths = {SKILLS_MANIFEST} | {
        path for skill in skills for path in skill_files(skill.name, harness)
    }
    for path in paths:
        validate_skill_path(home, path)
    previous = load_skill_inventory(home, harness)
    previous_paths = {path for name in previous for path in skill_files(name, harness)}
    for path in paths - previous_paths - {SKILLS_MANIFEST}:
        if (home / path).exists():
            raise ValueError(
                f"Refusing to replace an unmanaged skill file: {home / path}"
            )
    retired = frozenset(
        path
        for name in previous.keys() - {skill.name for skill in skills}
        for path in skill_files(name, harness)
    )
    if retired:
        with TemporaryDirectory(prefix="harness-retire-skills-") as empty:
            sync_tree(
                home, Path(empty), included_paths=frozenset(), retired_paths=retired
            )
    for skill in sorted(skills, key=lambda skill: skill.name):
        root = home / "skills" / skill.name
        root.mkdir(parents=True, exist_ok=True)
        (root / "SKILL.md").write_text(_markdown(skill, harness), encoding="utf-8")
        if harness == "codex":
            (root / "agents").mkdir(exist_ok=True)
            (root / "agents" / "openai.yaml").write_text(
                _policy(skill.invocation), encoding="utf-8"
            )
    (home / SKILLS_MANIFEST).write_text(
        json.dumps(
            {
                "schema_version": 1,
                "harness": harness,
                "skills": [
                    {"name": skill.name, "invocation": skill.invocation}
                    for skill in sorted(skills, key=lambda skill: skill.name)
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def deployment_skill_retirements(
    source: Path,
    target: Path,
    harness: Harness,
    managed_files: frozenset[Path],
    excluded_paths: tuple[Path, ...],
) -> frozenset[Path]:
    """Validate ownership before deployment, and retire only prior managed skills."""
    validate_skills(source, harness)
    validate_skill_path(target, SKILLS_MANIFEST)
    previous = load_skill_inventory(target, harness)
    current = load_skill_inventory(source, harness)
    current_paths = frozenset(
        path for name in current for path in skill_files(name, harness)
    )
    previous_paths = frozenset(
        path for name in previous for path in skill_files(name, harness)
    )
    if current_paths - managed_files or (
        current and SKILLS_MANIFEST not in managed_files
    ):
        raise ValueError(
            "managed skills must be included in the rendered ownership manifest"
        )
    if previous and SKILLS_MANIFEST not in managed_files:
        raise ValueError(
            "deployment must include a managed skill inventory to retire skills"
        )
    for path in current_paths | previous_paths | {SKILLS_MANIFEST}:
        if any(path == prefix or prefix in path.parents for prefix in excluded_paths):
            raise ValueError(
                "cannot partially exclude managed skill ownership or discovery files"
            )
        validate_skill_path(target, path)
        if path in current_paths - previous_paths and (target / path).exists():
            raise ValueError(
                f"Refusing to replace an unmanaged skill file: {target / path}"
            )
    return previous_paths - current_paths


def validate_skills(home: Path, harness: Harness) -> None:
    """Check managed discovery files and invocation policy without a model call."""
    validate_skill_path(home, SKILLS_MANIFEST)
    for name, invocation in load_skill_inventory(home, harness).items():
        for path in skill_files(name, harness):
            validate_skill_path(home, path)
            if not (home / path).is_file():
                raise ValueError(
                    f"managed skill discovery file is missing: {home / path}"
                )
        root = home / "skills" / name
        text = (root / "SKILL.md").read_text(encoding="utf-8")
        try:
            frontmatter, body = text.removeprefix("---\n").split("\n---\n", 1)
            fields = {}
            for line in frontmatter.splitlines():
                key, value = line.split(":", 1)
                if key in fields:
                    raise ValueError("duplicate frontmatter field")
                fields[key] = json.loads(value)
            disabled = fields.pop("disable-model-invocation", None)
            if set(fields) != {"name", "description"} or fields["name"] != name:
                raise ValueError("skill name must match its discovery directory")
            Skill(**fields, body=body, invocation=invocation)
            if harness == "claude" and disabled is not (invocation == "user"):
                raise ValueError("disable-model-invocation does not match invocation")
            if harness == "codex":
                if disabled is not None:
                    raise ValueError("Claude invocation setting in Codex skill")
                policy = (root / "agents" / "openai.yaml").read_text(encoding="utf-8")
                if policy != _policy(invocation):
                    raise ValueError(
                        "policy.allow_implicit_invocation does not match invocation"
                    )
            if not text.startswith("---\n"):
                raise ValueError("missing YAML frontmatter")
        except (ValueError, TypeError) as error:
            raise ValueError(f"invalid managed skill {name!r}: {error}") from error
