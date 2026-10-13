"""Merge generated harness intent into Claude's runtime state."""

from __future__ import annotations

import argparse
import json
from copy import deepcopy
from pathlib import Path
from typing import Any


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Merge generated trusted projects into Claude state."
    )
    parser.add_argument(
        "--config",
        type=Path,
        required=True,
        help="Path to generated claude.config.json.",
    )
    parser.add_argument(
        "--state",
        type=Path,
        default=Path.home() / ".claude.json",
        help="Claude state file to update.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print changes without writing the state file.",
    )
    args = parser.parse_args()

    changed = merge_trusted_projects_file(
        state_path=args.state,
        config_path=args.config,
        dry_run=args.dry_run,
    )
    action = "would update" if args.dry_run else "updated"
    print(f"{action} {len(changed)} Claude trusted project(s)")
    for path in changed:
        print(path)


def merge_trusted_projects_file(
    *, state_path: Path, config_path: Path, dry_run: bool = False
) -> list[str]:
    state = _read_json_object(state_path)
    config = _read_json_object(config_path)
    trusted_projects = _trusted_project_paths(config)
    merged, changed = merge_trusted_projects(state, trusted_projects)
    if changed and not dry_run:
        state_path.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n")
    return changed


def merge_trusted_projects(
    state: dict[str, Any], trusted_project_paths: list[str]
) -> tuple[dict[str, Any], list[str]]:
    merged = deepcopy(state)
    projects = merged.setdefault("projects", {})
    if not isinstance(projects, dict):
        raise TypeError("Claude state field 'projects' must be an object")

    changed: list[str] = []
    for path in sorted(set(trusted_project_paths)):
        project = projects.setdefault(path, {})
        if not isinstance(project, dict):
            raise TypeError(f"Claude project entry {path!r} must be an object")
        if project.get("hasTrustDialogAccepted") is not True:
            project["hasTrustDialogAccepted"] = True
            changed.append(path)
    return merged, changed


def _trusted_project_paths(manifest: dict[str, Any]) -> list[str]:
    factory_metadata = manifest.get("_harnessFactory", {})
    if not isinstance(factory_metadata, dict):
        raise TypeError("Claude config field '_harnessFactory' must be an object")

    projects = factory_metadata.get("trustedProjects", [])
    if not isinstance(projects, list):
        raise TypeError("trust manifest field 'projects' must be a list")

    paths: list[str] = []
    for project in projects:
        if not isinstance(project, dict):
            raise TypeError("trust manifest projects must be objects")
        path = project.get("path")
        if not isinstance(path, str):
            raise TypeError("trust manifest project path must be a string")
        paths.append(path)
    return paths


def _read_json_object(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise TypeError(f"{path} must contain a JSON object")
    return data


if __name__ == "__main__":
    main()
