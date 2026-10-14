"""Managed-file manifests for rendered harness homes."""

from __future__ import annotations

import json
from pathlib import Path

from harness_factory.skills import managed_skill_paths

MANAGED_FILES_MANIFEST = Path(".harness-factory-managed-files.json")
MANAGED_FILES_MANIFEST_VERSION = 1


class ManagedFilesManifestError(ValueError):
    """Raised when a rendered home's managed-file manifest is invalid."""


def write_managed_files_manifest(home: Path) -> Path:
    """Record the rendered files owned by the harness factory."""

    # A rendered home can also contain provider-installed or personal skills.
    # Own only the discovery files we generated, never their directory extras.
    skill_paths = managed_skill_paths(home)
    files = sorted(
        path.relative_to(home).as_posix()
        for path in home.rglob("*")
        if path.is_file()
        and path.relative_to(home) != MANAGED_FILES_MANIFEST
        and ".harness-retired" not in path.relative_to(home).parts
        and (
            skill_paths is None
            or path.relative_to(home).parts[0] != "skills"
            or path.relative_to(home) in skill_paths
        )
    )
    manifest_path = home / MANAGED_FILES_MANIFEST
    manifest_path.write_text(
        json.dumps(
            {"version": MANAGED_FILES_MANIFEST_VERSION, "files": files},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest_path


def load_managed_files_manifest(home: Path) -> frozenset[Path]:
    """Load and validate the rendered files owned by the harness factory."""

    manifest_path = home / MANAGED_FILES_MANIFEST
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ManagedFilesManifestError(
            f"Managed-file manifest is missing: {manifest_path}"
        ) from error
    except json.JSONDecodeError as error:
        raise ManagedFilesManifestError(
            f"Managed-file manifest is invalid JSON: {manifest_path}"
        ) from error

    if (
        not isinstance(data, dict)
        or data.get("version") != MANAGED_FILES_MANIFEST_VERSION
    ):
        raise ManagedFilesManifestError(
            f"Managed-file manifest has an unsupported version: {manifest_path}"
        )
    raw_files = data.get("files")
    if not isinstance(raw_files, list) or not all(
        isinstance(item, str) for item in raw_files
    ):
        raise ManagedFilesManifestError(
            f"Managed-file manifest has an invalid files list: {manifest_path}"
        )

    files: set[Path] = set()
    for raw_path in raw_files:
        path = Path(raw_path)
        if (
            not raw_path
            or path.is_absolute()
            or ".." in path.parts
            or path == MANAGED_FILES_MANIFEST
        ):
            raise ManagedFilesManifestError(
                f"Managed-file manifest contains an unsafe path: {raw_path!r}"
            )
        if path in files:
            raise ManagedFilesManifestError(
                f"Managed-file manifest contains a duplicate path: {raw_path!r}"
            )
        if not (home / path).is_file():
            raise ManagedFilesManifestError(
                f"Managed-file manifest references a missing file: {home / path}"
            )
        files.add(path)
    return frozenset(files)
