"""Compare rendered harness output trees."""

from __future__ import annotations

import difflib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from secrets import token_hex
from tempfile import mkdtemp
from typing import Literal

import tomllib

from harness_factory.serializers import dumps_toml

DiffKind = Literal["added", "removed", "modified", "mode", "retired"]
ConfigKeyPath = tuple[str, ...]
ConfigKeyRemovals = dict[Path, tuple[ConfigKeyPath, ...]]
ConfigKeyRedactions = dict[Path, tuple[ConfigKeyPath, ...]]
ManagedModes = dict[Path, int]


@dataclass(frozen=True)
class TreeDiff:
    path: Path
    kind: DiffKind
    text: str


def diff_trees(
    found_dir: Path,
    expected_dir: Path,
    *,
    include_removed: bool = False,
    excluded_path_prefixes: tuple[Path, ...] = (),
    config_key_removals: ConfigKeyRemovals | None = None,
    config_key_redactions: ConfigKeyRedactions | None = None,
    managed_modes: ManagedModes | None = None,
    included_paths: frozenset[Path] | None = None,
    retired_paths: frozenset[Path] = frozenset(),
) -> list[TreeDiff]:
    """Return text diffs needed to turn found_dir into expected_dir."""

    found_files = _relative_files(found_dir, excluded_path_prefixes, included_paths)
    expected_files = _relative_files(
        expected_dir, excluded_path_prefixes, included_paths
    )
    diffs: list[TreeDiff] = []

    compared_files = (
        expected_files | (found_files if include_removed else set())
    ) - retired_paths
    for relative_path in sorted(compared_files):
        found_path = found_dir / relative_path
        expected_path = expected_dir / relative_path

        if relative_path not in found_files:
            diffs.append(
                _content_diff(
                    relative_path,
                    kind="added",
                    old_bytes=b"",
                    new_bytes=expected_path.read_bytes(),
                    redacted_keys=_redactions_for(relative_path, config_key_redactions),
                )
            )
            continue

        if relative_path not in expected_files:
            if not include_removed:
                continue
            diffs.append(
                _content_diff(
                    relative_path,
                    kind="removed",
                    old_bytes=found_path.read_bytes(),
                    new_bytes=b"",
                    redacted_keys=_redactions_for(relative_path, config_key_redactions),
                )
            )
            continue

        found_bytes = found_path.read_bytes()
        expected_bytes = _planned_bytes(
            relative_path,
            found_path,
            expected_path,
            _removals_for(relative_path, config_key_removals),
        )
        if found_bytes != expected_bytes:
            diffs.append(
                _content_diff(
                    relative_path,
                    kind="modified",
                    old_bytes=found_bytes,
                    new_bytes=expected_bytes,
                    redacted_keys=_redactions_for(relative_path, config_key_redactions),
                )
            )

        required_mode = (managed_modes or {}).get(relative_path)
        found_mode = _file_mode(found_path, required_mode)
        expected_mode = _file_mode(expected_path, required_mode)
        if found_mode != expected_mode:
            diffs.append(
                TreeDiff(
                    path=relative_path,
                    kind="mode",
                    text=(
                        f"diff --harness {relative_path.as_posix()}\n"
                        f"old mode {found_mode:06o}\n"
                        f"new mode {expected_mode:06o}\n"
                    ),
                )
            )

    for relative_path, required_mode in sorted((managed_modes or {}).items()):
        found_path = found_dir / relative_path
        expected_path = expected_dir / relative_path
        if not expected_path.is_dir() or not found_path.is_dir():
            continue
        found_mode = stat.S_IMODE(found_path.stat().st_mode)
        if found_mode != required_mode:
            diffs.append(
                TreeDiff(
                    path=relative_path,
                    kind="mode",
                    text=(
                        f"diff --harness {relative_path.as_posix()}\n"
                        f"old mode {found_mode:06o}\n"
                        f"new mode {required_mode:06o}\n"
                    ),
                )
            )

    for relative_path in sorted(retired_paths):
        if _has_path_prefix(relative_path, excluded_path_prefixes):
            continue
        _validate_retired_path(found_dir, relative_path)
        if (expected_dir / relative_path).exists():
            raise ValueError(
                f"Managed file cannot be both active and retired: {relative_path}"
            )
        if (found_dir / relative_path).is_file():
            diffs.append(
                TreeDiff(
                    relative_path,
                    "retired",
                    f"[retired] Archive {relative_path.as_posix()} under .harness-retired/\n",
                )
            )
    return diffs


def format_tree_diffs(diffs: list[TreeDiff]) -> str:
    return "".join(diff.text for diff in diffs)


def sync_tree(
    target_dir: Path,
    expected_dir: Path,
    *,
    excluded_path_prefixes: tuple[Path, ...] = (),
    config_key_removals: ConfigKeyRemovals | None = None,
    config_key_redactions: ConfigKeyRedactions | None = None,
    managed_modes: ManagedModes | None = None,
    included_paths: frozenset[Path] | None = None,
    retired_paths: frozenset[Path] = frozenset(),
) -> list[TreeDiff]:
    """Copy expected files into target_dir without removing unmanaged files."""

    diffs = diff_trees(
        target_dir,
        expected_dir,
        excluded_path_prefixes=excluded_path_prefixes,
        config_key_removals=config_key_removals,
        config_key_redactions=config_key_redactions,
        managed_modes=managed_modes,
        included_paths=included_paths,
        retired_paths=retired_paths,
    )
    for diff in diffs:
        target = target_dir / diff.path
        if (expected_dir / diff.path).is_file() and target.is_symlink():
            raise ValueError(f"Refusing to sync files through symlink: {target}")
    retired = tuple(diff.path for diff in diffs if diff.kind == "retired")
    if retired:
        archive_root = target_dir / ".harness-retired"
        _validate_retired_path(target_dir, Path(".harness-retired"))
        archive_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        archive = Path(mkdtemp(prefix="definitions-", dir=archive_root))
        for relative_path in retired:
            _validate_retired_path(target_dir, relative_path)
            archived = archive / relative_path
            archived.parent.mkdir(parents=True, exist_ok=True)
            (target_dir / relative_path).rename(archived)
    for relative_path in sorted({diff.path for diff in diffs}):
        source = expected_dir / relative_path
        if not source.is_file():
            continue
        target = target_dir / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        _replace_file(
            target,
            _planned_bytes(
                relative_path,
                target,
                source,
                _removals_for(relative_path, config_key_removals),
            ),
            source,
            (managed_modes or {}).get(relative_path),
        )
    for relative_path, required_mode in (managed_modes or {}).items():
        source = expected_dir / relative_path
        target = target_dir / relative_path
        if source.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        if target.exists():
            target.chmod(required_mode)
    return diffs


def _validate_retired_path(root: Path, relative_path: Path) -> None:
    if (
        relative_path.is_absolute()
        or not relative_path.parts
        or ".." in relative_path.parts
    ):
        raise ValueError("Retired paths must be safe relative file paths")
    path = root
    if path.is_symlink():
        raise ValueError(f"Refusing to retire files through symlink: {path}")
    for part in relative_path.parts:
        path /= part
        if path.is_symlink():
            raise ValueError(f"Refusing to retire files through symlink: {path}")
    if (
        path.exists()
        and not path.is_file()
        and relative_path != Path(".harness-retired")
    ):
        raise ValueError(f"Retired path must be a file: {path}")


def _relative_files(
    root: Path,
    excluded_path_prefixes: tuple[Path, ...] = (),
    included_paths: frozenset[Path] | None = None,
) -> set[Path]:
    if not root.exists():
        return set()
    if included_paths is not None:
        return {
            relative_path
            for relative_path in included_paths
            if ((root / relative_path).is_file() or (root / relative_path).is_symlink())
            and not _has_path_prefix(relative_path, excluded_path_prefixes)
        }
    return {
        path.relative_to(root)
        for path in root.rglob("*")
        if (path.is_file() or path.is_symlink())
        and not _has_path_prefix(path.relative_to(root), excluded_path_prefixes)
    }


def _has_path_prefix(path: Path, prefixes: tuple[Path, ...]) -> bool:
    return any(path == prefix or prefix in path.parents for prefix in prefixes)


def _content_diff(
    relative_path: Path,
    *,
    kind: DiffKind,
    old_bytes: bytes,
    new_bytes: bytes,
    redacted_keys: tuple[ConfigKeyPath, ...] = (),
) -> TreeDiff:
    old_label = "/dev/null" if kind == "added" else f"found/{relative_path.as_posix()}"
    new_label = (
        "/dev/null" if kind == "removed" else f"expected/{relative_path.as_posix()}"
    )

    content_changed = old_bytes != new_bytes
    old_bytes = _redact_config_bytes(relative_path, old_bytes, redacted_keys)
    new_bytes = _redact_config_bytes(relative_path, new_bytes, redacted_keys)
    try:
        old_lines = old_bytes.decode("utf-8").splitlines(keepends=True)
        new_lines = new_bytes.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError:
        text = (
            f"diff --harness {relative_path.as_posix()}\n"
            f"Binary files {old_label} and {new_label} differ\n"
        )
    else:
        text = "".join(
            difflib.unified_diff(
                old_lines,
                new_lines,
                fromfile=old_label,
                tofile=new_label,
            )
        )
        if not text and content_changed and redacted_keys:
            text = (
                f"diff --harness {relative_path.as_posix()}\n-<redacted>\n+<redacted>\n"
            )
        if text and not text.endswith("\n"):
            text += "\n"

    return TreeDiff(path=relative_path, kind=kind, text=text)


def _file_mode(path: Path, required_mode: int | None) -> int:
    mode = stat.S_IMODE(path.stat().st_mode)
    return mode if required_mode is not None else mode & 0o111


def _replace_file(
    target_path: Path, content: bytes, expected_path: Path, required_mode: int | None
) -> None:
    """Atomically replace target_path through a file created with its final mode.

    Without a required mode, the target keeps its current permissions (or the
    default creation mode when new) with the expected file's executable bits.
    """
    expected_exec = _file_mode(expected_path, None)
    mode = required_mode
    if mode is None and target_path.exists():
        mode = (stat.S_IMODE(target_path.stat().st_mode) & ~0o111) | expected_exec
    temporary = target_path.parent / f".{target_path.name}.{token_hex(8)}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o666 if mode is None else mode,
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            if mode is None:
                current_mode = stat.S_IMODE(os.fstat(output.fileno()).st_mode)
                mode = (current_mode & ~0o111) | expected_exec
            # The umask may have narrowed the creation mode; set it before writing.
            os.fchmod(output.fileno(), mode)
            output.write(content)
        os.replace(temporary, target_path)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def _redact_config_bytes(
    relative_path: Path,
    content: bytes,
    key_paths: tuple[ConfigKeyPath, ...],
) -> bytes:
    if not content or not key_paths or relative_path.suffix not in (".json", ".toml"):
        return content
    try:
        text = content.decode("utf-8")
        if relative_path.suffix == ".json":
            data = json.loads(text)
        else:
            data = tomllib.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError, tomllib.TOMLDecodeError):
        return content
    if not isinstance(data, dict):
        return content

    for key_path in key_paths:
        for value in _config_values(data, key_path):
            text = text.replace(json.dumps(value), json.dumps("<redacted>"))
    return text.encode()


def _config_values(data: dict, key_path: ConfigKeyPath) -> tuple[str, ...]:
    value: object = data
    for key in key_path[:-1]:
        if not isinstance(value, dict) or key not in value:
            return ()
        value = value[key]
    if not key_path or not isinstance(value, dict):
        return ()
    final_key = key_path[-1]
    if final_key == "*":
        return tuple(item for item in value.values() if isinstance(item, str))
    final_value = value.get(final_key)
    return (final_value,) if isinstance(final_value, str) else ()


def _planned_bytes(
    relative_path: Path,
    found_path: Path,
    expected_path: Path,
    config_key_removals: tuple[ConfigKeyPath, ...] = (),
) -> bytes:
    if found_path.exists() and relative_path.suffix == ".json":
        found_data = json.loads(found_path.read_text())
        expected_data = json.loads(expected_path.read_text())
        if isinstance(found_data, dict) and isinstance(expected_data, dict):
            merged = _deep_overlay(found_data, expected_data)
            _remove_config_keys(merged, config_key_removals)
            return (json.dumps(merged, indent=2, sort_keys=True) + "\n").encode()

    if found_path.exists() and relative_path.suffix == ".toml":
        found_data = _load_toml(found_path)
        expected_data = _load_toml(expected_path)
        merged = _deep_overlay(found_data, expected_data)
        _remove_config_keys(merged, config_key_removals)
        return dumps_toml(merged).encode()

    return expected_path.read_bytes()


def _load_toml(path: Path) -> dict:
    load = getattr(tomllib, "load", None)
    if load is None:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    with path.open("rb") as handle:
        return load(handle)


def _deep_overlay(base: dict, overlay: dict) -> dict:
    merged = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_overlay(merged[key], value)
        else:
            merged[key] = value
    return merged


def _removals_for(
    relative_path: Path,
    config_key_removals: ConfigKeyRemovals | None,
) -> tuple[ConfigKeyPath, ...]:
    if config_key_removals is None:
        return ()
    return config_key_removals.get(relative_path, ())


def _redactions_for(
    relative_path: Path,
    config_key_redactions: ConfigKeyRedactions | None,
) -> tuple[ConfigKeyPath, ...]:
    if config_key_redactions is None:
        return ()
    return config_key_redactions.get(relative_path, ())


def _remove_config_keys(data: dict, key_paths: tuple[ConfigKeyPath, ...]) -> None:
    for key_path in key_paths:
        if not key_path:
            continue
        parent = data
        for key in key_path[:-1]:
            value = parent.get(key)
            if not isinstance(value, dict):
                break
            parent = value
        else:
            parent.pop(key_path[-1], None)
