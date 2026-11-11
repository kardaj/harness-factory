"""Typed project sandbox settings and ownership-aware scalar overrides."""

from __future__ import annotations

from collections.abc import MutableMapping
from dataclasses import dataclass
from typing import Any

from harness_factory.models import HarnessName, HarnessScopedValue, local_binding_value

PATHS = {
    "codex": ("features", "network_proxy", "allow_local_binding"),
    "claude": ("sandbox", "network", "allowLocalBinding"),
}


@dataclass(frozen=True)
class ProjectSandboxPolicy:
    """None inherits existing settings; booleans explicitly override them."""

    allow_local_binding: bool | HarnessScopedValue | None = None

    def __post_init__(self) -> None:
        for harness in ("codex", "claude"):
            self.local_binding_for(harness)

    def local_binding_for(self, harness: HarnessName) -> bool | None:
        return local_binding_value(self.allow_local_binding, harness)


def load_ownership(value: Any) -> dict:
    if not isinstance(value, dict) or set(value) - {"codex", "claude"}:
        raise ValueError("Invalid project sandbox ownership")
    for harness, record in value.items():
        if not isinstance(record, dict) or set(record) != {
            "before",
            "applied",
            "created_tables",
        }:
            raise ValueError("Invalid project sandbox ownership")
        if record["before"] is not None and type(record["before"]) is not bool:
            raise ValueError("Invalid project sandbox original value")
        if type(record["applied"]) is not bool:
            raise ValueError("Invalid project sandbox applied value")
        allowed = [".".join(PATHS[harness][:index]) for index in (1, 2)]
        created = record["created_tables"]
        if (
            not isinstance(created, list)
            or any(not isinstance(item, str) or item not in allowed for item in created)
            or len(created) != len(set(created))
        ):
            raise ValueError("Invalid project sandbox table ownership")
    return value


def current_value(config: MutableMapping, harness: HarnessName) -> bool | None:
    current = config
    for key in PATHS[harness][:-1]:
        if key not in current:
            return None
        current = current[key]
        if not isinstance(current, MutableMapping):
            raise ValueError(f"Expected table at {key} in project sandbox settings")
    if PATHS[harness][-1] not in current:
        return None
    value = current[PATHS[harness][-1]]
    value = value.unwrap() if hasattr(value, "unwrap") else value
    if type(value) is not bool:
        raise ValueError("Project local-binding setting must be a boolean")
    return value


def _missing_tables(config: MutableMapping, harness: HarnessName) -> list[str]:
    current = config
    missing = []
    for index, key in enumerate(PATHS[harness][:-1], 1):
        if key not in current:
            missing.extend(".".join(PATHS[harness][:end]) for end in range(index, 3))
            break
        current = current[key]
        if not isinstance(current, MutableMapping):
            raise ValueError(f"Expected table at {key} in project sandbox settings")
    return missing


def _set(
    config: MutableMapping, harness: HarnessName, value: bool | None, created: list[str]
) -> None:
    path = PATHS[harness]
    current = config
    for key in path[:-1]:
        if key not in current:
            if value is None:
                return
            current[key] = {}
        current = current[key]
    if value is None:
        current.pop(path[-1], None)
        for dotted in sorted(created, key=lambda item: item.count("."), reverse=True):
            parts = dotted.split(".")
            parent = config
            for part in parts[:-1]:
                parent = parent[part]
            if not parent.get(parts[-1]):
                parent.pop(parts[-1], None)
    else:
        current[path[-1]] = value


def reconcile(
    config: MutableMapping,
    harness: HarnessName,
    desired: bool | None,
    record: dict | None,
) -> dict | None:
    current = current_value(config, harness)
    if desired is None:
        if record and current == record["applied"]:
            _set(config, harness, record["before"], record["created_tables"])
        return None
    if record is None or current != record["applied"]:
        record = {
            "before": current,
            "applied": desired,
            "created_tables": _missing_tables(config, harness),
        }
    else:
        record = {**record, "applied": desired}
    _set(config, harness, desired, record["created_tables"])
    return record


def preview(config: MutableMapping, harness: HarnessName) -> dict:
    value = current_value(config, harness)
    result: dict = {}
    if value is not None:
        _set(result, harness, value, [])
    return result
