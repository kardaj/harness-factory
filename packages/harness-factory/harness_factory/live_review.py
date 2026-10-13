"""Report live harness config entries that are not in the model render."""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tomllib


@dataclass(frozen=True)
class LiveItem:
    value: str
    suggestion: str | None = None


@dataclass
class LiveReview:
    environment: str
    harness: str
    categories: dict[str, list[LiveItem]] = field(default_factory=dict)

    @property
    def has_items(self) -> bool:
        return any(self.categories.values())

    def add(self, category: str, value: str, suggestion: str | None = None) -> None:
        self.categories.setdefault(category, []).append(LiveItem(value, suggestion))


@dataclass(frozen=True)
class LiveHomeSet:
    environment: str
    codex_live: Path
    codex_expected: Path
    claude_live: Path
    claude_expected: Path


def review_live_output(
    live_dir: Path,
    expected_dir: Path,
    *,
    extra_home_sets: tuple[LiveHomeSet, ...] = (),
) -> list[LiveReview]:
    reviews: list[LiveReview] = []
    environment_names = _environment_names(live_dir, expected_dir)
    for environment in environment_names:
        reviews.append(
            _review_codex_home(
                environment,
                live_dir / "codex" / environment,
                expected_dir / "codex" / environment,
            )
        )
        reviews.append(
            _review_claude_home(
                environment,
                live_dir / "claude" / environment,
                expected_dir / "claude" / environment,
            )
        )
    for home_set in extra_home_sets:
        reviews.append(
            _review_codex_home(
                home_set.environment,
                home_set.codex_live,
                home_set.codex_expected,
            )
        )
        reviews.append(
            _review_claude_home(
                home_set.environment,
                home_set.claude_live,
                home_set.claude_expected,
            )
        )
    return [review for review in reviews if review.has_items]


def format_live_reviews(reviews: list[LiveReview]) -> str:
    if not reviews:
        return "[harness] No live-only model candidates found.\n"

    lines: list[str] = []
    current_environment: str | None = None
    for review in reviews:
        if review.environment != current_environment:
            if lines:
                lines.append("")
            lines.append(f"{review.environment}:")
            current_environment = review.environment
        lines.append(f"  {review.harness}:")
        for category, items in review.categories.items():
            lines.append(f"    {category}:")
            for item in items:
                lines.append(f"      - {item.value}")
                if item.suggestion:
                    lines.append(f"        suggest: {item.suggestion}")
    return "\n".join(lines) + "\n"


def _environment_names(live_dir: Path, expected_dir: Path) -> list[str]:
    names: set[str] = set()
    for root in (live_dir, expected_dir):
        for harness in ("codex", "claude"):
            harness_dir = root / harness
            if harness_dir.is_dir():
                names.update(
                    path.name for path in harness_dir.iterdir() if path.is_dir()
                )
    return sorted(names)


def _review_codex_home(
    environment: str, live_home: Path, expected_home: Path
) -> LiveReview:
    review = LiveReview(environment, "codex")
    live = _read_toml(live_home / "config.toml")
    expected = _read_toml(expected_home / "config.toml")
    if not live:
        return review

    for path in _extra_keys(live.get("projects"), expected.get("projects")):
        review.add("trusted_projects", path, f'trust("{path}")')

    live_servers = _as_dict(live.get("mcp_servers"))
    expected_servers = _as_dict(expected.get("mcp_servers"))
    for server in sorted(set(live_servers) - set(expected_servers)):
        review.add("mcp_servers", server)

    for server in sorted(live_servers):
        live_tools = _as_dict(_as_dict(live_servers[server]).get("tools"))
        expected_tools = _as_dict(_as_dict(expected_servers.get(server)).get("tools"))
        for tool in sorted(set(live_tools) - set(expected_tools)):
            approval = _as_dict(live_tools[tool]).get("approval_mode")
            value = f"{server}.{tool}"
            suggestion = None
            if approval == "approve":
                suggestion = f'approve_tool("{tool}") on ToolServer({server!r})'
            elif approval == "ask":
                suggestion = f'ask_tool("{tool}") on ToolServer({server!r})'
            elif approval == "deny":
                suggestion = f'deny_tool("{tool}") on ToolServer({server!r})'
            review.add("mcp_tool_approvals", value, suggestion)

    live_rules = _read_codex_rules(live_home / "rules")
    expected_rules = _read_codex_rules(expected_home / "rules")
    expected_rule_values = (
        set().union(*expected_rules.values()) if expected_rules else set()
    )
    for rule_set in sorted(live_rules):
        for rule in sorted(live_rules[rule_set] - expected_rule_values):
            review.add(
                f"rules.{rule_set}", rule, _codex_rule_suggestion(rule_set, rule)
            )

    return review


def _review_claude_home(
    environment: str, live_home: Path, expected_home: Path
) -> LiveReview:
    review = LiveReview(environment, "claude")
    live_settings = _read_json(live_home / "settings.json")
    expected_settings = _read_json(expected_home / "settings.json")

    live_permissions = _as_dict(live_settings.get("permissions"))
    expected_permissions = _as_dict(expected_settings.get("permissions"))
    for effect in ("allow", "ask", "deny"):
        for permission in sorted(
            set(_as_list(live_permissions.get(effect)))
            - set(_as_list(expected_permissions.get(effect)))
        ):
            review.add(
                f"permissions.{effect}",
                permission,
                _permission_suggestion(effect, permission),
            )

    live_mcp = _as_dict(_read_json(live_home / ".mcp.json").get("mcpServers"))
    expected_mcp = _as_dict(_read_json(expected_home / ".mcp.json").get("mcpServers"))
    for server in sorted(set(live_mcp) - set(expected_mcp)):
        review.add("mcp_servers", server)

    live_trust = _trusted_project_paths(live_home / "claude.config.json")
    expected_trust = _trusted_project_paths(expected_home / "claude.config.json")
    for path in sorted(live_trust - expected_trust):
        review.add("trusted_projects", path, f'trust("{path}")')

    return review


def _permission_suggestion(effect: str, permission: str) -> str | None:
    if not permission.startswith("mcp__"):
        return None
    parts = permission.split("__", 2)
    if len(parts) != 3:
        return None
    _, server, tool = parts
    helper_by_effect = {"allow": "approve_tool", "ask": "ask_tool", "deny": "deny_tool"}
    helper = helper_by_effect.get(effect)
    if helper is None:
        return None
    return f'{helper}("{tool}") on ToolServer({server!r})'


def _read_codex_rules(rules_dir: Path) -> dict[str, set[str]]:
    if not rules_dir.is_dir():
        return {}
    rules: dict[str, set[str]] = {}
    for path in sorted(rules_dir.glob("*.rules")):
        values = _codex_rule_values(path)
        if values:
            rules[path.stem] = values
    return rules


def _codex_rule_values(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError:
        return set()

    rules: set[str] = set()
    for statement in tree.body:
        if not isinstance(statement, ast.Expr) or not isinstance(
            statement.value, ast.Call
        ):
            continue
        call = statement.value
        if not isinstance(call.func, ast.Name) or call.func.id != "prefix_rule":
            continue

        values = {
            keyword.arg: _literal(keyword.value)
            for keyword in call.keywords
            if keyword.arg is not None
        }
        pattern = values.get("pattern")
        decision = values.get("decision")
        if _valid_codex_pattern(pattern) and isinstance(decision, str):
            rules.add(_format_codex_rule(pattern, decision))
    return rules


def _codex_rule_suggestion(rule_set: str, rule: str) -> str | None:
    try:
        parsed = json.loads(rule)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    pattern = parsed.get("pattern")
    decision = parsed.get("decision")
    if not _valid_codex_pattern(pattern) or not isinstance(decision, str):
        return None

    effect_by_decision = {"allow": "allow", "ask": "ask", "forbidden": "deny"}
    effect = effect_by_decision.get(decision)
    if effect is None:
        return None
    return f"{effect}({_shell_suggestion(pattern)}) on RuleSet({rule_set!r})"


def _shell_suggestion(pattern: Any) -> str:
    parts = []
    for part in pattern:
        if isinstance(part, str):
            parts.append(json.dumps(part))
        else:
            choices = ", ".join(json.dumps(value) for value in part)
            parts.append(f"choice({choices})")
    return f"shell({', '.join(parts)})"


def _literal(node: ast.AST) -> Any:
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        return None


def _valid_codex_pattern(value: Any) -> bool:
    if not isinstance(value, list):
        return False
    return all(
        isinstance(item, str)
        or (
            isinstance(item, list)
            and bool(item)
            and all(isinstance(choice, str) for choice in item)
        )
        for item in value
    )


def _format_codex_rule(pattern: Any, decision: str) -> str:
    return json.dumps(
        {"pattern": pattern, "decision": decision},
        sort_keys=True,
        separators=(",", ":"),
    )


def _trusted_project_paths(config_path: Path) -> set[str]:
    config = _read_json(config_path)
    metadata = _as_dict(config.get("_harnessFactory"))
    projects = metadata.get("trustedProjects")
    if not isinstance(projects, list):
        return set()
    return {
        project["path"]
        for project in projects
        if isinstance(project, dict) and isinstance(project.get("path"), str)
    }


def _extra_keys(live: Any, expected: Any) -> list[str]:
    live_dict = _as_dict(live)
    expected_dict = _as_dict(expected)
    return sorted(set(live_dict) - set(expected_dict))


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    data = json.loads(path.read_text())
    return data if isinstance(data, dict) else {}


def _read_toml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    load = getattr(tomllib, "load", None)
    if load is None:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    else:
        with path.open("rb") as handle:
            data = load(handle)
    return data if isinstance(data, dict) else {}


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]
