"""Parse versioned, harness-neutral CLI command policies into portable rules."""

from __future__ import annotations

import json

from harness_manifest import checks
from harness_manifest.rules import Rule, RuleSet, allow, deny, shell


def parse_command_policy(payload: str, *, name: str) -> RuleSet:
    """Import schema 1: command-prefix lists with reasons and sandbox exclusions.

    Unknown schemas and malformed entries fail before any policy is rendered.
    The caller owns obtaining the payload from its selected CLI.
    """
    try:
        policy = json.loads(payload)
    except (ValueError, TypeError) as error:
        raise ValueError("command policy must be valid JSON") from error
    if not isinstance(policy, dict) or set(policy) != {
        "schema",
        "allow",
        "deny",
        "unsandboxed",
    }:
        raise ValueError("command policy must contain schema, allow, deny, unsandboxed")
    if type(policy["schema"]) is not int or policy["schema"] != 1:
        raise ValueError("unsupported command policy schema (expected 1)")

    rules: list[Rule] = []
    exclusions: list[str] = []
    reasons: list[str] = []
    for kind in ("allow", "deny", "unsandboxed"):
        entries = policy[kind]
        if not isinstance(entries, list):
            raise ValueError(f"command policy {kind} must be a list")
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"command", "reason"}:
                raise ValueError(
                    f"command policy {kind} entry must contain command and reason"
                )
            command, reason = entry["command"], entry["reason"]
            if (
                not isinstance(command, list)
                or not command
                or not all(_safe_part(part) for part in command)
                or not isinstance(reason, str)
                or not reason.strip()
                or "\n" in reason
                or "\r" in reason
            ):
                raise ValueError(f"invalid command policy {kind} entry")
            if kind == "unsandboxed":
                exclusions.append(" ".join(command) + " *")
                reasons.append(reason)
            else:
                constructor = allow if kind == "allow" else deny
                rules.append(constructor(shell(*command), justification=reason))

    return RuleSet(
        name=name,
        rules=tuple(rules),
        sandbox_excluded_commands=tuple(dict.fromkeys(exclusions)),
        sandbox_exclusion_reason="; ".join(dict.fromkeys(reasons)) or None,
    )


def _safe_part(part: object) -> bool:
    try:
        checks.command_part(part, "command")
    except ValueError:
        return False
    return True
