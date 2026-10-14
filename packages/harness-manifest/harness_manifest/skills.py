"""Self-contained workflows exported by tools, loaded only when invoked."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal, get_args

from harness_manifest import checks

SkillInvocation = Literal["user", "auto"]


@dataclass(frozen=True)
class Skill:
    """An inline workflow with an explicit invocation policy for both providers."""

    name: str
    description: str
    body: str
    invocation: SkillInvocation

    def __post_init__(self) -> None:
        checks.string(self.name, "skill name")
        if (
            len(self.name) > 64
            or re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", self.name) is None
            or self.name in ("synced", "anthropic-skills")
        ):
            raise ValueError(
                "skill name must be 1–64 lowercase letters, digits, or single "
                "hyphens between words, and must not be reserved by a provider"
            )
        for field in ("description", "body"):
            value = getattr(self, field)
            checks.string(value, f"skill {self.name!r} {field}")
            if not value.strip() or "\0" in value:
                raise ValueError(
                    f"skill {self.name!r} {field} must contain text without NUL"
                )
        if len(self.description) > 1024:
            raise ValueError(
                f"skill {self.name!r} description must be at most 1024 characters"
            )
        checks.one_of(self.invocation, get_args(SkillInvocation), "skill invocation")
