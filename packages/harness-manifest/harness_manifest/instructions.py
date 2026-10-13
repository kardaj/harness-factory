"""Portable instruction primitives for harness homes."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, get_args

from harness_manifest import checks

InstructionHarness = Literal["codex", "claude"]


@dataclass(frozen=True)
class InstructionBlock:
    """A titled markdown instruction block."""

    title: str
    body: str

    def __post_init__(self) -> None:
        checks.string(self.title, "instruction block title")
        checks.string(self.body, f"instruction block {self.title!r} body", empty=True)
        if not self.body.strip():
            raise ValueError(f"instruction block {self.title!r} requires a body")


@dataclass(frozen=True)
class InstructionFile:
    """A markdown instruction file loaded at render time."""

    path: Path


@dataclass(frozen=True)
class SandboxExclusions:
    """Placement of the section generated from rule set sandbox exclusions."""


InstructionSource = InstructionBlock | InstructionFile | SandboxExclusions


@dataclass(frozen=True)
class InstructionSet:
    """A named, composable group of instruction blocks."""

    name: str
    blocks: tuple[InstructionSource, ...]
    harnesses: tuple[InstructionHarness, ...] = ("codex", "claude")

    def __post_init__(self) -> None:
        checks.string(self.name, "instruction set name")
        checks.instances(
            self.blocks,
            (InstructionBlock, InstructionFile, SandboxExclusions),
            f"instruction set {self.name!r} blocks",
        )
        checks.strings(self.harnesses, f"instruction set {self.name!r} harnesses")
        if not self.harnesses:
            raise ValueError(f"instruction set {self.name!r} requires a harness")
        for harness in self.harnesses:
            checks.one_of(
                harness,
                get_args(InstructionHarness),
                f"instruction set {self.name!r} harness",
            )


def instructions(
    name: str,
    *blocks: InstructionSource,
    harnesses: tuple[InstructionHarness, ...] = ("codex", "claude"),
) -> InstructionSet:
    return InstructionSet(name=name, blocks=blocks, harnesses=harnesses)


def block(title: str, body: str) -> InstructionBlock:
    return InstructionBlock(title=title, body=body.strip())


def markdown(path: str | Path) -> InstructionFile:
    return InstructionFile(Path(path))


def sandbox_exclusions() -> SandboxExclusions:
    return SandboxExclusions()
