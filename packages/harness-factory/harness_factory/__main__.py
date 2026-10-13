"""Command-line smoke renderer for harness_factory."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from harness_factory.adapters import ClaudeAdapter, CodexAdapter
from harness_factory.models import (
    Environment,
    EnvVar,
    Mode,
    SandboxPolicy,
    ToolServer,
    TrustedProject,
)
from harness_factory.serializers import dumps_toml


def main() -> None:
    parser = argparse.ArgumentParser(description="Render sample harness configuration.")
    parser.add_argument("--harness", choices=["codex", "claude"], default="codex")
    parser.add_argument("--mode", default="webdev")
    args = parser.parse_args()

    environment = _sample_environment()
    mode = environment.mode_named(args.mode)
    adapter = CodexAdapter() if args.harness == "codex" else ClaudeAdapter()
    rendered = adapter.render(environment, mode)

    if args.harness == "codex":
        print(dumps_toml(rendered), end="")
    else:
        print(json.dumps(rendered, indent=2, sort_keys=True))


def _sample_environment() -> Environment:
    return Environment(
        name="work",
        reasoning_tier="best",
        sandbox=SandboxPolicy(mode="workspace-write", allow_tmp=True, network=False),
        env_vars=(
            EnvVar("API_TOKEN", source="host"),
            EnvVar("GH_CONFIG_DIR", value="/tmp/gh-codex"),
            EnvVar("GH_PROMPT_DISABLED", value="1"),
        ),
        base_mcp_servers=(
            ToolServer(
                name="openapi-tools",
                kind="stdio",
                command="uvx",
                args=("--from", "openapi-tools-mcp", "openapi-tools-mcp"),
            ),
        ),
        modes=(
            Mode(
                name="webdev",
                mcp_servers=(
                    ToolServer(
                        name="figma", kind="http", url="https://mcp.figma.com/mcp"
                    ),
                ),
                trusted_projects=(TrustedProject(Path("~/src/web-app")),),
            ),
        ),
    )


if __name__ == "__main__":
    main()
