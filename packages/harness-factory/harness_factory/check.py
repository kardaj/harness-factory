"""Validate generated harness home configs with their CLIs where possible."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import tomllib


@dataclass(frozen=True)
class CheckResult:
    name: str
    path: Path
    ok: bool
    detail: str


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate generated harness configs.")
    parser.add_argument("--output-dir", type=Path, default=Path("harness/output"))
    parser.add_argument("--skip-missing-cli", action="store_true")
    args = parser.parse_args()

    results = check_output_dir(args.output_dir, skip_missing_cli=args.skip_missing_cli)
    for result in results:
        status = "ok" if result.ok else "error"
        print(f"[{status}] {result.name}: {result.path} - {result.detail}")

    if not all(result.ok for result in results):
        raise SystemExit(1)


def check_output_dir(
    output_dir: Path, *, skip_missing_cli: bool = False
) -> list[CheckResult]:
    results: list[CheckResult] = [
        check_codex_home(codex_home, skip_missing_cli=skip_missing_cli)
        for codex_home in sorted((output_dir / "codex").glob("*"))
        if codex_home.is_dir()
    ]
    results.extend(
        check_claude_home(claude_home, skip_missing_cli=skip_missing_cli)
        for claude_home in sorted((output_dir / "claude").glob("*"))
        if claude_home.is_dir()
    )
    if not results:
        return [
            CheckResult(
                name="harness",
                path=output_dir,
                ok=False,
                detail="no generated harness homes found",
            )
        ]
    return results


def check_codex_home(home: Path, *, skip_missing_cli: bool = False) -> CheckResult:
    config_path = home / "config.toml"
    if not config_path.is_file():
        return CheckResult("codex", home, False, "missing config.toml")

    codex = shutil.which("codex")
    if codex is None:
        return _missing_cli_result("codex", home, skip_missing_cli)

    env = os.environ.copy()
    env["CODEX_HOME"] = str(home.resolve())
    try:
        result = subprocess.run(
            [codex, "--strict-config", "doctor"],
            env=env,
            text=True,
            capture_output=True,
            timeout=45,
            check=False,
        )
    finally:
        _cleanup_codex_runtime(home)
    output = result.stdout + result.stderr
    if (
        "config.toml parse        ok" in output
        or "config       config loaded" in output
    ):
        return CheckResult("codex", home, True, "codex doctor loaded config")
    return CheckResult(
        "codex",
        home,
        False,
        _summarize_process(result, redacted_values=_codex_env_values(config_path)),
    )


def check_claude_home(home: Path, *, skip_missing_cli: bool = False) -> CheckResult:
    settings_path = home / "settings.json"
    if not settings_path.is_file():
        return CheckResult("claude", home, False, "missing settings.json")

    try:
        data = json.loads(settings_path.read_text())
    except json.JSONDecodeError as error:
        return CheckResult("claude", home, False, f"invalid JSON: {error}")

    missing = [
        key for key in ("model", "effortLevel", "permissions") if key not in data
    ]
    if missing:
        return CheckResult("claude", home, False, f"missing keys: {', '.join(missing)}")

    invalid_settings_keys = [
        key
        for key in ("personality", "mcpServers", "agents", "_harnessFactory")
        if key in data
    ]
    if invalid_settings_keys:
        return CheckResult(
            "claude",
            home,
            False,
            f"settings contains non-settings keys: {', '.join(invalid_settings_keys)}",
        )

    env = data.get("env", {})
    if not isinstance(env, dict) or any(
        key in env for key in ("set", "inherit", "include")
    ):
        return CheckResult("claude", home, False, "env must be a flat string map")
    non_string_env = [key for key, value in env.items() if not isinstance(value, str)]
    if non_string_env:
        return CheckResult(
            "claude",
            home,
            False,
            f"env values must be strings: {', '.join(non_string_env)}",
        )

    mcp_result = _check_claude_mcp_config(home)
    if mcp_result is not None:
        return mcp_result

    agent_result = _check_claude_agent_files(home)
    if agent_result is not None:
        return agent_result

    claude = shutil.which("claude")
    if claude is None:
        return _missing_cli_result("claude", home, skip_missing_cli)

    command = [claude, "--settings", str(settings_path)]
    mcp_config_path = home / ".mcp.json"
    if mcp_config_path.is_file():
        command.extend(["--mcp-config", str(mcp_config_path), "--strict-mcp-config"])
    command.append("--help")
    result = subprocess.run(
        command,
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )
    if result.returncode == 0:
        return CheckResult("claude", home, True, "claude accepted settings/mcp config")
    return CheckResult(
        "claude",
        home,
        False,
        _summarize_process(result, redacted_values=tuple(env.values())),
    )


def _check_claude_mcp_config(home: Path) -> CheckResult | None:
    mcp_config_path = home / ".mcp.json"
    if not mcp_config_path.exists():
        return None
    try:
        data = json.loads(mcp_config_path.read_text())
    except json.JSONDecodeError as error:
        return CheckResult(
            "claude", mcp_config_path, False, f"invalid MCP JSON: {error}"
        )
    if not isinstance(data.get("mcpServers"), dict):
        return CheckResult(
            "claude", mcp_config_path, False, "missing mcpServers object"
        )
    return None


def _check_claude_agent_files(home: Path) -> CheckResult | None:
    for agent_path in sorted((home / "agents").glob("*.json")):
        return CheckResult(
            "claude",
            agent_path,
            False,
            "Claude subagents must be Markdown files, not JSON",
        )
    for agent_path in sorted((home / "agents").glob("*.md")):
        content = agent_path.read_text()
        if not content.startswith("---\n"):
            return CheckResult(
                "claude",
                agent_path,
                False,
                "agent is missing YAML frontmatter",
            )
        _, frontmatter, body = content.split("---", 2)
        missing = [key for key in ("name:", "description:") if key not in frontmatter]
        if missing:
            return CheckResult(
                "claude",
                agent_path,
                False,
                "agent frontmatter missing: "
                + ", ".join(key.rstrip(":") for key in missing),
            )
        if not body.strip():
            return CheckResult("claude", agent_path, False, "agent body is empty")
    return None


def _missing_cli_result(name: str, home: Path, skip_missing_cli: bool) -> CheckResult:
    if skip_missing_cli:
        return CheckResult(name, home, True, f"{name} CLI missing; skipped")
    return CheckResult(name, home, False, f"{name} CLI not found")


def _summarize_process(
    result: subprocess.CompletedProcess[str], *, redacted_values: tuple[str, ...] = ()
) -> str:
    process_output = result.stderr or result.stdout
    for value in redacted_values:
        if value:
            process_output = process_output.replace(value, "<redacted>")
    output = process_output.strip().splitlines()
    if not output:
        return f"command exited {result.returncode}"
    return f"command exited {result.returncode}: {output[0]}"


def _codex_env_values(config_path: Path) -> tuple[str, ...]:
    try:
        with config_path.open("rb") as config_file:
            config = tomllib.load(config_file)
    except (OSError, tomllib.TOMLDecodeError):
        return ()
    shell_environment = config.get("shell_environment_policy", {})
    if not isinstance(shell_environment, dict):
        return ()
    values = shell_environment.get("set", {})
    if not isinstance(values, dict):
        return ()
    return tuple(value for value in values.values() if isinstance(value, str))


def _cleanup_codex_runtime(home: Path) -> None:
    for relative_path in ("tmp",):
        path = home / relative_path
        if path.exists():
            shutil.rmtree(path)


if __name__ == "__main__":
    try:
        main()
    except subprocess.TimeoutExpired as error:
        print(f"[error] command timed out: {' '.join(error.cmd)}", file=sys.stderr)
        raise SystemExit(1) from error
