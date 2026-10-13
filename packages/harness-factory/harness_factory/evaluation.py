"""Evaluate working-tree harness policy in an existing repository."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Iterable, TextIO

from harness_factory.adapters import ClaudeAdapter, CodexAdapter
from harness_factory.models import Environment, HarnessName

UV_RUN_PATTERN = re.compile(
    r"(?:^|(?:bash|zsh|sh)?\s*-lc\s+['\"])(?:exec\s+)?uv run --active(?:\s|$)"
)
UV_HOST_PATTERN = re.compile(
    r"(?:^|(?:bash|zsh|sh)?\s*-lc\s+['\"])(?:exec\s+)?uv-host run(?:\s|$)"
)
DIRECT_PYTHON_PATTERN = re.compile(
    r"(?:^|(?:bash|zsh|sh)?\s*-lc\s+['\"])(?:exec\s+)?"
    r"(?:python(?:3(?:\.\d+)?)?|pytest|ruff|pip(?:3)?)(?:\s|$)"
)
DEVCONTAINER_PATTERN = re.compile(
    r"\[uv\]\[devcontainer\]\s+(?:Starting|Reusing|Running)", re.IGNORECASE
)


@dataclass(frozen=True)
class EvaluationSummary:
    """Machine-readable outcome derived from a harness JSONL trace."""

    harness: str
    model: str
    process_exit_code: int
    event_count: int
    commands: tuple[str, ...]
    used_uv_run_active: bool
    used_uv_host: bool
    used_direct_python_entrypoint: bool
    devcontainer_expected: bool
    devcontainer_observed: bool
    workspace_changed: bool
    workspace_status_before: tuple[str, ...]
    workspace_status_after: tuple[str, ...]
    final_message: str | None
    expectations_met: bool


@dataclass(frozen=True)
class EvaluationRequest:
    """Inputs for a single reusable harness evaluation."""

    harness: HarnessName
    environment: Environment
    workspace: Path
    source_home: Path
    wrapper_dir: Path
    executable: str | Path
    model: str
    reasoning: str
    prompt: str
    trace_path: Path | None = None
    expect_uv: bool = False
    expect_clean_worktree: bool = False
    set_claude_config_dir: bool = False


def evaluate(request: EvaluationRequest) -> EvaluationSummary:
    """Run a harness evaluation using caller-supplied paths and policy."""

    workspace = request.workspace.expanduser().resolve()
    if not workspace.is_dir():
        raise ValueError(f"workspace is not a directory: {workspace}")
    source_home = request.source_home.expanduser().resolve()
    wrapper_dir = request.wrapper_dir.expanduser().resolve()
    executable = Path(request.executable).expanduser()
    if not executable.is_absolute():
        executable = executable.resolve()

    if request.harness == "claude" and request.reasoning == "ultra":
        raise ValueError("Claude supports reasoning levels through `max`, not `ultra`")
    _validate_executable(wrapper_dir / "uv", "managed uv wrapper")
    _validate_executable(wrapper_dir / "uv-host", "managed uv-host escape hatch")
    _validate_executable(executable, f"{request.harness} executable")

    status_before = workspace_status(workspace)
    with TemporaryDirectory(prefix="harness-eval-") as temporary:
        temporary_root = Path(temporary)
        zdotdir = temporary_root / "zsh"
        if request.harness == "codex":
            policy_home = temporary_root / "codex-home"
            prepare_codex_home(
                environment=request.environment,
                codex_home=policy_home,
                source_codex_home=source_home,
                zdotdir=zdotdir,
                wrapper_dir=wrapper_dir,
            )
            command = codex_command(
                codex=str(executable),
                workspace=workspace,
                model=request.model,
                reasoning=request.reasoning,
                prompt=request.prompt,
            )
        else:
            policy_home = temporary_root / "claude-policy"
            prepare_claude_policy(
                environment=request.environment,
                policy_home=policy_home,
                zdotdir=zdotdir,
                wrapper_dir=wrapper_dir,
            )
            verify_claude_auth(
                str(executable),
                source_home,
                set_config_dir=request.set_claude_config_dir,
            )
            command = claude_command(
                claude=str(executable),
                policy_home=policy_home,
                model=request.model,
                reasoning=request.reasoning,
                prompt=request.prompt,
            )
        verify_wrapper_resolution(workspace, zdotdir, wrapper_dir / "uv")
        print(
            f"[harness-eval] {request.environment.name}/{request.harness} policy -> {workspace}",
            file=sys.stderr,
        )
        events, process_exit_code = stream_harness(
            command,
            harness=request.harness,
            workspace=workspace,
            policy_home=policy_home,
            source_home=source_home,
            set_claude_config_dir=request.set_claude_config_dir,
            zdotdir=zdotdir,
            wrapper_dir=wrapper_dir,
            trace_path=request.trace_path,
        )

    status_after = workspace_status(workspace)
    return summarize_evaluation(
        events,
        harness=request.harness,
        model=request.model,
        process_exit_code=process_exit_code,
        status_before=status_before,
        status_after=status_after,
        devcontainer_expected=has_supported_devcontainer(workspace),
        expect_uv=request.expect_uv,
        expect_clean_worktree=request.expect_clean_worktree,
    )


def prepare_codex_home(
    *,
    environment: Environment,
    codex_home: Path,
    source_codex_home: Path,
    zdotdir: Path,
    wrapper_dir: Path,
) -> None:
    """Materialize non-secret policy plus a private, temporary auth copy."""

    source_auth = source_codex_home / "auth.json"
    if not source_auth.is_file():
        raise RuntimeError(f"Codex authentication file not found: {source_auth}")

    codex_home.mkdir(mode=0o700, parents=True)
    codex_home.chmod(0o700)
    CodexAdapter().write_policy_preview(environment, codex_home)
    managed_path = f"{wrapper_dir}:{os.environ['PATH']}"
    config_path = codex_home / "config.toml"
    config_path.write_text(
        "[shell_environment_policy]\n"
        'inherit = "core"\n\n'
        "[shell_environment_policy.set]\n"
        f"PATH = {json.dumps(managed_path)}\n"
        f"ZDOTDIR = {json.dumps(str(zdotdir))}\n",
        encoding="utf-8",
    )
    config_path.chmod(0o600)
    destination_auth = codex_home / "auth.json"
    shutil.copyfile(source_auth, destination_auth)
    destination_auth.chmod(0o600)

    prepare_zsh_policy(zdotdir, wrapper_dir)


def prepare_claude_policy(
    *,
    environment: Environment,
    policy_home: Path,
    zdotdir: Path,
    wrapper_dir: Path,
) -> None:
    """Materialize current Claude policy without copying credentials or runtime state."""

    policy_home.mkdir(mode=0o700, parents=True)
    policy_home.chmod(0o700)
    ClaudeAdapter().write_policy_preview(environment, policy_home)
    settings_path = policy_home / "settings.json"
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    settings["env"] = {
        "PATH": f"{wrapper_dir}:{os.environ['PATH']}",
        "ZDOTDIR": str(zdotdir),
    }
    settings_path.write_text(
        json.dumps(settings, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    settings_path.chmod(0o600)
    prepare_zsh_policy(zdotdir, wrapper_dir)


def prepare_zsh_policy(zdotdir: Path, wrapper_dir: Path) -> None:
    """Create login and non-login startup files that select the managed wrapper."""

    zdotdir.mkdir(mode=0o700, parents=True)
    zdotdir.chmod(0o700)
    for filename in (".zshenv", ".zprofile"):
        profile = zdotdir / filename
        profile.write_text(f'export PATH="{wrapper_dir}:$PATH"\n', encoding="utf-8")
        profile.chmod(0o600)


def verify_claude_auth(claude: str, source_home: Path, *, set_config_dir: bool) -> None:
    """Fail before the model turn if the selected Claude home is not authenticated."""

    environment = os.environ.copy()
    if set_config_dir:
        environment["CLAUDE_CONFIG_DIR"] = str(source_home)
    else:
        environment.pop("CLAUDE_CONFIG_DIR", None)
    result = subprocess.run(
        [claude, "auth", "status"],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise RuntimeError(f"Claude auth preflight failed: {detail}")
    status = json.loads(result.stdout)
    if not status.get("loggedIn"):
        raise RuntimeError(f"Claude home is not authenticated: {source_home}")


def verify_wrapper_resolution(
    workspace: Path, zdotdir: Path, expected_wrapper: Path
) -> None:
    """Fail before the model turn if login zsh would bypass the managed wrapper."""

    environment = os.environ.copy()
    environment["ZDOTDIR"] = str(zdotdir)
    result = subprocess.run(
        ["zsh", "-lc", "command -v uv"],
        cwd=workspace,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    resolved = Path(result.stdout.strip()).resolve()
    if resolved != expected_wrapper.resolve():
        raise RuntimeError(
            f"managed uv wrapper did not resolve first: {resolved} != {expected_wrapper}"
        )


def codex_command(
    *,
    codex: str,
    workspace: Path,
    model: str,
    reasoning: str,
    prompt: str,
) -> list[str]:
    """Build the non-interactive Codex invocation."""

    return [
        codex,
        "exec",
        "--ephemeral",
        "--strict-config",
        "--disable",
        "shell_snapshot",
        "--approve-for-me",
        "--json",
        "--model",
        model,
        "--config",
        f'model_reasoning_effort="{reasoning}"',
        "--cd",
        str(workspace),
        prompt,
    ]


def claude_command(
    *,
    claude: str,
    policy_home: Path,
    model: str,
    reasoning: str,
    prompt: str,
) -> list[str]:
    """Build the non-interactive Claude invocation."""

    instructions = (policy_home / "CLAUDE.md").read_text(encoding="utf-8")
    return [
        claude,
        "--print",
        "--output-format",
        "stream-json",
        "--verbose",
        "--no-session-persistence",
        "--safe-mode",
        "--settings",
        str(policy_home / "settings.json"),
        "--strict-mcp-config",
        "--mcp-config",
        '{"mcpServers":{}}',
        "--permission-mode",
        "acceptEdits",
        "--model",
        model,
        "--effort",
        reasoning,
        "--append-system-prompt",
        instructions,
        prompt,
    ]


def stream_harness(
    command: list[str],
    *,
    harness: str,
    workspace: Path,
    policy_home: Path,
    source_home: Path,
    set_claude_config_dir: bool,
    zdotdir: Path,
    wrapper_dir: Path,
    trace_path: Path | None,
) -> tuple[list[dict[str, Any]], int]:
    """Run a harness, stream concise progress, and optionally retain raw JSONL."""

    environment = os.environ.copy()
    if harness == "codex":
        environment["CODEX_HOME"] = str(policy_home)
    elif set_claude_config_dir:
        environment["CLAUDE_CONFIG_DIR"] = str(source_home)
    else:
        environment.pop("CLAUDE_CONFIG_DIR", None)
    environment["ZDOTDIR"] = str(zdotdir)
    environment["PATH"] = f"{wrapper_dir}:{environment['PATH']}"
    trace: TextIO | None = None
    if trace_path is not None:
        trace_path = trace_path.expanduser().resolve()
        trace_path.parent.mkdir(parents=True, exist_ok=True)
        trace = trace_path.open("w", encoding="utf-8")

    events: list[dict[str, Any]] = []
    process: subprocess.Popen[str] | None = None
    try:
        process = subprocess.Popen(
            command,
            cwd=workspace,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            text=True,
        )
        if process.stdout is None:  # pragma: no cover - guaranteed by PIPE
            raise RuntimeError("harness stdout pipe was not created")
        for line in process.stdout:
            if trace is not None:
                trace.write(line)
                trace.flush()
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                print(f"[harness-eval][{harness}] {line.rstrip()}", file=sys.stderr)
                continue
            if isinstance(event, dict):
                events.append(event)
                print_event(event, harness)
        return events, process.wait()
    except KeyboardInterrupt:
        if process is not None:
            process.terminate()
            process.wait()
        raise
    finally:
        if trace is not None:
            trace.close()


def print_event(event: dict[str, Any], harness: str) -> None:
    """Print only useful human-facing progress from a harness JSONL event."""

    if harness == "claude":
        print_claude_event(event)
        return
    if event.get("type") != "item.completed":
        return
    item = event.get("item")
    if not isinstance(item, dict):
        return
    if item.get("type") == "command_execution":
        command = item.get("command", "")
        exit_code = item.get("exit_code")
        print(f"[harness-eval][command][{exit_code}] {command}", file=sys.stderr)
    elif item.get("type") == "agent_message":
        text = item.get("text")
        if isinstance(text, str):
            print(f"[harness-eval][agent] {text}", file=sys.stderr)


def print_claude_event(event: dict[str, Any]) -> None:
    """Print concise progress from a Claude stream-json event."""

    if event.get("type") == "assistant":
        for block in _claude_message_blocks(event):
            if block.get("type") == "text" and isinstance(block.get("text"), str):
                print(f"[harness-eval][agent] {block['text']}", file=sys.stderr)
            elif block.get("type") == "tool_use" and block.get("name") == "Bash":
                tool_input = block.get("input")
                if isinstance(tool_input, dict) and isinstance(
                    tool_input.get("command"), str
                ):
                    print(
                        f"[harness-eval][command] {tool_input['command']}",
                        file=sys.stderr,
                    )
    elif event.get("type") == "result" and isinstance(event.get("result"), str):
        print(f"[harness-eval][agent] {event['result']}", file=sys.stderr)


def summarize_evaluation(
    events: Iterable[dict[str, Any]],
    *,
    harness: str,
    model: str,
    process_exit_code: int,
    status_before: tuple[str, ...],
    status_after: tuple[str, ...],
    devcontainer_expected: bool,
    expect_uv: bool,
    expect_clean_worktree: bool,
) -> EvaluationSummary:
    """Derive stable evaluation signals from Codex events."""

    event_list = tuple(events)
    commands, command_output, final_message = trace_signals(event_list, harness)

    used_uv = any(UV_RUN_PATTERN.search(command) for command in commands)
    used_uv_host = any(UV_HOST_PATTERN.search(command) for command in commands)
    used_direct_python = any(
        DIRECT_PYTHON_PATTERN.search(command) for command in commands
    )
    workspace_changed = status_before != status_after
    expectations_met = process_exit_code == 0
    if expect_uv:
        expectations_met = (
            expectations_met and used_uv and not used_uv_host and not used_direct_python
        )
        if devcontainer_expected:
            expectations_met = expectations_met and bool(
                DEVCONTAINER_PATTERN.search("\n".join(command_output))
            )
    if expect_clean_worktree:
        expectations_met = expectations_met and not workspace_changed

    return EvaluationSummary(
        harness=harness,
        model=model,
        process_exit_code=process_exit_code,
        event_count=len(event_list),
        commands=tuple(commands),
        used_uv_run_active=used_uv,
        used_uv_host=used_uv_host,
        used_direct_python_entrypoint=used_direct_python,
        devcontainer_expected=devcontainer_expected,
        devcontainer_observed=bool(
            DEVCONTAINER_PATTERN.search("\n".join(command_output))
        ),
        workspace_changed=workspace_changed,
        workspace_status_before=status_before,
        workspace_status_after=status_after,
        final_message=final_message,
        expectations_met=expectations_met,
    )


def trace_signals(
    events: tuple[dict[str, Any], ...], harness: str
) -> tuple[list[str], list[str], str | None]:
    """Extract comparable commands, output, and final text from native traces."""

    if harness == "claude":
        return claude_trace_signals(events)

    commands: list[str] = []
    command_output: list[str] = []
    final_message: str | None = None
    for event in events:
        if event.get("type") != "item.completed":
            continue
        item = event.get("item")
        if not isinstance(item, dict):
            continue
        if item.get("type") == "command_execution":
            command = item.get("command")
            output = item.get("aggregated_output")
            if isinstance(command, str):
                commands.append(command)
            if isinstance(output, str):
                command_output.append(output)
        elif item.get("type") == "agent_message" and isinstance(item.get("text"), str):
            final_message = item["text"]
    return commands, command_output, final_message


def claude_trace_signals(
    events: tuple[dict[str, Any], ...],
) -> tuple[list[str], list[str], str | None]:
    """Extract Bash calls and tool results from Claude stream-json."""

    commands: list[str] = []
    command_output: list[str] = []
    final_message: str | None = None
    for event in events:
        if event.get("type") == "assistant":
            for block in _claude_message_blocks(event):
                if block.get("type") != "tool_use" or block.get("name") != "Bash":
                    continue
                tool_input = block.get("input")
                if isinstance(tool_input, dict) and isinstance(
                    tool_input.get("command"), str
                ):
                    commands.append(tool_input["command"])
        elif event.get("type") == "user":
            for block in _claude_message_blocks(event):
                if block.get("type") == "tool_result":
                    command_output.extend(_claude_text_values(block.get("content")))
        elif event.get("type") == "result" and isinstance(event.get("result"), str):
            final_message = event["result"]
    return commands, command_output, final_message


def _claude_message_blocks(event: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    message = event.get("message")
    if not isinstance(message, dict) or not isinstance(message.get("content"), list):
        return ()
    return tuple(block for block in message["content"] if isinstance(block, dict))


def _claude_text_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list):
        return []
    return [
        block["text"]
        for block in value
        if isinstance(block, dict) and isinstance(block.get("text"), str)
    ]


def workspace_status(workspace: Path) -> tuple[str, ...]:
    """Return a deterministic Git status snapshot without changing repository state."""

    result = subprocess.run(
        [
            "git",
            "-C",
            str(workspace),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return tuple(result.stdout.splitlines())


def has_supported_devcontainer(workspace: Path) -> bool:
    """Mirror the managed wrapper's supported Dev Container discovery shapes."""

    direct_candidates = (
        workspace / ".devcontainer/devcontainer.json",
        workspace / ".devcontainer.json",
        workspace / ".devcontainer/base/devcontainer.json",
    )
    if any(candidate.is_file() for candidate in direct_candidates):
        return True
    return any((workspace / ".devcontainer").glob("*/devcontainer.json"))


def _validate_executable(path: Path, label: str) -> None:
    if not path.is_file() or not os.access(path, os.X_OK):
        raise RuntimeError(f"{label} is not executable: {path}")
