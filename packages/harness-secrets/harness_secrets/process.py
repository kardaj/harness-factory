"""Run trusted helper executables with bounded time, output, and environment.

Executables are taken from fixed absolute candidates rather than ``PATH`` and
must be regular files that only root or the current user can modify. Children
get a minimal environment, are killed with their process group when they
exceed their deadline or output limit, and their output is never included in
raised errors.
"""

from __future__ import annotations

import os
import selectors
import signal
import stat
import subprocess
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
BASE_ENV_VARS = ("HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE")
NETWORK_ENV_VARS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)
OUTPUT_LIMIT = 1024 * 1024


class ExecutableUnavailable(RuntimeError):
    """The executable is missing, untrusted, or cannot be started."""


class ProcessTimeout(RuntimeError):
    """The child exceeded its deadline and was killed."""


class OutputLimitExceeded(RuntimeError):
    """The child exceeded its output limit and was killed."""


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: str
    stderr: str


def trusted_executable(candidates: Iterable[str | Path]) -> str | None:
    """Return the resolved path of the first trusted executable candidate.

    A candidate is trusted when it resolves to an executable regular file that
    is owned by root or the current user and is not writable by group or
    others, in a directory with the same properties.
    """
    for candidate in candidates:
        path = Path(candidate)
        if not path.is_absolute():
            continue
        try:
            resolved = path.resolve(strict=True)
            if not _trusted(resolved, directory=False) or not _trusted(
                resolved.parent, directory=True
            ):
                continue
        except OSError:
            continue
        if os.access(resolved, os.X_OK):
            return str(resolved)
    return None


def trusted_file(path: str | Path) -> str | None:
    """Return the resolved path of a trusted regular file, or None.

    The file is held to the same ownership and permission rule as executables,
    without requiring it to be executable.
    """
    path = Path(path)
    if not path.is_absolute():
        return None
    try:
        resolved = path.resolve(strict=True)
        if _trusted(resolved, directory=False) and _trusted(
            resolved.parent, directory=True
        ):
            return str(resolved)
    except OSError:
        pass
    return None


def _trusted(path: Path, *, directory: bool) -> bool:
    status = path.stat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    return (
        kind(status.st_mode)
        and status.st_uid in (0, os.getuid())
        and not status.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    )


def child_environment(
    names: Iterable[str] = (), *, set_values: Mapping[str, str] | None = None
) -> dict[str, str]:
    """Return the base environment plus the named variables that are set."""
    environment = {"PATH": SYSTEM_PATH}
    for name in (*BASE_ENV_VARS, *names):
        if name in os.environ:
            environment[name] = os.environ[name]
    environment.update(set_values or {})
    return environment


def run(
    arguments: list[str],
    *,
    environment: Mapping[str, str],
    timeout: float,
    input_text: str | None = None,
    limit: int = OUTPUT_LIMIT,
) -> ProcessResult:
    """Run a child with a deadline and a combined stdout and stderr limit."""
    if timeout <= 0 or limit <= 0:
        raise ValueError("process limits must be positive")
    try:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL if input_text is None else subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(environment),
            start_new_session=True,
        )
    except OSError:
        raise ExecutableUnavailable(
            f"{Path(arguments[0]).name} cannot be started"
        ) from None
    deadline = time.monotonic() + timeout
    name = Path(arguments[0]).name
    try:
        stdout, stderr = _communicate(
            process,
            b"" if input_text is None else input_text.encode(),
            deadline=deadline,
            limit=limit,
        )
        try:
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise ProcessTimeout(f"{name} timed out") from None
    except BaseException:
        _kill(process)
        raise
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()
    return ProcessResult(
        process.returncode,
        stdout.decode(errors="replace"),
        stderr.decode(errors="replace"),
    )


def _communicate(
    process: subprocess.Popen[bytes], data: bytes, *, deadline: float, limit: int
) -> tuple[bytes, bytes]:
    outputs: dict[int, bytearray] = {}
    with selectors.DefaultSelector() as selector:
        if process.stdin is not None:
            if data:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE)
            else:
                process.stdin.close()
        for stream in (process.stdout, process.stderr):
            assert stream is not None
            outputs[stream.fileno()] = bytearray()
            selector.register(stream, selectors.EVENT_READ)
        written = 0
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProcessTimeout(f"{Path(str(process.args[0])).name} timed out")
            for key, _ in selector.select(remaining):
                stream = key.fileobj
                if stream is process.stdin:
                    try:
                        written += os.write(stream.fileno(), data[written:])
                    except BrokenPipeError:
                        written = len(data)
                    if written >= len(data):
                        selector.unregister(stream)
                        stream.close()
                    continue
                chunk = os.read(stream.fileno(), 65536)
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                outputs[stream.fileno()] += chunk
                if sum(len(output) for output in outputs.values()) > limit:
                    raise OutputLimitExceeded(
                        f"{Path(str(process.args[0])).name} output exceeded the limit"
                    )
    stdout, stderr = outputs.values()
    return bytes(stdout), bytes(stderr)


def _kill(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        process.kill()
    process.wait()
