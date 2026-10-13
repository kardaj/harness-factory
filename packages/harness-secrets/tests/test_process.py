import sys
import time
import traceback
import unittest
from unittest.mock import patch

from harness_secrets.process import (
    ExecutableUnavailable,
    OutputLimitExceeded,
    ProcessTimeout,
    child_environment,
    run,
)


class ProcessTests(unittest.TestCase):
    def command(self, source):
        return [sys.executable, "-c", source]

    def run_cli(self, source, *, timeout=15, **options):
        return run(
            self.command(source),
            environment=child_environment(),
            timeout=timeout,
            **options,
        )

    def test_returns_exit_code_and_separate_output_streams(self):
        result = self.run_cli(
            "import sys; print('manifest'); print('diagnostic', file=sys.stderr); sys.exit(3)"
        )
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, "manifest\n")
        self.assertEqual(result.stderr, "diagnostic\n")

    def test_stdin_is_closed_unless_input_text_is_supplied(self):
        source = "import sys; print(sys.stdin.read())"
        self.assertEqual(self.run_cli(source).stdout, "\n")
        self.assertEqual(self.run_cli(source, input_text="input").stdout, "input\n")

    def test_invalid_utf8_is_replaced(self):
        result = self.run_cli("import sys; sys.stdout.buffer.write(b'\\xff')")
        self.assertEqual(result.stdout, "\ufffd")

    def test_failure_messages_and_tracebacks_omit_output(self):
        secret = "test-private-output"
        for source, options, error in (
            (
                f"import time; print('{secret}', flush=True); time.sleep(30)",
                {"timeout": 0.2},
                ProcessTimeout,
            ),
            (f"print('{secret}', flush=True)", {"limit": 1}, OutputLimitExceeded),
        ):
            with self.subTest(source=source), self.assertRaises(error) as raised:
                self.run_cli(source, **options)
            self.assertNotIn(secret, str(raised.exception))
            self.assertNotIn(
                secret, "".join(traceback.format_exception(raised.exception))
            )

    def test_limits_combined_stdout_and_stderr(self):
        for source in (
            "import sys; sys.stdout.write('x' * 65)",
            "import sys; sys.stdout.write('x' * 32); sys.stderr.write('y' * 33)",
            "import sys; sys.stderr.write('y' * 65)",
        ):
            with (
                self.subTest(source=source),
                self.assertRaisesRegex(
                    OutputLimitExceeded, "output exceeded the limit"
                ),
            ):
                self.run_cli(source, limit=64)
        self.assertEqual(
            self.run_cli("print('x' * 63)", limit=64).stdout, "x" * 63 + "\n"
        )

    def test_timeout_includes_descendants_holding_pipes_open(self):
        started = time.monotonic()
        with self.assertRaisesRegex(ProcessTimeout, "timed out"):
            self.run_cli(
                "import subprocess; subprocess.Popen(['sleep', '30'])",
                timeout=0.2,
            )
        self.assertLess(time.monotonic() - started, 3)

    def test_timeout_when_child_closes_pipes_but_keeps_running(self):
        with self.assertRaisesRegex(ProcessTimeout, "timed out"):
            self.run_cli(
                "import os, time; os.close(1); os.close(2); time.sleep(30)",
                timeout=0.2,
            )

    def test_missing_executable_and_invalid_limits(self):
        with self.assertRaisesRegex(ExecutableUnavailable, "cannot be started"):
            run(["/nonexistent/cli"], environment=child_environment(), timeout=15)
        for limits in ({"timeout": 0}, {"limit": 0}):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                self.run_cli("", **limits)

    def test_cleanup_permission_race_preserves_result_and_original_failure(self):
        with patch("harness_secrets.process.os.killpg", side_effect=PermissionError):
            self.assertEqual(self.run_cli("print('manifest')").stdout, "manifest\n")
            self.assertEqual(self.run_cli("import sys; sys.exit(3)").returncode, 3)
            with self.assertRaisesRegex(ProcessTimeout, "timed out"):
                self.run_cli("import time; time.sleep(30)", timeout=0.2)
