import io
import json
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from harness_manifest.__main__ import main


class CheckerTests(unittest.TestCase):
    def check(self, arguments, stdin=""):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch("sys.stdin", io.StringIO(stdin)),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            status = main(["check", *arguments])
        self.assertEqual(stdout.getvalue(), "")
        return status, stderr.getvalue()

    def test_stdin_json_and_explicit_dash(self):
        for arguments in ([], ["-"]):
            self.assertEqual(
                self.check(arguments, '{"schema_version": 3, "name": "cli"}'), (0, "")
            )

    def test_json_errors_include_all_manifest_validations(self):
        valid = {"schema_version": 3, "name": "cli"}
        for data, message in (
            ("{", "not valid JSON"),
            (json.dumps({**valid, "schema_version": 99}), "unsupported"),
            (json.dumps({**valid, "extra": True}), "unknown fields"),
            (
                json.dumps({**valid, "vars": ["TOKEN"], "optional_vars": ["TOKEN"]}),
                "must not overlap",
            ),
            (
                json.dumps({**valid, "rules": {"name": "cli", "rules": []}}),
                "omit rules",
            ),
            (
                json.dumps(
                    {
                        **valid,
                        "rules": {
                            "name": "cli",
                            "sandbox_excluded_commands": ["cli"],
                            "sandbox_exclusion_reason": "host",
                        },
                    }
                ),
                "must end in",
            ),
        ):
            with self.subTest(message=message):
                status, stderr = self.check([], data)
                self.assertEqual(status, 1)
                self.assertIn(message, stderr)
                self.assertNotIn("Traceback", stderr)

    def test_toml_path_uses_loader_and_reports_io_and_validation_errors(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "tool-manifest.toml"
            for text, message in (
                ('schema_version = 3\nname = "cli"\n', None),
                ('schema_version = 3\nname = "cli"\n[rules]\n', "omit rules"),
                ("schema_version = 3\n", "explicit name"),
                ('schema_version = 3\nname = "cli"\nextra = true\n', "unknown fields"),
                ("not toml =", "invalid TOML"),
            ):
                path.write_text(text)
                status, stderr = self.check([str(path)])
                if message is None:
                    self.assertEqual((status, stderr), (0, ""))
                else:
                    self.assertEqual(status, 1)
                    self.assertIn(message, stderr)
                    self.assertIn(str(path), stderr)
            path.unlink()
            status, stderr = self.check([str(path)])
            self.assertEqual(status, 1)
            self.assertIn(str(path), stderr)

    def test_module_entrypoint_sets_exit_status(self):
        for text, status in (('{"schema_version": 3, "name": "cli"}', 0), ("{}", 1)):
            result = subprocess.run(
                [sys.executable, "-m", "harness_manifest", "check"],
                input=text,
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, status)
            self.assertEqual(result.stdout, "")
            self.assertEqual(bool(result.stderr), bool(status))
