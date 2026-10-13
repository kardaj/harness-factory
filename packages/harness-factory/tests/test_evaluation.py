import json
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from harness_factory import EvaluationRequest, evaluate
from harness_factory.evaluation import (
    claude_command,
    codex_command,
    prepare_claude_policy,
    prepare_codex_home,
    summarize_evaluation,
)
from harness_factory import Environment, RuleSet, allow, block, instructions, shell


class HarnessEvaluationTests(unittest.TestCase):
    def test_public_evaluator_orchestrates_explicit_inputs(self) -> None:
        environment = Environment(name="test")
        events = [
            {
                "type": "item.completed",
                "item": {
                    "type": "command_execution",
                    "command": "uv run --active pytest",
                    "aggregated_output": "1 passed",
                    "exit_code": 0,
                },
            }
        ]
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            source_home = root / "source"
            source_home.mkdir()
            wrapper_dir = root / "wrapper"
            wrapper_dir.mkdir()
            executable = root / "codex"
            for path in (wrapper_dir / "uv", wrapper_dir / "uv-host", executable):
                path.write_text("#!/bin/sh\n", encoding="utf-8")
                path.chmod(0o700)

            with (
                patch(
                    "harness_factory.evaluation.workspace_status",
                    side_effect=[(), ()],
                ),
                patch("harness_factory.evaluation.prepare_codex_home"),
                patch("harness_factory.evaluation.verify_wrapper_resolution"),
                patch(
                    "harness_factory.evaluation.stream_harness",
                    return_value=(events, 0),
                ),
                patch(
                    "harness_factory.evaluation.has_supported_devcontainer",
                    return_value=False,
                ),
            ):
                summary = evaluate(
                    EvaluationRequest(
                        harness="codex",
                        environment=environment,
                        workspace=workspace,
                        source_home=source_home,
                        wrapper_dir=wrapper_dir,
                        executable=executable,
                        model="gpt-6-sol",
                        reasoning="medium",
                        prompt="Run tests.",
                        expect_uv=True,
                        expect_clean_worktree=True,
                    )
                )

        self.assertTrue(summary.expectations_met)
        self.assertEqual(summary.commands, ("uv run --active pytest",))

    def test_temporary_home_contains_policy_and_private_auth_only(self) -> None:
        environment = Environment(
            name="test",
            instruction_sets=(instructions("shared", block("Workflow", "Use uv.")),),
            rules=(RuleSet(name="test", rules=(allow(shell("uv", "run")),)),),
        )
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_home = root / "source"
            source_home.mkdir()
            (source_home / "auth.json").write_text(
                json.dumps({"token": "secret"}), encoding="utf-8"
            )
            codex_home = root / "preview"
            zdotdir = root / "zsh"
            wrapper_dir = Path("/managed/uv")

            prepare_codex_home(
                environment=environment,
                codex_home=codex_home,
                source_codex_home=source_home,
                zdotdir=zdotdir,
                wrapper_dir=wrapper_dir,
            )

            self.assertEqual(
                (codex_home / "AGENTS.md").read_text(), "## Workflow\n\nUse uv.\n"
            )
            self.assertTrue((codex_home / "rules/test.rules").is_file())
            self.assertEqual(
                (codex_home / "config.toml").read_text().splitlines()[:4],
                [
                    "[shell_environment_policy]",
                    'inherit = "core"',
                    "",
                    "[shell_environment_policy.set]",
                ],
            )
            self.assertIn(
                'PATH = "/managed/uv:',
                (codex_home / "config.toml").read_text(),
            )
            self.assertIn(
                f'ZDOTDIR = "{zdotdir}"',
                (codex_home / "config.toml").read_text(),
            )
            self.assertEqual(
                stat.S_IMODE((codex_home / "auth.json").stat().st_mode), 0o600
            )
            self.assertEqual(
                (zdotdir / ".zprofile").read_text(),
                'export PATH="/managed/uv:$PATH"\n',
            )
            self.assertEqual(
                (zdotdir / ".zshenv").read_text(),
                'export PATH="/managed/uv:$PATH"\n',
            )

    def test_codex_command_is_ephemeral_and_selects_model(self) -> None:
        command = codex_command(
            codex="codex",
            workspace=Path("/repo"),
            model="gpt-6-sol",
            reasoning="medium",
            prompt="Run the test.",
        )

        self.assertEqual(
            command[:7],
            [
                "codex",
                "exec",
                "--ephemeral",
                "--strict-config",
                "--disable",
                "shell_snapshot",
                "--approve-for-me",
            ],
        )
        self.assertIn("--json", command)
        self.assertIn('model_reasoning_effort="medium"', command)
        self.assertEqual(command[-3:], ["--cd", "/repo", "Run the test."])

    def test_summary_checks_uv_contract_and_workspace_integrity(self) -> None:
        events = [
            {
                "type": "item.completed",
                "item": {
                    "type": "command_execution",
                    "command": "uv run --active pytest tests/test_utils.py",
                    "aggregated_output": (
                        "[uv][devcontainer] Reusing running Dev Container\n1 passed"
                    ),
                    "exit_code": 0,
                },
            },
            {
                "type": "item.completed",
                "item": {"type": "agent_message", "text": "The test passed."},
            },
        ]

        summary = summarize_evaluation(
            events,
            harness="codex",
            model="gpt-6-sol",
            process_exit_code=0,
            status_before=(),
            status_after=(),
            devcontainer_expected=True,
            expect_uv=True,
            expect_clean_worktree=True,
        )

        self.assertTrue(summary.expectations_met)
        self.assertTrue(summary.used_uv_run_active)
        self.assertTrue(summary.devcontainer_observed)
        self.assertFalse(summary.used_uv_host)
        self.assertEqual(summary.final_message, "The test passed.")

    def test_summary_requires_container_evidence_for_container_project(self) -> None:
        summary = summarize_evaluation(
            [
                {
                    "type": "item.completed",
                    "item": {
                        "type": "command_execution",
                        "command": "uv run --active pytest tests/test_utils.py",
                        "aggregated_output": "1 passed",
                        "exit_code": 0,
                    },
                }
            ],
            harness="codex",
            model="gpt-6-sol",
            process_exit_code=0,
            status_before=(),
            status_after=(),
            devcontainer_expected=True,
            expect_uv=True,
            expect_clean_worktree=False,
        )

        self.assertFalse(summary.expectations_met)
        self.assertTrue(summary.devcontainer_expected)
        self.assertFalse(summary.devcontainer_observed)

    def test_summary_rejects_host_escape_and_direct_python(self) -> None:
        for command in (
            "uv-host run pytest tests/test_utils.py",
            "zsh -lc 'python -m pytest tests/test_utils.py'",
        ):
            with self.subTest(command=command):
                summary = summarize_evaluation(
                    [
                        {
                            "type": "item.completed",
                            "item": {
                                "type": "command_execution",
                                "command": command,
                                "aggregated_output": "",
                                "exit_code": 0,
                            },
                        }
                    ],
                    harness="codex",
                    model="gpt-6-sol",
                    process_exit_code=0,
                    status_before=(),
                    status_after=(),
                    devcontainer_expected=False,
                    expect_uv=True,
                    expect_clean_worktree=False,
                )

                self.assertFalse(summary.expectations_met)

    def test_claude_policy_and_command_use_explicit_safe_mode_inputs(self) -> None:
        environment = Environment(
            name="test",
            instruction_sets=(instructions("shared", block("Workflow", "Use uv.")),),
            rules=(RuleSet(name="test", rules=(allow(shell("uv", "run")),)),),
        )
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy_home = root / "policy"
            zdotdir = root / "zsh"
            prepare_claude_policy(
                environment=environment,
                policy_home=policy_home,
                zdotdir=zdotdir,
                wrapper_dir=Path("/managed/uv"),
            )

            command = claude_command(
                claude="claude",
                policy_home=policy_home,
                model="opus",
                reasoning="medium",
                prompt="Run the test.",
            )
            settings = json.loads((policy_home / "settings.json").read_text())

            self.assertIn("--safe-mode", command)
            self.assertIn("--no-session-persistence", command)
            self.assertIn("## Project Instructions", command[-2])
            self.assertEqual(command[-1], "Run the test.")
            self.assertTrue(settings["env"]["PATH"].startswith("/managed/uv:"))
            self.assertEqual(settings["env"]["ZDOTDIR"], str(zdotdir))

    def test_summary_extracts_claude_bash_and_devcontainer_output(self) -> None:
        events = [
            {
                "type": "assistant",
                "message": {
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "tool-1",
                            "name": "Bash",
                            "input": {
                                "command": "uv run --active pytest tests/test_utils.py"
                            },
                        }
                    ]
                },
            },
            {
                "type": "user",
                "message": {
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "tool-1",
                            "content": "[uv][devcontainer] Reusing repo\n5 passed",
                        }
                    ]
                },
            },
            {"type": "result", "result": "Five tests passed."},
        ]

        summary = summarize_evaluation(
            events,
            harness="claude",
            model="opus",
            process_exit_code=0,
            status_before=(),
            status_after=(),
            devcontainer_expected=True,
            expect_uv=True,
            expect_clean_worktree=True,
        )

        self.assertTrue(summary.expectations_met)
        self.assertEqual(
            summary.commands, ("uv run --active pytest tests/test_utils.py",)
        )
        self.assertTrue(summary.devcontainer_observed)
        self.assertEqual(summary.final_message, "Five tests passed.")


if __name__ == "__main__":
    unittest.main()
