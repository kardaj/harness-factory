import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from harness_factory import RuleSet, allow, shell
from harness_factory.projects import (
    ProjectOwner,
    ProjectPolicy,
    ProjectRepository,
    plan_project,
)

SOURCE = """schema_version = 1
name = "deployment"
[[rules]]
effect = "deny"
command = ["deploy"]
"""


class ProjectRuleSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / ".harness/guardrails.toml"
        self.source.parent.mkdir()
        self.source.write_text(SOURCE)
        self.policy = ProjectPolicy(
            "app",
            ("example/app",),
            rule_files=(Path(".harness/guardrails.toml"),),
            claude_rules="shared",
        )
        self.owner = ProjectOwner("test", "project-sync")
        self.repository = ProjectRepository(self.root, "example/app")

    def plan(self, policy=None):
        return plan_project(self.repository, policy or self.policy, owner=self.owner)

    def test_repository_source_renders_both_providers_and_reconciles_changes(self):
        self.plan().apply()
        self.assertIn(
            "Bash(deploy *)", (self.root / ".claude/settings.json").read_text()
        )
        self.assertIn(
            '"deploy"', (self.root / ".codex/rules/test-project.rules").read_text()
        )
        self.assertFalse(self.plan().changes)
        self.assertEqual(self.source.read_text(), SOURCE)
        self.source.write_text(SOURCE.replace("deploy", "publish"))
        self.plan().apply()
        text = (self.root / ".claude/settings.json").read_text()
        self.assertIn("Bash(publish *)", text)
        self.assertNotIn("Bash(deploy *)", text)

    def test_missing_invalid_and_symlinked_sources_fail_before_writes(self):
        self.source.unlink()
        with self.assertRaisesRegex(ValueError, "Missing project rule source"):
            self.plan()
        self.source.write_text("schema_version = 99")
        with self.assertRaisesRegex(ValueError, "schema_version"):
            self.plan()
        self.source.unlink()
        self.source.symlink_to(self.root / "elsewhere.toml")
        with self.assertRaisesRegex(ValueError, "symlinks"):
            self.plan()
        self.assertFalse((self.root / ".codex").exists())

    def test_paths_names_and_source_changes_are_validated(self):
        for paths in (
            (Path("../outside.toml"),),
            (Path("/outside.toml"),),
            ("rules.toml",),
            (Path("x.toml"), Path("x.toml")),
        ):
            with self.subTest(paths=paths), self.assertRaises(ValueError):
                replace(self.policy, rule_files=paths)
        with self.assertRaisesRegex(ValueError, "Duplicate project rule set names"):
            self.plan(
                replace(
                    self.policy,
                    rules=(RuleSet("deployment", (allow(shell("inspect")),)),),
                )
            )
        plan = self.plan()
        self.source.write_text(SOURCE.replace("deploy", "publish"))
        with self.assertRaisesRegex(ValueError, "source changed"):
            plan.apply()
        self.assertFalse((self.root / ".codex").exists())
