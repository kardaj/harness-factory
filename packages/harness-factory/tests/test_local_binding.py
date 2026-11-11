import json
import tomllib
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from harness_factory import (
    ClaudeAdapter,
    CodexAdapter,
    Environment,
    HarnessScopedValue,
    SandboxPolicy,
    load_environments,
)
from harness_factory.projects import (
    ProjectOwner,
    ProjectPolicy,
    ProjectRepository,
    ProjectSandboxPolicy,
    plan_project,
)


class LocalBindingTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.owner = ProjectOwner("test", "test-sync")
        self.repository = ProjectRepository(self.root, "example/app")
        self.policy = ProjectPolicy(
            "app",
            ("example/app",),
            sandbox=ProjectSandboxPolicy(allow_local_binding=True),
        )

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def apply(self, policy=None, harnesses=("codex", "claude")):
        plan = plan_project(
            self.repository,
            policy or self.policy,
            owner=self.owner,
            harnesses=harnesses,
        )
        plan.apply()
        return plan

    def values(self):
        codex = tomllib.loads((self.root / ".codex/config.toml").read_text())
        claude = json.loads((self.root / ".claude/settings.local.json").read_text())
        return codex.get("features", {}).get("network_proxy", {}).get(
            "allow_local_binding"
        ), claude.get("sandbox", {}).get("network", {}).get("allowLocalBinding")

    def test_global_true_false_and_unmanaged_have_provider_specific_shapes(self):
        for value in (True, False, None):
            environment = Environment(
                "example", sandbox=SandboxPolicy(allow_local_binding=value)
            )
            codex = CodexAdapter().render(environment)
            claude = ClaudeAdapter().render(environment)
            self.assertIs(
                codex.get("features", {})
                .get("network_proxy", {})
                .get("allow_local_binding"),
                value,
            )
            self.assertIs(
                claude["sandbox"].get("network", {}).get("allowLocalBinding"), value
            )
        local = CodexAdapter().render(
            Environment("local", sandbox=SandboxPolicy(allow_local_binding=True))
        )
        self.assertTrue(local["sandbox_workspace_write"]["network_access"])
        self.assertTrue(local["features"]["network_proxy"]["enabled"])
        self.assertEqual(local["features"]["network_proxy"].get("domains", {}), {})
        internet = CodexAdapter().render(
            Environment(
                "internet",
                sandbox=SandboxPolicy(network=True, allow_local_binding=False),
            )
        )
        self.assertEqual(
            internet["features"]["network_proxy"]["domains"], {"*": "allow"}
        )

    def test_harness_scoped_values_and_boolean_validation(self):
        value = HarnessScopedValue(codex=False, claude=True)
        for policy in (
            SandboxPolicy(allow_local_binding=value),
            ProjectSandboxPolicy(allow_local_binding=value),
        ):
            self.assertIs(policy.local_binding_for("codex"), False)
            self.assertIs(policy.local_binding_for("claude"), True)
        for bad in ("true", 1, [], HarnessScopedValue(codex="false")):
            for model in (SandboxPolicy, ProjectSandboxPolicy):
                with (
                    self.subTest(bad=bad, model=model),
                    self.assertRaisesRegex(ValueError, "boolean"),
                ):
                    model(allow_local_binding=bad)

    def test_global_environment_schema_migration_and_inheritance(self):
        directory = self.root / "definitions"
        directory.mkdir()
        (directory / "base.toml").write_text(
            "schema_version = 3\n[sandbox]\nallow_local_binding = true\n"
        )
        (directory / "child.toml").write_text(
            'schema_version = 3\nextends = "base"\n[sandbox]\nallow_local_binding = false\n'
        )

        def load():
            return load_environments(
                directory, rule_sets={}, instruction_sets={}, tools={}, variables={}
            )

        loaded = load()
        self.assertTrue(loaded["base"].sandbox.allow_local_binding)
        self.assertFalse(loaded["child"].sandbox.allow_local_binding)
        (directory / "child.toml").write_text('schema_version = 2\nextends = "base"\n')
        self.assertTrue(load()["child"].sandbox.allow_local_binding)
        (directory / "child.toml").write_text(
            "schema_version = 2\n[sandbox]\nallow_local_binding = true\n"
        )
        with self.assertRaisesRegex(ValueError, "requires schema_version 3"):
            load()

    def test_project_overrides_are_idempotent_and_removal_inherits_global(self):
        self.apply()
        self.assertEqual(self.values(), (True, True))
        self.assertFalse(
            plan_project(self.repository, self.policy, owner=self.owner).changes
        )
        deny = replace(
            self.policy, sandbox=ProjectSandboxPolicy(allow_local_binding=False)
        )
        self.apply(deny)
        self.assertEqual(self.values(), (False, False))
        self.apply(replace(self.policy, sandbox=ProjectSandboxPolicy()))
        self.assertEqual(self.values(), (None, None))
        state = json.loads((self.root / self.owner.state_path).read_text())
        self.assertEqual(state["sandbox_settings"], {})
        self.assertEqual(state["schema"], 2)

    def test_original_settings_comments_and_secret_values_survive_without_diff_leaks(
        self,
    ):
        text = '# Preserve this comment\nmodel = "custom"\nprivate_key = "private-sentinel"\n[features.network_proxy]\nallow_local_binding = false\n'
        self.write(".codex/config.toml", text)
        settings = {
            "env": {"TOKEN": "private-sentinel"},
            "sandbox": {
                "network": {
                    "allowLocalBinding": False,
                    "allowedDomains": ["example.com"],
                },
                "excludedCommands": ["manual *"],
            },
        }
        self.write(".claude/settings.local.json", json.dumps(settings))
        plan = self.apply()
        self.assertNotIn(
            "private-sentinel", "".join(change.diff for change in plan.changes)
        )
        self.assertEqual(self.values(), (True, True))
        self.assertIn(
            "# Preserve this comment", (self.root / ".codex/config.toml").read_text()
        )
        self.apply(replace(self.policy, sandbox=ProjectSandboxPolicy()))
        self.assertEqual(self.values(), (False, False))
        self.assertEqual((self.root / ".codex/config.toml").read_text(), text)
        self.assertEqual(
            json.loads((self.root / ".claude/settings.local.json").read_text()),
            settings,
        )

    def test_single_harness_sync_preserves_other_harness_settings_and_ownership(self):
        self.apply()
        state = json.loads((self.root / self.owner.state_path).read_text())
        claude = (self.root / ".claude/settings.local.json").read_text()
        deny = replace(
            self.policy, sandbox=ProjectSandboxPolicy(allow_local_binding=False)
        )
        self.apply(deny, ("codex",))
        self.assertEqual(self.values(), (False, True))
        self.assertEqual(
            (self.root / ".claude/settings.local.json").read_text(), claude
        )
        self.assertEqual(
            json.loads((self.root / self.owner.state_path).read_text())[
                "sandbox_settings"
            ]["claude"],
            state["sandbox_settings"]["claude"],
        )

    def test_manual_edits_after_application_survive_retirement(self):
        self.apply()
        self.write(
            ".codex/config.toml",
            "[features.network_proxy]\nallow_local_binding = false\n",
        )
        self.write(
            ".claude/settings.local.json",
            '{"sandbox":{"network":{"allowLocalBinding":false}}}',
        )
        self.apply(replace(self.policy, sandbox=ProjectSandboxPolicy()))
        self.assertEqual(self.values(), (False, False))

    def test_legacy_ownership_migrates_and_corrupt_scalar_ownership_fails_closed(self):
        self.write(
            self.owner.state_path,
            '{"schema":1,"policy":"app","repository":"example/app","claude_permissions":{},"claude_exclusions":[]}',
        )
        self.apply()
        path = self.root / self.owner.state_path
        state = json.loads(path.read_text())
        self.assertEqual(state["schema"], 2)
        before = (self.root / ".codex/config.toml").read_text()
        state["sandbox_settings"]["codex"]["created_tables"] = ["unrelated.secret"]
        path.write_text(json.dumps(state))
        with self.assertRaisesRegex(ValueError, "ownership"):
            plan_project(self.repository, self.policy, owner=self.owner)
        self.assertEqual((self.root / ".codex/config.toml").read_text(), before)

    def test_unmanaged_settings_are_not_interpreted_or_copied_into_state(self):
        self.write(
            ".claude/settings.local.json",
            '{"sandbox":{"network":{"allowLocalBinding":"unmanaged-sentinel"}}}',
        )
        self.apply(replace(self.policy, sandbox=ProjectSandboxPolicy()))
        self.assertNotIn(
            "unmanaged-sentinel", (self.root / self.owner.state_path).read_text()
        )
        self.assertIn(
            "unmanaged-sentinel",
            (self.root / ".claude/settings.local.json").read_text(),
        )
