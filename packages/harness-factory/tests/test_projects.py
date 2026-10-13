import json
import subprocess
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from harness_factory import RuleSet, allow, shell
from harness_factory.projects import (
    SETTINGS_PATH,
    ProjectOwner,
    ProjectPolicy,
    ProjectRepository,
    discover_repositories,
    github_slug,
    inspect_repository,
    match_project,
    plan_project,
)

OWNER = ProjectOwner("deployer", "deploy-project")
STATE_PATH = OWNER.state_path
RULES_PATH = OWNER.rules_path


class ProjectPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.repository = ProjectRepository(self.root, "example/app")
        self.policy = ProjectPolicy(
            name="app",
            repositories=("example/App",),
            rules=(RuleSet(name="tools", rules=(allow(shell("tools/lint.sh")),)),),
        )

    def write(self, path: Path | str, text: str) -> Path:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        return target

    def test_github_identity_formats_and_host_boundaries(self) -> None:
        for value in (
            "Example/App",
            "git@github.com:Example/App.git",
            "git@GitHub.com:Example/App.git",
            "https://github.com/Example/App.git",
            "ssh://git@github.com/Example/App.git",
        ):
            with self.subTest(value=value):
                self.assertEqual(github_slug(value), "example/app")
        for value in (
            "https://github.com.evil/Example/App",
            "https://gitlab.com/Example/App",
            "https://github.com/Example/App/issues",
            "../App",
            "Example/..",
            "/local/App",
            "https://github.com/Example/App?token=value",
        ):
            with self.subTest(value=value):
                self.assertIsNone(github_slug(value))

    def test_origin_only_read_only_inspection_and_ambiguous_origin(self) -> None:
        root_result = subprocess.CompletedProcess([], 0, f"{self.root}\n", "")
        remote_result = subprocess.CompletedProcess(
            [], 0, "git@github.com:Example/App.git\n", ""
        )
        with patch(
            "harness_factory.projects.subprocess.run",
            side_effect=(root_result, remote_result),
        ) as run:
            repository = inspect_repository(self.root / "nested")
        self.assertEqual(repository, self.repository)
        self.assertEqual(
            run.call_args_list[0].args[0][-2:], ["rev-parse", "--show-toplevel"]
        )
        self.assertEqual(
            run.call_args_list[1].args[0][-3:],
            ["config", "--get-all", "remote.origin.url"],
        )
        for origins in (
            "",
            "git@github.com:Other/App.git\ngit@github.com:Example/App.git\n",
        ):
            with patch(
                "harness_factory.projects.subprocess.run",
                side_effect=(
                    root_result,
                    subprocess.CompletedProcess([], 0, origins, ""),
                ),
            ):
                self.assertIsNone(inspect_repository(self.root).slug)

    def test_registry_matches_slugs_and_rejects_ambiguity(self) -> None:
        self.assertEqual(match_project(self.repository, (self.policy,)), self.policy)
        self.assertIsNone(
            match_project(replace(self.repository, slug="fork/app"), (self.policy,))
        )
        with self.assertRaises(ValueError):
            match_project(
                self.repository, (self.policy, replace(self.policy, name="duplicate"))
            )

    def test_discovery_includes_worktrees_grouped_checkouts_and_stops_at_repo(
        self,
    ) -> None:
        for path in ("group/app/.git", "app/.git", "app/nested/.git", "Build/app/.git"):
            self.write(path, "gitdir: somewhere\n")
        (self.root / "linked").symlink_to(self.root / "group", target_is_directory=True)
        self.assertEqual(
            discover_repositories((self.root,)),
            (self.root / "app", self.root / "group/app"),
        )

    def test_discovery_resolves_explicit_symlink_root_without_following_child_links(
        self,
    ) -> None:
        self.write("actual/group/app/.git", "gitdir: somewhere\n")
        self.write("outside/app/.git", "gitdir: somewhere\n")
        (self.root / "Projects").symlink_to(
            self.root / "actual", target_is_directory=True
        )
        (self.root / "actual/linked").symlink_to(
            self.root / "outside", target_is_directory=True
        )
        self.assertEqual(
            discover_repositories((self.root / "Projects",)),
            (self.root / "actual/group/app",),
        )

    def test_first_sync_preserves_existing_config_prose_permissions_and_runtime(
        self,
    ) -> None:
        settings = {
            "env": {"SECRET": "private-value"},
            "hooks": {"Stop": []},
            "permissions": {
                "allow": ["Bash(manual *)"],
                "deny": ["Bash(git push *)"],
                "defaultMode": "acceptEdits",
            },
            "sandbox": {
                "excludedCommands": ["manual *"],
                "allowUnsandboxedCommands": False,
            },
        }
        self.write(SETTINGS_PATH, json.dumps(settings))
        self.write(".codex/config.toml", "model = 'custom'\n")
        agents = "# Repository\n\nKeep this exact prose.\n"
        claude = "# Personal\n\nKeep my instructions.\n"
        self.write("AGENTS.md", agents)
        self.write("CLAUDE.md", claude)
        self.write(".claude/history.json", "runtime")
        self.write(".gitignore", "/Build/\n")
        plan = plan_project(self.repository, self.policy, owner=OWNER)
        self.assertNotIn(
            "private-value", "".join(change.diff for change in plan.changes)
        )
        plan.apply()
        updated = json.loads((self.root / SETTINGS_PATH).read_text())
        self.assertEqual(
            updated["permissions"]["allow"], ["Bash(manual *)", "Bash(tools/lint.sh *)"]
        )
        for key in ("env", "hooks", "sandbox"):
            self.assertEqual(updated[key], settings[key])
        self.assertEqual(
            (self.root / ".codex/config.toml").read_text(), "model = 'custom'\n"
        )
        self.assertEqual((self.root / "AGENTS.md").read_text(), agents)
        self.assertEqual((self.root / "CLAUDE.md").read_text(), claude)
        self.assertEqual((self.root / ".claude/history.json").read_text(), "runtime")
        self.assertEqual((self.root / ".gitignore").read_text(), "/Build/\n")
        self.assertEqual(
            plan_project(self.repository, self.policy, owner=OWNER).changes, ()
        )

    def test_update_retires_owned_permissions_and_exclusions(self) -> None:
        policy = replace(
            self.policy,
            rules=(
                RuleSet(
                    name="tools",
                    rules=self.policy.rules[0].rules,
                    sandbox_excluded_commands=("tools/lint.sh *",),
                    sandbox_exclusion_reason="Host inspection needed.",
                ),
            ),
        )
        plan_project(self.repository, policy, owner=OWNER).apply()
        settings = json.loads((self.root / SETTINGS_PATH).read_text())
        settings["permissions"]["allow"].append("Bash(manual *)")
        settings["sandbox"]["excludedCommands"].append("manual *")
        self.write(SETTINGS_PATH, json.dumps(settings))
        policy = replace(
            self.policy,
            rules=(RuleSet(name="tools", rules=(allow(shell("tools/new.sh")),)),),
        )
        plan_project(self.repository, policy, owner=OWNER).apply()
        updated = json.loads((self.root / SETTINGS_PATH).read_text())
        self.assertEqual(
            updated["permissions"]["allow"], ["Bash(manual *)", "Bash(tools/new.sh *)"]
        )
        self.assertEqual(updated["sandbox"]["excludedCommands"], ["manual *"])
        self.assertNotIn("tools/lint.sh", (self.root / RULES_PATH).read_text())
        self.assertEqual(plan_project(self.repository, policy, owner=OWNER).changes, ())

    def test_preexisting_matching_approval_is_not_claimed_or_retired(self) -> None:
        self.write(
            SETTINGS_PATH,
            json.dumps({"permissions": {"allow": ["Bash(tools/lint.sh *)"]}}),
        )
        plan_project(self.repository, self.policy, owner=OWNER).apply()
        self.assertEqual(
            json.loads((self.root / STATE_PATH).read_text())["claude_permissions"][
                "allow"
            ],
            [],
        )
        plan_project(
            self.repository, replace(self.policy, rules=()), owner=OWNER
        ).apply()
        self.assertEqual(
            json.loads((self.root / SETTINGS_PATH).read_text())["permissions"]["allow"],
            ["Bash(tools/lint.sh *)"],
        )

    def test_single_harness_preserves_other_agent_and_its_ownership(self) -> None:
        plan_project(self.repository, self.policy, owner=OWNER).apply()
        state = json.loads((self.root / STATE_PATH).read_text())
        original_settings = (self.root / SETTINGS_PATH).read_text()
        changed = replace(self.policy, rules=())
        plan_project(
            self.repository, changed, harnesses=("codex",), owner=OWNER
        ).apply()
        self.assertEqual((self.root / SETTINGS_PATH).read_text(), original_settings)
        self.assertEqual(
            json.loads((self.root / STATE_PATH).read_text())["claude_permissions"],
            state["claude_permissions"],
        )
        plan_project(
            self.repository, changed, harnesses=("claude",), owner=OWNER
        ).apply()
        self.assertEqual(
            json.loads((self.root / SETTINGS_PATH).read_text())["permissions"]["allow"],
            [],
        )

    def test_invalid_settings_or_state_fail_before_any_write(self) -> None:
        for path, text in (
            (SETTINGS_PATH, "not json"),
            (SETTINGS_PATH, '{"permissions":{"allow":"all"}}'),
            (SETTINGS_PATH, '{"sandbox":null}'),
            (STATE_PATH, '{"schema":2}'),
            (STATE_PATH, '{"schema":true}'),
            (STATE_PATH, "{}"),
        ):
            with self.subTest(path=path, text=text), TemporaryDirectory() as temporary:
                repository = replace(self.repository, root=Path(temporary))
                target = repository.root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text)
                with self.assertRaises(ValueError):
                    plan_project(repository, self.policy, owner=OWNER)
                self.assertFalse((repository.root / RULES_PATH).exists())
                self.assertEqual(target.read_text(), text)

    def test_symlinked_agent_directories_and_unowned_rule_collisions_fail_closed(
        self,
    ) -> None:
        for relative in (".codex", ".claude"):
            with self.subTest(relative=relative), TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / relative).symlink_to(self.root, target_is_directory=True)
                with self.assertRaises(ValueError):
                    plan_project(
                        replace(self.repository, root=root), self.policy, owner=OWNER
                    )
                self.assertFalse((root / STATE_PATH).exists())
        self.write(RULES_PATH, "# User rules\n")
        with self.assertRaises(ValueError):
            plan_project(self.repository, self.policy, owner=OWNER)

    def test_repository_instructions_and_ignores_are_neither_read_nor_written(
        self,
    ) -> None:
        # Undecodable content and symlink targets must not enter deployment planning.
        for filename in ("AGENTS.md", "CLAUDE.md", ".gitignore"):
            (self.root / filename).write_bytes(b"\xff repository-owned\n")
        plan = plan_project(self.repository, self.policy, owner=OWNER)
        self.assertEqual(
            {change.path for change in plan.changes},
            {RULES_PATH, SETTINGS_PATH, STATE_PATH, Path(".codex/config.toml")},
        )
        plan.apply()
        for filename in ("AGENTS.md", "CLAUDE.md", ".gitignore"):
            self.assertEqual(
                (self.root / filename).read_bytes(), b"\xff repository-owned\n"
            )

    def test_apply_rechecks_all_inputs_before_writing(self) -> None:
        plan = plan_project(self.repository, self.policy, owner=OWNER)
        self.write(SETTINGS_PATH, '{"permissions":{"allow":["Bash(manual *)"]}}')
        with self.assertRaises(ValueError):
            plan.apply()
        self.assertFalse((self.root / RULES_PATH).exists())

    def test_planning_is_read_only_and_creates_minimal_config(self) -> None:
        before = set(self.root.rglob("*"))
        plan = plan_project(self.repository, self.policy, owner=OWNER)
        self.assertEqual(set(self.root.rglob("*")), before)
        config = next(
            change.after
            for change in plan.changes
            if change.path == Path(".codex/config.toml")
        )
        self.assertNotIn("model", config)
        self.assertNotIn("sandbox", config)
        plan.apply()
        for filename in ("AGENTS.md", "CLAUDE.md", ".gitignore"):
            self.assertFalse((self.root / filename).exists())


if __name__ == "__main__":
    unittest.main()
