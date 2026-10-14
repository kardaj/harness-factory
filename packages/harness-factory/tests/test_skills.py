import json
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from harness_factory import (
    ClaudeAdapter,
    CodexAdapter,
    Environment,
    HomeFile,
    Skill,
    ToolManifest,
    apply_tools,
    block,
    deploy_rendered_home,
    instructions,
    load_managed_files_manifest,
    write_harness_homes,
)
from harness_factory.check import check_claude_home, check_codex_home
from harness_factory.exports import ExportError, ManifestExport, apply_exports
from harness_factory.skills import (
    SKILLS_MANIFEST,
    load_skill_inventory,
    validate_skills,
)
from harness_factory.tree_diff import diff_trees
from harness_manifest import to_json


USER = Skill(
    "clarify-brief",
    'Clarify: the "current" brief.\nUser invoked.',
    "Run `agent-flow agent discover`.\nThen retrieve and follow the CLI workflow prompt.\n",
    "user",
)
AUTO = Skill(
    "implement-brief",
    "Implement a brief.",
    "Retrieve the tool-owned implementation workflow.",
    "auto",
)


class SkillCompositionTests(unittest.TestCase):
    def test_tool_reapplication_replaces_renames_and_removes_owned_skills(self):
        tool = ToolManifest(name="cli", skills=(USER, AUTO))
        local = replace(AUTO, name="local")
        other = replace(AUTO, name="other")
        env = apply_tools(
            Environment(name="test", skills=(local,)),
            tool,
            ToolManifest(name="other", skills=(other,)),
        )
        self.assertEqual(env.skills, (local, USER, AUTO, other))
        self.assertEqual(apply_tools(env, tool), env)
        renamed = replace(USER, name="renamed", body="Updated workflow.")
        env = apply_tools(env, replace(tool, skills=(renamed,)))
        self.assertEqual(env.skills, (local, renamed, other))
        env = apply_tools(env, replace(tool, skills=()))
        self.assertEqual(env.skills, (local, other))

    def test_name_collisions_fail_even_for_identical_skills(self):
        tool = ToolManifest(name="cli", skills=(USER,))
        other = replace(tool, name="other")
        with self.assertRaisesRegex(ValueError, "same skill"):
            apply_tools(Environment(name="test"), tool, other)
        with self.assertRaisesRegex(ValueError, "cannot replace skill"):
            apply_tools(apply_tools(Environment(name="test"), tool), other)
        with self.assertRaisesRegex(ValueError, "cannot replace skill"):
            apply_tools(Environment(name="test", skills=(USER,)), tool)
        with self.assertRaisesRegex(ValueError, "repeats skill"):
            Environment(name="test", skills=(USER, USER))

    def test_manifest_import_keeps_cli_wording_and_composes_local_skills(self):
        local = ToolManifest(name="selected", skills=(AUTO,))
        exported = ToolManifest(name="agent-flow", skills=(USER,))
        with (
            patch(
                "harness_factory.exports.trusted_executable",
                return_value="/managed/bin/agent-flow",
            ),
            patch("harness_factory.exports._run", return_value=to_json(exported)),
        ):
            env = apply_exports(
                apply_tools(Environment(name="test"), local),
                {"selected": ManifestExport("agent-flow", commands=("agent-flow",))},
                bin_dir=Path("/managed/bin"),
            )
        self.assertEqual(env.skills, (USER, AUTO))
        self.assertEqual(env.tools[0].skills, (USER, AUTO))
        self.assertEqual(env.instruction_sets, ())
        with (
            patch(
                "harness_factory.exports.trusted_executable",
                return_value="/managed/bin/agent-flow",
            ),
            patch(
                "harness_factory.exports._run",
                return_value=to_json(replace(exported, skills=(AUTO,))),
            ),
        ):
            with self.assertRaisesRegex(ExportError, "unique names"):
                apply_exports(
                    apply_tools(Environment(name="test"), local),
                    {
                        "selected": ManifestExport(
                            "agent-flow", commands=("agent-flow",)
                        )
                    },
                    bin_dir=Path("/managed/bin"),
                )


class SkillRenderingTests(unittest.TestCase):
    def setUp(self):
        self.env = apply_tools(
            Environment(
                name="test",
                instruction_sets=(
                    instructions("base", block("Base", "Keep these instructions.")),
                ),
            ),
            ToolManifest(name="agent-flow", skills=(USER, AUTO)),
        )

    def test_native_files_are_deterministic_and_leave_always_loaded_instructions_unchanged(
        self,
    ):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            for adapter, filename in (
                (CodexAdapter(), "AGENTS.md"),
                (ClaudeAdapter(), "CLAUDE.md"),
            ):
                home = root / adapter.name
                baseline = root / (adapter.name + "-baseline")
                adapter.write(replace(self.env, skills=()), baseline)
                adapter.write(self.env, home)
                self.assertEqual(
                    (home / filename).read_bytes(), (baseline / filename).read_bytes()
                )
                for skill in (USER, AUTO):
                    skill_dir = home / "skills" / skill.name
                    text = (skill_dir / "SKILL.md").read_text()
                    self.assertIn(skill.body, text)
                    self.assertIn(f"description: {json.dumps(skill.description)}", text)
                    if adapter.name == "codex":
                        self.assertNotIn("disable-model-invocation", text)
                        self.assertEqual(
                            (skill_dir / "agents/openai.yaml").read_text(),
                            f"policy:\n  allow_implicit_invocation: {str(skill.invocation == 'auto').lower()}\n",
                        )
                    else:
                        self.assertIn(
                            f"disable-model-invocation: {str(skill.invocation == 'user').lower()}",
                            text,
                        )
                        self.assertFalse((skill_dir / "agents").exists())
                validate_skills(home, adapter.name)
                before = {
                    path.relative_to(home): path.read_bytes()
                    for path in home.rglob("*")
                    if path.is_file()
                }
                adapter.write(
                    replace(self.env, skills=tuple(reversed(self.env.skills))), home
                )
                self.assertEqual(
                    before,
                    {
                        path.relative_to(home): path.read_bytes()
                        for path in home.rglob("*")
                        if path.is_file()
                    },
                )

    def test_policy_and_full_render_previews_include_skill_changes_and_removals(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            for adapter in (CodexAdapter(), ClaudeAdapter()):
                old = root / adapter.name / "old"
                new = root / adapter.name / "new"
                adapter.write_policy_preview(self.env, old)
                adapter.write_policy_preview(
                    replace(self.env, skills=(replace(USER, body="New workflow."),)),
                    new,
                )
                diffs = diff_trees(old, new, include_removed=True)
                self.assertIn(
                    Path("skills/clarify-brief/SKILL.md"),
                    {diff.path for diff in diffs if diff.kind == "modified"},
                )
                self.assertIn(
                    Path("skills/implement-brief/SKILL.md"),
                    {diff.path for diff in diffs if diff.kind == "removed"},
                )
            write_harness_homes(root / "full-old", environments=(self.env,))
            write_harness_homes(
                root / "full-new", environments=(replace(self.env, skills=()),)
            )
            self.assertTrue(
                any(
                    "skills/clarify-brief/SKILL.md" in str(diff.path)
                    for diff in diff_trees(
                        root / "full-old", root / "full-new", include_removed=True
                    )
                )
            )

    def test_validation_detects_discovery_and_invocation_errors_without_installed_clis(
        self,
    ):
        with (
            TemporaryDirectory() as temporary,
            patch("harness_factory.check.shutil.which", return_value=None),
        ):
            root = Path(temporary)
            for adapter, check in (
                (CodexAdapter(), check_codex_home),
                (ClaudeAdapter(), check_claude_home),
            ):
                home = root / adapter.name
                adapter.write(self.env, home)
                self.assertTrue(check(home, skip_missing_cli=True).ok)
                path = (
                    home
                    / "skills/clarify-brief"
                    / ("agents/openai.yaml" if adapter.name == "codex" else "SKILL.md")
                )
                original = path.read_text()
                path.write_text(
                    original.replace("false", "true")
                    if adapter.name == "codex"
                    else original.replace("true", "false")
                )
                result = check(home, skip_missing_cli=True)
                self.assertFalse(result.ok)
                self.assertIn("invocation", result.detail)
                path.write_text(original)
                path.unlink()
                self.assertFalse(check(home, skip_missing_cli=True).ok)

    def test_rerender_retires_removed_skills_without_claiming_unrelated_files(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_harness_homes(root, environments=(self.env,))
            for harness in ("codex", "claude"):
                home = root / harness / "test"
                extra = home / "skills/clarify-brief/personal.txt"
                extra.write_text("Unrelated")
                if harness == "claude":
                    policy = home / "skills/implement-brief/agents/openai.yaml"
                    policy.parent.mkdir()
                    policy.write_text("Unrelated Codex policy")
                personal = home / "skills/personal/SKILL.md"
                personal.parent.mkdir()
                personal.write_text("Personal")
            write_harness_homes(root, environments=(replace(self.env, skills=(AUTO,)),))
            for harness in ("codex", "claude"):
                home = root / harness / "test"
                self.assertFalse((home / "skills/clarify-brief/SKILL.md").exists())
                self.assertTrue((home / "skills/clarify-brief/personal.txt").exists())
                self.assertTrue((home / "skills/personal/SKILL.md").exists())
                owned = load_managed_files_manifest(home)
                if harness == "claude":
                    self.assertNotIn(
                        Path("skills/implement-brief/agents/openai.yaml"), owned
                    )
                self.assertNotIn(Path("skills/personal/SKILL.md"), owned)
                self.assertNotIn(Path("skills/clarify-brief/personal.txt"), owned)
                self.assertFalse(
                    any(".harness-retired" in path.parts for path in owned)
                )

    def test_home_files_cannot_replace_skill_discovery_or_policy(self):
        for adapter in (CodexAdapter(), ClaudeAdapter()):
            with TemporaryDirectory() as temporary:
                env = replace(
                    self.env,
                    home_files=(
                        HomeFile(
                            relative_path=Path("skills/clarify-brief/SKILL.md"),
                            source_path=Path("/unused"),
                        ),
                    ),
                )
                with self.assertRaisesRegex(ValueError, "collides"):
                    adapter.write(env, Path(temporary))


class SkillDeploymentTests(unittest.TestCase):
    def test_deployment_updates_and_archives_only_previously_managed_skill_files(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            old = apply_tools(
                Environment(name="test"), ToolManifest(name="cli", skills=(USER, AUTO))
            )
            new = apply_tools(
                old,
                ToolManifest(
                    name="cli",
                    skills=(replace(USER, invocation="auto", body="Updated body."),),
                ),
            )
            write_harness_homes(root / "old", environments=(old,))
            write_harness_homes(root / "new", environments=(new,))
            write_harness_homes(
                root / "empty", environments=(Environment(name="test"),)
            )
            for harness in ("codex", "claude"):
                home = root / "live" / harness
                deploy_rendered_home(old, harness, root / "old", home)
                retired = home / "skills/implement-brief/SKILL.md"
                retired.write_text("Local edits to preserve")
                extra = retired.parent / "notes.txt"
                extra.write_text("Personal notes")
                personal = home / "skills/personal/SKILL.md"
                personal.parent.mkdir()
                personal.write_text("Personal workflow")
                with patch.object(
                    Path,
                    "rglob",
                    side_effect=AssertionError("deployment scanned user files"),
                ):
                    deploy_rendered_home(new, harness, root / "new", home)
                    self.assertEqual(
                        deploy_rendered_home(new, harness, root / "new", home), 0
                    )
                self.assertFalse(retired.exists())
                archived = list(
                    (home / ".harness-retired").glob(
                        "*/skills/implement-brief/SKILL.md"
                    )
                )
                self.assertEqual(
                    [path.read_text() for path in archived], ["Local edits to preserve"]
                )
                self.assertEqual(extra.read_text(), "Personal notes")
                self.assertEqual(personal.read_text(), "Personal workflow")
                validate_skills(home, harness)
                deploy_rendered_home(
                    Environment(name="test"), harness, root / "empty", home
                )
                self.assertEqual(load_skill_inventory(home), {})
                self.assertFalse((home / "skills/clarify-brief/SKILL.md").exists())
                self.assertTrue(personal.is_file())

    def test_deployment_refuses_unmanaged_collisions_and_symlinks_before_writes(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = apply_tools(
                Environment(name="test"), ToolManifest(name="cli", skills=(USER,))
            )
            write_harness_homes(root / "rendered", environments=(env,))
            for harness in ("codex", "claude"):
                home = root / harness
                existing = home / "skills/clarify-brief/SKILL.md"
                existing.parent.mkdir(parents=True)
                existing.write_text("User owned")
                with self.assertRaisesRegex(ValueError, "unmanaged skill"):
                    deploy_rendered_home(env, harness, root / "rendered", home)
                self.assertEqual(existing.read_text(), "User owned")
                self.assertFalse(
                    (
                        home
                        / ("config.toml" if harness == "codex" else "settings.json")
                    ).exists()
                )
                existing.unlink()
                existing.parent.rmdir()
                outside = root / (harness + "-outside")
                outside.mkdir()
                existing.parent.symlink_to(outside, target_is_directory=True)
                with self.assertRaisesRegex(ValueError, "symlink"):
                    deploy_rendered_home(env, harness, root / "rendered", home)
                self.assertEqual(list(outside.iterdir()), [])

    def test_inventory_rejects_unknown_versions_fields_and_unsafe_names(self):
        with TemporaryDirectory() as temporary:
            home = Path(temporary)
            for data in (
                {"schema_version": 2, "skills": []},
                {"schema_version": True, "skills": []},
                {"schema_version": 1, "skills": [], "extra": True},
                {
                    "schema_version": 1,
                    "skills": [{"name": "../escape", "invocation": "user"}],
                },
                {
                    "schema_version": 1,
                    "skills": [{"name": "test", "invocation": "user"}] * 2,
                },
            ):
                (home / SKILLS_MANIFEST).write_text(
                    json.dumps({"harness": "codex", **data})
                )
                with self.subTest(data=data), self.assertRaises(ValueError):
                    load_skill_inventory(home)

    def test_incomplete_managed_output_and_partial_exclusions_fail(self):
        with (
            TemporaryDirectory() as temporary,
            patch("harness_factory.check.shutil.which", return_value=None),
        ):
            root = Path(temporary)
            env = apply_tools(
                Environment(name="test"), ToolManifest(name="cli", skills=(USER,))
            )
            write_harness_homes(root / "rendered", environments=(env,))
            for harness, check in (
                ("codex", check_codex_home),
                ("claude", check_claude_home),
            ):
                source = root / "rendered" / harness / "test"
                self.assertTrue(check(source, skip_missing_cli=True).ok)
                with self.assertRaisesRegex(ValueError, "partially exclude"):
                    deploy_rendered_home(
                        env,
                        harness,
                        root / "rendered",
                        root / "live" / harness,
                        excluded_paths=(Path("skills"),),
                    )
                inventory = (source / SKILLS_MANIFEST).read_text()
                (source / SKILLS_MANIFEST).unlink()
                self.assertFalse(check(source, skip_missing_cli=True).ok)
                (source / SKILLS_MANIFEST).write_text(inventory)
                skill = source / "skills/clarify-brief/SKILL.md"
                skill.write_text(
                    skill.read_text().replace(
                        'name: "clarify-brief"', 'name: "wrong-name"'
                    )
                )
                self.assertFalse(check(source, skip_missing_cli=True).ok)
