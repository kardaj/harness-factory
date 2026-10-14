import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from harness_manifest import (
    Skill,
    ToolManifest,
    from_dict,
    from_json,
    load_manifest,
    to_dict,
    to_json,
)


class SkillTests(unittest.TestCase):
    def setUp(self):
        self.skill = Skill(
            name="clarify-brief",
            description="Clarify the current brief when the user invokes this workflow.",
            body="Run `agent-flow agent discover`, then retrieve the CLI workflow prompt.\n",
            invocation="user",
        )

    def test_self_contained_json_and_toml_round_trips(self):
        manifest = ToolManifest(
            name="agent-flow",
            skills=(
                self.skill,
                replace(self.skill, name="implement-brief", invocation="auto"),
            ),
        )
        self.assertEqual(from_json(to_json(manifest)), manifest)
        self.assertEqual(to_dict(manifest)["schema_version"], 4)
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "tool-manifest.toml"
            path.write_text('''schema_version = 4
name = "agent-flow"
[[skills]]
name = "clarify-brief"
description = "Clarify the current brief when the user invokes this workflow."
invocation = "user"
body = """Run `agent-flow agent discover`, then retrieve the CLI workflow prompt.
"""
''')
            self.assertEqual(
                load_manifest(path),
                ToolManifest(name="agent-flow", skills=(self.skill,)),
            )

    def test_old_schemas_migrate_and_reject_skills_even_when_empty(self):
        for version in (1, 2, 3):
            data = {"schema_version": version, "name": "cli"}
            with self.subTest(version=version):
                migrated = to_dict(from_dict(data))
                self.assertEqual(migrated["schema_version"], 4)
                self.assertEqual(migrated["skills"], [])
                with self.assertRaisesRegex(
                    ValueError, "unknown fields.*skills.*schema_version 4"
                ):
                    from_dict({**data, "skills": []})

    def test_invalid_and_nonportable_fields_fail(self):
        for changes in (
            {"name": "../escape"},
            {"name": "Upper"},
            {"name": "a--b"},
            {"name": "-skill"},
            {"name": "skill-"},
            {"name": "x" * 65},
            {"name": "synced"},
            {"name": "anthropic-skills"},
            {"description": " "},
            {"description": "x" * 1025},
            {"body": "\n"},
            {"body": Path("workflow.md")},
            {"invocation": "implicit"},
            {"invocation": False},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(self.skill, **changes)
        with self.assertRaisesRegex(ValueError, "unique names"):
            ToolManifest(name="cli", skills=(self.skill, self.skill))
        data = to_dict(ToolManifest(name="cli", skills=(self.skill,)))
        for field in ("path", "scripts", "files", "extra"):
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(ValueError, "unknown fields"),
            ):
                from_dict(
                    {**data, "skills": [{**data["skills"][0], field: "anything"}]}
                )
        for skills in (None, "workflow", ["workflow"], [{}]):
            with self.subTest(skills=skills), self.assertRaises(ValueError):
                from_dict({**data, "skills": skills})
        missing = dict(data["skills"][0])
        missing.pop("invocation")
        with self.assertRaisesRegex(ValueError, "invocation"):
            from_dict({**data, "skills": [missing]})
