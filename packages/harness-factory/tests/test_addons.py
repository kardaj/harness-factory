import json
import tomllib
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from harness_factory import (
    ClaudeProfile,
    Environment,
    SkillBundle,
    ToolServer,
    deploy_rendered_home,
    load_environments,
    load_managed_files_manifest,
    write_harness_homes,
)
from harness_factory.addons import ADDONS_MANIFEST, addon_retirements
from harness_factory.render import retired_config_keys


class AddonTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        (self.source / "references").mkdir(parents=True)
        (self.source / "SKILL.md").write_text(
            "---\nname: example\ndescription: Example\n---\nRead references/guide.md.\n"
        )
        (self.source / "references/guide.md").write_text("Guide\n")
        self.bundle = SkillBundle("example", self.source, harnesses=("claude",))
        self.output = self.root / "output"
        self.target = self.root / "live"

    def render(self, environment):
        write_harness_homes(self.output, environments=(environment,))

    def test_mcp_scoping_and_migration_prune_only_the_excluded_harness(self):
        shared = ToolServer("shared", "http", url="https://shared.example/mcp")
        optional = ToolServer("optional", "http", url="https://optional.example/mcp")
        old = Environment("personal", base_mcp_servers=(shared, optional))
        self.render(old)
        deploy_rendered_home(old, "codex", self.output, self.target)
        new = replace(
            old, base_mcp_servers=(shared, replace(optional, harnesses=("claude",)))
        )
        self.render(new)
        codex = tomllib.loads((self.output / "codex/personal/config.toml").read_text())
        claude = json.loads((self.output / "claude/personal/.mcp.json").read_text())
        self.assertNotIn("optional", codex["mcp_servers"])
        self.assertIn("optional", claude["mcpServers"])
        self.assertIn(
            ("mcp_servers", "optional"),
            retired_config_keys((new,))[Path("codex/personal/config.toml")],
        )
        deploy_rendered_home(new, "codex", self.output, self.target)
        self.assertNotIn(
            "optional",
            tomllib.loads((self.target / "config.toml").read_text())["mcp_servers"],
        )

    def test_bundles_deploy_all_files_retire_owned_files_and_keep_local_extras(self):
        environment = Environment("personal", skill_bundles=(self.bundle,))
        self.render(environment)
        home = self.output / "claude/personal"
        self.assertIn(
            Path("skills/example/references/guide.md"),
            load_managed_files_manifest(home),
        )
        self.assertFalse((self.output / "codex/personal/skills/example").exists())
        deploy_rendered_home(environment, "claude", self.output, self.target)
        local = self.target / "skills/example/local-note.md"
        local.write_text("Keep this local extra")
        self.assertEqual(
            (self.target / "skills/example/references/guide.md").read_text(), "Guide\n"
        )
        (self.source / "references/guide.md").unlink()
        self.render(environment)
        deploy_rendered_home(environment, "claude", self.output, self.target)
        self.assertFalse((self.target / "skills/example/references/guide.md").exists())
        self.assertEqual(local.read_text(), "Keep this local extra")
        empty = replace(environment, skill_bundles=())
        self.render(empty)
        deploy_rendered_home(empty, "claude", self.output, self.target)
        self.assertFalse((self.target / "skills/example/SKILL.md").exists())
        self.assertTrue(local.exists())

    def test_profiles_inherit_mcp_but_do_not_change_base_discovery_or_auth(self):
        base = ToolServer("shared", "http", url="https://shared.example/mcp")
        extra = ToolServer(
            "optional",
            "http",
            url="https://optional.example/mcp",
            harnesses=("claude",),
        )
        environment = Environment(
            "personal",
            base_mcp_servers=(base,),
            claude_profiles=(
                ClaudeProfile(
                    "example", mcp_servers=(extra,), skill_bundles=(self.bundle,)
                ),
            ),
        )
        self.render(environment)
        home = self.output / "claude/personal"
        profile = home / "profiles/example"
        self.assertFalse((home / "skills/example").exists())
        self.assertFalse((self.output / "codex/personal/profiles").exists())
        self.assertEqual(
            set(json.loads((home / ".mcp.json").read_text())["mcpServers"]), {"shared"}
        )
        self.assertEqual(
            set(json.loads((profile / "mcp.json").read_text())["mcpServers"]),
            {"shared", "optional"},
        )
        self.assertFalse((profile / ".mcp.json").exists())
        self.assertEqual(
            (profile / "skills/example/references/guide.md").read_text(), "Guide\n"
        )
        self.target.mkdir()
        auth = self.target / ".credentials.json"
        auth.write_text("private-auth-sentinel")
        deploy_rendered_home(environment, "claude", self.output, self.target)
        self.assertEqual(auth.read_text(), "private-auth-sentinel")
        self.assertFalse((self.target / "skills/example").exists())

    def test_unmanaged_bundle_collisions_and_symlinks_fail_before_deployment(self):
        environment = Environment("personal", skill_bundles=(self.bundle,))
        self.render(environment)
        (self.target / "skills/example").mkdir(parents=True)
        sentinel = self.target / "skills/example/SKILL.md"
        sentinel.write_text("Keep unmanaged skill")
        with self.assertRaisesRegex(ValueError, "unmanaged add-on"):
            deploy_rendered_home(environment, "claude", self.output, self.target)
        self.assertEqual(sentinel.read_text(), "Keep unmanaged skill")
        (self.source / "references/escape.md").symlink_to(self.root / "outside")
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.render(environment)

    def test_corrupt_inventory_and_missing_owned_source_fail_closed(self):
        environment = Environment("personal", skill_bundles=(self.bundle,))
        self.render(environment)
        home = self.output / "claude/personal"
        (home / "skills/example/SKILL.md").unlink()
        with self.assertRaisesRegex(ValueError, "missing"):
            addon_retirements(home, self.target, "claude")
        (home / ADDONS_MANIFEST).write_text(
            '{"schema_version": 1, "harness": "claude", "files": ["../outside"]}'
        )
        with self.assertRaisesRegex(ValueError, "Invalid add-on inventory"):
            addon_retirements(home, self.target, "claude")

    def test_schema_v2_profiles_and_scoping_keep_v1_compatible(self):
        definitions = self.root / "definitions"
        definitions.mkdir()
        (definitions / "base.toml").write_text("schema_version = 1\n")
        text = """schema_version = 2
extends = "base"
[base_mcp_servers.optional]
kind = "http"
url = "https://optional.example/mcp"
harnesses = ["claude"]
[claude_profiles.example]
[[claude_profiles.example.skill_bundles]]
name = "example"
source_dir = "${SOURCE}"
harnesses = ["claude"]
"""
        file = definitions / "personal.toml"
        file.write_text(text)
        loaded = load_environments(
            definitions,
            rule_sets={},
            instruction_sets={},
            tools={},
            variables={"SOURCE": str(self.source)},
        )
        self.assertEqual(loaded["personal"].base_mcp_servers[0].harnesses, ("claude",))
        self.assertEqual(
            loaded["personal"].claude_profiles[0].skill_bundles, (self.bundle,)
        )
        file.write_text(text.replace("schema_version = 2", "schema_version = 1"))
        with self.assertRaisesRegex(ValueError, "require schema_version 2"):
            load_environments(
                definitions,
                rule_sets={},
                instruction_sets={},
                tools={},
                variables={"SOURCE": str(self.source)},
            )

    def test_executable_assets_keep_their_mode_and_exclusions_are_respected(self):
        script = self.source / "helper.sh"
        script.write_text("#!/bin/sh\nexit 0\n")
        script.chmod(0o755)
        environment = Environment("personal", skill_bundles=(self.bundle,))
        self.render(environment)
        deploy_rendered_home(environment, "claude", self.output, self.target)
        self.assertTrue(
            (self.target / "skills/example/helper.sh").stat().st_mode & 0o111
        )
        with self.assertRaisesRegex(ValueError, "partially exclude"):
            deploy_rendered_home(
                environment,
                "claude",
                self.output,
                self.target,
                excluded_paths=(Path("skills/example"),),
            )

    def test_bundle_names_and_paths_are_validated(self):
        with self.assertRaisesRegex(ValueError, "absolute Path"):
            SkillBundle("example", Path("relative"))
        (self.source / "SKILL.md").write_text("---\nname: another\n---\nBody\n")
        with self.assertRaisesRegex(ValueError, "frontmatter"):
            self.render(Environment("personal", skill_bundles=(self.bundle,)))

    def test_profile_removal_archives_owned_plugin_and_keeps_local_files(self):
        environment = Environment(
            "personal",
            claude_profiles=(ClaudeProfile("example", skill_bundles=(self.bundle,)),),
        )
        self.render(environment)
        deploy_rendered_home(environment, "claude", self.output, self.target)
        local = self.target / "profiles/example/local-note.md"
        local.write_text("Keep")
        environment = replace(environment, claude_profiles=())
        self.render(environment)
        deploy_rendered_home(environment, "claude", self.output, self.target)
        self.assertFalse(
            (self.target / "profiles/example/.claude-plugin/plugin.json").exists()
        )
        self.assertEqual(local.read_text(), "Keep")

    def test_owned_json_assets_replace_old_keys_exactly(self):
        asset = self.source / "data.json"
        asset.write_text('{"old": true, "keep": 1}\n')
        environment = Environment("personal", skill_bundles=(self.bundle,))
        self.render(environment)
        deploy_rendered_home(environment, "claude", self.output, self.target)
        asset.write_text('{"keep": 2}\n')
        self.output = self.root / "fresh-output"
        self.render(environment)
        deploy_rendered_home(environment, "claude", self.output, self.target)
        self.assertEqual(
            (self.target / "skills/example/data.json").read_bytes(), asset.read_bytes()
        )

    def test_profile_mcp_updates_remove_old_servers_and_retirement_relinquishes_ownership(
        self,
    ):
        server = ToolServer("optional", "http", url="https://optional.example/mcp")
        profile = ClaudeProfile(
            "example", mcp_servers=(server,), skill_bundles=(self.bundle,)
        )
        environment = Environment("personal", claude_profiles=(profile,))
        self.render(environment)
        deploy_rendered_home(environment, "claude", self.output, self.target)
        environment = replace(
            environment, claude_profiles=(replace(profile, mcp_servers=()),)
        )
        self.output = self.root / "fresh-output"
        self.render(environment)
        deploy_rendered_home(environment, "claude", self.output, self.target)
        self.assertEqual(
            json.loads((self.target / "profiles/example/mcp.json").read_text())[
                "mcpServers"
            ],
            {},
        )
        self.assertEqual(
            (self.target / "profiles/example/mcp.json").stat().st_mode & 0o777, 0o600
        )
        environment = replace(environment, claude_profiles=())
        self.output = self.root / "empty-output"
        self.render(environment)
        deploy_rendered_home(environment, "claude", self.output, self.target)
        self.assertEqual(
            json.loads((self.target / ADDONS_MANIFEST).read_text())["files"], []
        )
        sentinel = self.target / "profiles/example/skills/example/SKILL.md"
        sentinel.write_text("Now an unmanaged personal file")
        self.output = self.root / "returning-output"
        environment = replace(environment, claude_profiles=(profile,))
        self.render(environment)
        with self.assertRaisesRegex(ValueError, "unmanaged add-on"):
            deploy_rendered_home(environment, "claude", self.output, self.target)
        self.assertEqual(sentinel.read_text(), "Now an unmanaged personal file")
