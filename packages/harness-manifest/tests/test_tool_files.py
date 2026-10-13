import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from harness_manifest import (
    RuleSet,
    SCHEMA_VERSION,
    ToolInstall,
    ToolManifest,
    allow,
    codex_only,
    load_manifest,
    load_manifests,
    shell,
)

SHARED = RuleSet(name="shared-cli", rules=(allow(shell("cli", "list")),))

TOOL = """\
schema_version = 1
vars = ["CLI_TOKEN"]
rules = "shared"
writable_roots = ["/cache/cli", { codex = "/state/cli" }]

[[installs]]
manager = "uv"
name = "cli-package"
source = "cli-package>=1"
commands = ["cli"]
required = false
"""

INLINE = """\
schema_version = 1

[rules]
sandbox_excluded_commands = ["cli *"]
sandbox_exclusion_reason = "host services"

[[rules.rules]]
effect = "allow"
command = ["cli", ["list", "show"]]
"""


class ToolFileTests(unittest.TestCase):
    def test_empty_inline_and_referenced_rule_sets_must_be_omitted(self):
        for text, rule_sets in (
            ("schema_version = 3\n[rules]\n", {}),
            ("schema_version = 3\n[rules]\nrules = []\n", {}),
            (
                'schema_version = 3\nrules = "empty"\n',
                {"empty": RuleSet(name="empty", rules=())},
            ),
        ):
            path = self.write("cli", text)
            with (
                self.subTest(text=text),
                self.assertRaisesRegex(
                    ValueError, "empty rule set; omit rules"
                ) as raised,
            ):
                load_manifest(path, rule_sets)
            self.assertIn(str(path), str(raised.exception))
        self.assertIsNone(
            load_manifest(self.write("cli", "schema_version = 3\n")).rules
        )

    def test_exclusion_only_policy_loads_but_bare_commands_do_not(self):
        text = """schema_version = 3
[rules]
sandbox_excluded_commands = ["cli *"]
sandbox_exclusion_reason = "host services"
"""
        self.assertEqual(load_manifest(self.write("cli", text)).rules.rules, ())
        with self.assertRaisesRegex(ValueError, "must end in ' \\*'"):
            load_manifest(self.write("cli", text.replace("cli *", "cli")))

    def test_optional_vars_and_portable_roots_load_from_toml(self):
        tool = load_manifest(
            self.write(
                "cli",
                """\
schema_version = 3
vars = ["TOKEN"]
optional_vars = ["CACHE"]
writable_roots = ["${CACHE}/data"]
""",
            )
        )
        self.assertEqual(tool.vars, ("TOKEN",))
        self.assertEqual(tool.optional_vars, ("CACHE",))
        self.assertEqual(tool.writable_roots, (Path("${CACHE}/data"),))
        with self.assertRaisesRegex(ValueError, "must not overlap"):
            load_manifest(
                self.write(
                    "cli",
                    """\
schema_version = 3
vars = ["TOKEN"]
optional_vars = ["TOKEN"]
""",
                )
            )

    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write(self, name: str, text: str) -> Path:
        path = self.root / f"{name}.toml"
        path.write_text(text, encoding="utf-8")
        return path

    def test_named_rule_sets_resolve_and_the_name_defaults_to_the_stem(self) -> None:
        self.write("cli", TOOL)

        self.assertEqual(
            load_manifests(self.root, {"shared": SHARED}),
            {
                "cli": ToolManifest(
                    name="cli",
                    installs=(
                        ToolInstall(
                            manager="uv",
                            name="cli-package",
                            source="cli-package>=1",
                            commands=("cli",),
                            required=False,
                        ),
                    ),
                    vars=("CLI_TOKEN",),
                    rules=SHARED,
                    writable_roots=(Path("/cache/cli"), codex_only(Path("/state/cli"))),
                )
            },
        )

    def test_inline_rule_sets_are_named_after_the_tool(self) -> None:
        rules = load_manifest(self.write("cli", INLINE)).rules

        self.assertEqual(rules.name, "cli")
        self.assertEqual(rules.sandbox_excluded_commands, ("cli *",))
        self.assertEqual(rules.rules[0].target.parts[1].values, ("list", "show"))

    def test_invalid_files_name_the_path(self) -> None:
        for text, rule_sets, message in (
            (TOOL, {}, "unknown rule set 'shared'"),
            (
                TOOL.replace("= 1", f"= {SCHEMA_VERSION + 1}"),
                {"shared": SHARED},
                "schema_version",
            ),
            ("extra = true\n" + TOOL, {"shared": SHARED}, "unknown fields"),
            ("not toml =", {}, "invalid TOML"),
            ('name = "other"\n' + TOOL, {"shared": SHARED}, "must match the file"),
        ):
            with self.subTest(message=message):
                path = self.write("cli", text)
                with self.assertRaisesRegex(ValueError, message) as raised:
                    load_manifest(path, rule_sets)
                self.assertIn(str(path), str(raised.exception))


if __name__ == "__main__":
    unittest.main()
