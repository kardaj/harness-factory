import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from harness_factory import (
    EnvVar,
    HarnessScopedValue,
    RuleSet,
    ToolManifest,
    allow,
    instructions,
    load_environments,
    load_instruction_sets,
    markdown,
    sandbox_exclusions,
    shell,
    trust,
    trust_children,
)

RULES = {
    name: RuleSet(name=name, rules=(allow(shell(name)),))
    for name in ("base-cli", "child-cli", "tool-cli")
}
# A variant may share a rendered name, as environment-specific policies do.
RULES["tool-cli-variant"] = RuleSet(name="tool-cli", rules=(allow(shell("x")),))
TOOLS = {
    "tool": ToolManifest(
        name="tool",
        rules=RULES["tool-cli"],
        writable_roots=(Path("/cache/tool"),),
    )
}

BASE = """\
schema_version = 1
context_window_size = { claude = 300000 }
instruction_sets = ["base"]
rules = ["base-cli"]
tools = ["tool"]
retired_env_vars = ["OLD"]
trusted_projects = [{ path = "${REPO}" }]

[env_vars]
HOME_DIR = { source = "host" }
CACHE = "${REPO}/cache"

[sandbox]
writable_roots = ["/cache/base"]
network_allowed_domains = ["a.example"]

[harness_overrides.codex]
model = "base"
features = { a = true, b = true }
list = [1, 2]
"""

CHILD = """\
schema_version = 1
extends = "base"
personality = "terse"
rules = ["base-cli", "child-cli"]
retired_env_vars = ["OLD", "OLDER"]
trusted_projects = [{ root = "/projects", devcontainer_mirror = "/home/dev" }]

[env_vars]
HOME_DIR = { source = { codex = "host", claude = "literal" }, value = { claude = "/claude" } }
CACHE = { source = "1password", value = "secrets.CACHE" }

[sandbox]
network = true
network_allowed_domains = ["a.example", "b.example"]

[base_mcp_servers.docs]
kind = "stdio"
command = "node"
args = ["docs.js"]
cwd = "/docs"

[harness_overrides.codex]
features = { b = false }
list = [3]
"""


class EnvironmentFileTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sets = {"base": instructions("base", markdown("base.md"))}

    def load(self, **files: str):
        for name, text in files.items():
            (self.root / f"{name}.toml").write_text(text, encoding="utf-8")
        return load_environments(
            self.root,
            rule_sets=RULES,
            instruction_sets=self.sets,
            tools=TOOLS,
            variables={"REPO": "/repo"},
        )

    def test_children_merge_each_field_by_its_rule(self) -> None:
        loaded = self.load(base=BASE, child=CHILD)
        base, child = loaded["base"], loaded["child"]

        self.assertEqual(base.context_window_size, HarnessScopedValue(claude=300000))
        self.assertEqual(base.rules, (RULES["base-cli"], RULES["tool-cli"]))
        self.assertEqual(base.tools, (TOOLS["tool"],))
        self.assertEqual(
            base.env_vars,
            (EnvVar("HOME_DIR", source="host"), EnvVar("CACHE", value="/repo/cache")),
        )
        self.assertEqual(
            base.sandbox.writable_roots, (Path("/cache/base"), Path("/cache/tool"))
        )
        self.assertEqual(base.trusted_projects, (trust("/repo"),))

        self.assertEqual(child.name, "child")
        self.assertEqual(child.personality, "terse")
        self.assertEqual(child.context_window_size, base.context_window_size)
        self.assertEqual(child.rules, base.rules + (RULES["child-cli"],))
        self.assertEqual(child.tools, base.tools)
        self.assertEqual(child.retired_env_vars, ("OLD", "OLDER"))
        # Named entries replace the base entry in place instead of stacking.
        self.assertEqual(
            child.env_vars,
            (
                EnvVar(
                    "HOME_DIR",
                    value=HarnessScopedValue(claude="/claude"),
                    source=HarnessScopedValue(codex="host", claude="literal"),
                ),
                EnvVar("CACHE", source="1password", value="secrets.CACHE"),
            ),
        )
        self.assertEqual(child.env_vars[0].source_for("codex"), "host")
        self.assertEqual(child.env_vars[0].source_for("claude"), "literal")
        self.assertTrue(child.sandbox.network)
        self.assertEqual(child.sandbox.writable_roots, base.sandbox.writable_roots)
        self.assertEqual(
            child.sandbox.network_allowed_domains, ("a.example", "b.example")
        )
        self.assertEqual(
            child.trusted_projects,
            (
                trust("/repo"),
                trust_children("/projects", devcontainer_mirror="/home/dev"),
            ),
        )
        self.assertEqual(child.base_mcp_servers[0].args, ("docs.js",))
        self.assertEqual(child.base_mcp_servers[0].cwd, Path("/docs"))
        self.assertEqual(
            child.harness_overrides,
            {
                "codex": {
                    "model": "base",
                    "features": {"a": True, "b": False},
                    "list": [3],
                }
            },
        )

    def test_invalid_files_name_the_file_and_the_problem(self) -> None:
        for text, message in (
            (BASE.replace("${REPO}/cache", "${MISSING}"), "unknown variable"),
            (BASE.replace('"base-cli"', '"missing"'), "unknown rule set 'missing'"),
            (BASE.replace('"tool"]', '"missing"]'), "unknown tool 'missing'"),
            ("agents = []\n" + BASE, "unsupported fields: \\['agents'\\]"),
            (BASE.replace("= 1", "= 2", 1), "schema_version 2"),
            (
                BASE.replace(
                    "schema_version = 1", 'schema_version = 1\nextends = "base"'
                ),
                "extends itself",
            ),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message) as raised:
                    self.load(base=text)
                self.assertIn("base.toml", str(raised.exception))

    def test_children_may_not_replace_sets_owned_by_a_base_tool(self) -> None:
        child = 'schema_version = 1\nextends = "base"\nrules = ["{}"]\n'

        same = self.load(base=BASE, child=child.format("tool-cli"))["child"]

        self.assertEqual(same.rules, (RULES["base-cli"], RULES["tool-cli"]))
        with self.assertRaisesRegex(ValueError, "child.toml: .*owned by tool 'tool'"):
            self.load(base=BASE, child=child.format("tool-cli-variant"))


class ScopedSourceTests(unittest.TestCase):
    def test_scoped_sources_only_choose_literal_or_host_with_values(self) -> None:
        with self.assertRaisesRegex(ValueError, "only scope literal or host"):
            EnvVar("TOKEN", source=HarnessScopedValue(codex="1password"), value="x")
        with self.assertRaisesRegex(ValueError, "requires a claude value"):
            EnvVar(
                "HOME_DIR",
                source=HarnessScopedValue(codex="host", claude="literal"),
                value=HarnessScopedValue(codex="/codex"),
            )


class InstructionSetFileTests(unittest.TestCase):
    def test_sets_list_root_relative_markdown_then_optional_exclusions(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "sets.toml"
            path.write_text(
                "schema_version = 1\n"
                '[one]\nmarkdown = ["a.md", "/abs/b.md"]\n'
                '[two]\nharnesses = ["claude"]\nmarkdown = ["c.md"]\n'
                "sandbox_exclusions = true\n",
                encoding="utf-8",
            )
            self.assertEqual(
                load_instruction_sets(path, root=Path("/repo")),
                {
                    "one": instructions(
                        "one", markdown("/repo/a.md"), markdown("/abs/b.md")
                    ),
                    "two": instructions(
                        "two",
                        markdown("/repo/c.md"),
                        sandbox_exclusions(),
                        harnesses=("claude",),
                    ),
                },
            )


if __name__ == "__main__":
    unittest.main()
