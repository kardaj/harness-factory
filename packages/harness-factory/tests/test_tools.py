import unittest
from dataclasses import replace
from pathlib import Path

from harness_manifest import resolve_manifest

from harness_factory import (
    ClaudeAdapter,
    CodexAdapter,
    Environment,
    EnvVar,
    RuleSet,
    SandboxPolicy,
    ToolInstall,
    ToolManifest,
    allow,
    apply_tools,
    block,
    check_tool_vars,
    collect_installs,
    instructions,
    shell,
)


def rules(name: str, command: str) -> RuleSet:
    return RuleSet(name=name, rules=(allow(shell(command)),))


class ToolManifestTests(unittest.TestCase):
    def test_lowers_every_contribution_and_replaces_owned_names_in_place(
        self,
    ) -> None:
        environment = apply_tools(
            Environment(
                name="work",
                sandbox=SandboxPolicy(
                    writable_roots=(Path("/cache/a"),),
                    network_allowed_domains=("a.example",),
                ),
                env_vars=(
                    EnvVar("TOOL_HOME", value="old"),
                    EnvVar("LAST", value="x"),
                ),
                rules=(rules("other", "other"),),
            ),
            ToolManifest(
                name="tool",
                rules=rules("tool", "old"),
                instructions=instructions("tool", block("Old", "- old")),
            ),
        )
        tool = ToolManifest(
            name="tool",
            vars=("TOOL_HOME",),
            rules=rules("tool", "tool"),
            writable_roots=(Path("/cache/a"), Path("/cache/tool")),
            network_domains=("a.example", "tool.example"),
            instructions=instructions("tool", block("Tool", "- use tool")),
        )

        applied = apply_tools(environment, tool)

        self.assertEqual(applied.env_vars, environment.env_vars)
        self.assertEqual(applied.rules, (rules("other", "other"), tool.rules))
        self.assertEqual(applied.instruction_sets, (tool.instructions,))
        self.assertEqual(applied.tools, (tool,))
        self.assertEqual(
            applied.sandbox.writable_roots, (Path("/cache/a"), Path("/cache/tool"))
        )
        self.assertEqual(
            applied.sandbox.network_allowed_domains, ("a.example", "tool.example")
        )
        self.assertEqual(apply_tools(applied, tool), applied)

    def test_portable_tool_roots_resolve_before_rendering(self):
        tool = ToolManifest(
            name="cli",
            vars=("CLI_HOME",),
            writable_roots=(Path("${CLI_HOME}"), Path("~/.local/state/cli")),
        )
        resolved = resolve_manifest(
            tool, home=Path("/home/test"), variables={"CLI_HOME": "/work"}
        )
        environment = apply_tools(
            Environment(name="test", sandbox=SandboxPolicy(allow_tmp=False)), resolved
        )
        expected = ["/home/test/.local/state/cli", "/work"]
        self.assertEqual(
            CodexAdapter().render(environment)["sandbox_workspace_write"][
                "writable_roots"
            ],
            expected,
        )
        self.assertEqual(
            ClaudeAdapter().render(environment)["sandbox"]["filesystem"]["allowWrite"],
            expected,
        )

    def test_conflicting_tools_fail_before_lowering(
        self,
    ) -> None:
        with self.assertRaisesRegex(ValueError, "same tool: \\['a'\\]"):
            apply_tools(
                Environment(name="work"), ToolManifest(name="a"), ToolManifest(name="a")
            )
        with self.assertRaisesRegex(ValueError, "same rule set"):
            apply_tools(
                Environment(name="work"),
                ToolManifest(name="a", rules=rules("cli", "a")),
                ToolManifest(name="b", rules=rules("cli", "b")),
            )

    def test_tools_cannot_replace_policy_they_do_not_own(self) -> None:
        environment = apply_tools(
            Environment(
                name="work",
                rules=(rules("deploy", "deploy"),),
                instruction_sets=(instructions("shared", block("Base", "- base")),),
            ),
            ToolManifest(name="a", rules=rules("a-cli", "a")),
        )
        for tool, message in (
            (
                ToolManifest(name="evil", rules=rules("deploy", "evil")),
                "rule set 'deploy' owned by the environment",
            ),
            (
                ToolManifest(
                    name="evil",
                    instructions=instructions("shared", block("Evil", "- evil")),
                ),
                "instruction set 'shared' owned by the environment",
            ),
            (
                ToolManifest(name="b", rules=rules("a-cli", "b")),
                "rule set 'a-cli' owned by 'a'",
            ),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    apply_tools(environment, tool)

    def test_reapplying_a_tool_replaces_its_earlier_contributions_in_place(
        self,
    ) -> None:
        old = ToolManifest(
            name="t",
            rules=rules("t-old", "curl"),
            instructions=instructions("t-docs", block("Old", "- old")),
        )
        environment = apply_tools(
            Environment(name="work", rules=(rules("first", "first"),)),
            old,
            ToolManifest(name="after", rules=rules("after", "after")),
        )

        renamed = apply_tools(environment, replace(old, rules=rules("t-new", "t")))
        dropped = apply_tools(environment, ToolManifest(name="t"))

        self.assertEqual(
            [rule_set.name for rule_set in renamed.rules], ["first", "t-new", "after"]
        )
        self.assertEqual(
            [rule_set.name for rule_set in dropped.rules], ["first", "after"]
        )
        self.assertEqual(dropped.instruction_sets, ())
        # The renamed set belongs to the tool, so the old name is free again.
        apply_tools(renamed, ToolManifest(name="other", rules=rules("t-old", "x")))

    def test_tools_may_share_the_identical_set_the_environment_lists(self) -> None:
        shared = rules("aws", "aws")

        environment = apply_tools(
            Environment(name="work", rules=(shared,)),
            ToolManifest(name="aws", rules=shared),
        )

        self.assertEqual(environment.rules, (shared,))


class EnvironmentNameTests(unittest.TestCase):
    def test_environments_reject_repeated_names_and_unknown_sources(self) -> None:
        for kwargs, message in (
            ({"rules": (rules("a", "a"), rules("a", "b"))}, "rule set names"),
            (
                {"env_vars": (EnvVar("A", value="1"), EnvVar("A", value="2"))},
                "env var names",
            ),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    Environment(name="work", **kwargs)
        with self.assertRaisesRegex(ValueError, "source must be one of"):
            EnvVar("A", source="Host")


class ToolVarsTests(unittest.TestCase):
    def test_optional_vars_do_not_need_environment_definitions(self):
        cli = ToolManifest(
            name="cli", vars=("TOKEN",), optional_vars=("CACHE", "PROFILE")
        )
        environment = apply_tools(
            Environment(name="work", env_vars=(EnvVar("TOKEN", source="host"),)), cli
        )
        check_tool_vars(environment)
        self.assertEqual([var.name for var in environment.env_vars], ["TOKEN"])
        with self.assertRaisesRegex(ValueError, "cli: TOKEN"):
            check_tool_vars(replace(environment, env_vars=()))

    def test_environment_must_define_every_var_its_tools_declare(self) -> None:
        cli = ToolManifest(name="cli", vars=("CLI_TOKEN", "CLI_CACHE"))
        shared = apply_tools(Environment(name="shared"), cli)
        defined = replace(
            shared,
            name="work",
            env_vars=(
                EnvVar("CLI_TOKEN", source="1password", value="secrets.CLI_TOKEN"),
                EnvVar("CLI_CACHE", value="/cache/cli"),
            ),
        )

        check_tool_vars(defined)
        with self.assertRaisesRegex(
            ValueError, "'partial' must define its tools' vars \\(cli: CLI_CACHE\\)"
        ):
            check_tool_vars(
                replace(defined, name="partial", env_vars=defined.env_vars[:1])
            )


class CollectInstallsTests(unittest.TestCase):
    def test_union_is_sorted_deduplicated_and_rejects_conflicts(self) -> None:
        gh = ToolInstall(manager="brew", name="gh", source="gh", commands=("gh",))
        ggh = ToolInstall(manager="uv", name="ggh", source="ggh", commands=("ggh",))
        tool = ToolManifest(name="gh", installs=(gh, ggh))
        first = apply_tools(Environment(name="a"), tool)
        second = apply_tools(Environment(name="b"), tool)

        self.assertEqual(collect_installs(first, second), (gh, ggh))
        conflicting = apply_tools(
            Environment(name="c"),
            ToolManifest(name="other", installs=(replace(gh, source="tap/gh"),)),
        )
        with self.assertRaisesRegex(ValueError, "conflicting brew installs"):
            collect_installs(first, conflicting)


if __name__ == "__main__":
    unittest.main()
