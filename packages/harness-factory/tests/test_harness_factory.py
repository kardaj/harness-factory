import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import tomllib

from harness_factory import (
    Agent,
    ClaudeAdapter,
    CodexAdapter,
    Environment,
    EnvVar,
    HarnessScopedValue,
    HomeFile,
    Mode,
    Notification,
    RuleSet,
    SandboxPolicy,
    ToolServer,
    TrustedProject,
    allow,
    approve_tool,
    ask,
    ask_tool,
    block,
    choice,
    claude_only,
    codex_only,
    deny,
    deny_tool,
    instructions,
    markdown,
    sandbox_exclusions,
    shell,
    trust_children,
)
from harness_factory.adapters import CLAUDE_SANDBOX_EXCLUSION_INTRO
from harness_factory.claude_state import merge_trusted_projects
from harness_factory.deploy import deploy_rendered_home
from harness_factory.live_review import (
    LiveHomeSet,
    format_live_reviews,
    review_live_output,
)
from harness_factory.managed_files import write_managed_files_manifest
from harness_factory.render import (
    retired_config_keys,
    retired_home_files,
    write_harness_homes,
)
from harness_factory.tree_diff import diff_trees, sync_tree


class CodexAdapterTests(unittest.TestCase):
    def test_renders_workspace_tmp_policy_and_env_sources(self) -> None:
        environment = Environment(
            name="work",
            reasoning_tier="best",
            sandbox=SandboxPolicy(
                mode="workspace-write", allow_tmp=True, network=False
            ),
            env_vars=(
                EnvVar("GH_TOKEN", source="host"),
                EnvVar("GH_CONFIG_DIR", value="/tmp/gh-codex"),
            ),
            base_mcp_servers=(
                ToolServer(
                    name="openapi-tools",
                    kind="stdio",
                    command="uvx",
                    args=("--from", "openapi-tools-mcp", "openapi-tools-mcp"),
                ),
            ),
            modes=(
                Mode(
                    name="webdev",
                    mcp_servers=(
                        ToolServer(
                            name="figma", kind="http", url="https://mcp.figma.com/mcp"
                        ),
                    ),
                    trusted_projects=(TrustedProject(Path("/home/dev/src/web-app")),),
                ),
            ),
        )

        rendered = CodexAdapter().render(environment, environment.mode_named("webdev"))

        self.assertEqual(rendered["model"], "gpt-6-sol")
        self.assertEqual(rendered["model_reasoning_effort"], "high")
        self.assertFalse(rendered["sandbox_workspace_write"]["exclude_slash_tmp"])
        self.assertFalse(rendered["sandbox_workspace_write"]["exclude_tmpdir_env_var"])
        shell_policy = rendered["shell_environment_policy"]
        self.assertEqual(shell_policy["inherit"], "all")
        self.assertNotIn("include", shell_policy)
        self.assertTrue(
            {"PATH", "HOME", "USERPROFILE", "GH_TOKEN", "GH_CONFIG_DIR"}.issubset(
                shell_policy["include_only"]
            )
        )
        self.assertNotIn("OPENAI_API_KEY", shell_policy["include_only"])
        self.assertNotIn("*", shell_policy["include_only"])
        self.assertEqual(
            rendered["shell_environment_policy"]["set"],
            {"GH_CONFIG_DIR": "/tmp/gh-codex"},
        )
        self.assertEqual(rendered["mcp_servers"]["openapi-tools"]["command"], "uvx")
        self.assertEqual(
            rendered["mcp_servers"]["figma"]["url"], "https://mcp.figma.com/mcp"
        )
        self.assertEqual(
            rendered["projects"]["/home/dev/src/web-app"]["trust_level"],
            "trusted",
        )

    def test_reasoning_tiers_render_codex_models(self) -> None:
        expected = {
            "best": ("gpt-6-sol", "high"),
            "balanced": ("gpt-5.5", "medium"),
            "cheapest": ("gpt-5.4-mini", "medium"),
        }

        for tier, (model, effort) in expected.items():
            with self.subTest(tier=tier):
                rendered = CodexAdapter().render(
                    Environment(name="test", reasoning_tier=tier)
                )

                self.assertEqual(rendered["model"], model)
                self.assertEqual(rendered["model_reasoning_effort"], effort)

    def test_reasoning_tiers_render_claude_models(self) -> None:
        expected = {
            "best": ("claude-opus-4-8", "high"),
            "balanced": ("sonnet", "high"),
            "cheapest": ("haiku", "high"),
        }

        for tier, (model, effort) in expected.items():
            with self.subTest(tier=tier):
                rendered = ClaudeAdapter().render(
                    Environment(name="test", reasoning_tier=tier)
                )

                self.assertEqual(rendered["model"], model)
                self.assertEqual(rendered["effortLevel"], effort)

    def test_literal_env_vars_can_be_harness_scoped(self) -> None:
        environment = Environment(
            name="test",
            env_vars=(
                EnvVar(
                    "GH_CONFIG_DIR",
                    value=HarnessScopedValue(
                        codex="/tmp/gh-codex", claude="/tmp/gh-claude"
                    ),
                ),
            ),
        )

        codex = CodexAdapter().render(environment)
        claude = ClaudeAdapter().render(environment)

        self.assertEqual(
            codex["shell_environment_policy"]["set"]["GH_CONFIG_DIR"],
            "/tmp/gh-codex",
        )
        self.assertEqual(claude["env"]["GH_CONFIG_DIR"], "/tmp/gh-claude")

    def test_context_window_size_is_harness_scoped(self) -> None:
        environment = Environment(
            name="test",
            context_window_size=claude_only(300_000),
            modes=(Mode(name="codex-window", context_window_size=codex_only(128_000)),),
        )

        codex = CodexAdapter().render(environment)
        codex_mode = CodexAdapter().render(
            environment, environment.mode_named("codex-window")
        )
        claude = ClaudeAdapter().render(environment)
        with TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            ClaudeAdapter().write(environment, output_dir / "claude")
            self.assertFalse((output_dir / "claude" / "claude.config.json").exists())

        self.assertNotIn("model_context_window", codex)
        self.assertEqual(codex_mode["model_context_window"], 128_000)
        self.assertEqual(claude["autoCompactWindow"], 300_000)

    def test_web_search_renders_codex_mode_and_claude_permission(self) -> None:
        environment = Environment(name="test", web_search="live")

        codex = CodexAdapter().render(environment)
        claude = ClaudeAdapter().render(environment)

        self.assertEqual(codex["web_search"], "live")
        self.assertIn("WebSearch", claude["permissions"]["allow"])

    def test_disabled_web_search_denies_claude_tool(self) -> None:
        rendered = ClaudeAdapter().render(
            Environment(name="test", web_search="disabled")
        )

        self.assertIn("WebSearch", rendered["permissions"]["deny"])

    def test_network_allowed_domains_render_for_codex_and_claude(self) -> None:
        environment = Environment(
            name="test",
            sandbox=SandboxPolicy(
                network_allowed_domains=("api.example.com", "api.github.com")
            ),
        )

        codex = CodexAdapter().render(environment)
        claude = ClaudeAdapter().render(environment)

        self.assertTrue(codex["sandbox_workspace_write"]["network_access"])
        self.assertEqual(
            codex["features"]["network_proxy"],
            {
                "enabled": True,
                "domains": {
                    "api.example.com": "allow",
                    "api.github.com": "allow",
                },
            },
        )
        self.assertEqual(
            claude["sandbox"]["network"]["allowedDomains"],
            ["api.example.com", "api.github.com"],
        )

    def test_writable_roots_render_for_codex_and_claude(self) -> None:
        environment = Environment(
            name="test",
            sandbox=SandboxPolicy(writable_roots=(Path("/Users/example/.cache/uv"),)),
        )

        codex = CodexAdapter().render(environment)
        claude = ClaudeAdapter().render(environment)

        self.assertEqual(
            codex["sandbox_workspace_write"]["writable_roots"],
            ["/Users/example/.cache/uv"],
        )
        self.assertEqual(
            claude["sandbox"]["filesystem"]["allowWrite"],
            ["/Users/example/.cache/uv", "/tmp"],
        )

    def test_harness_scoped_writable_roots_render_only_for_their_harness(
        self,
    ) -> None:
        environment = Environment(
            name="test",
            sandbox=SandboxPolicy(
                allow_tmp=False,
                writable_roots=(
                    Path("/shared"),
                    codex_only(Path("/codex")),
                    claude_only(Path("/claude")),
                ),
            ),
        )

        codex = CodexAdapter().render(environment)
        claude = ClaudeAdapter().render(environment)

        self.assertEqual(
            codex["sandbox_workspace_write"]["writable_roots"], ["/codex", "/shared"]
        )
        self.assertEqual(
            claude["sandbox"]["filesystem"]["allowWrite"], ["/claude", "/shared"]
        )
        with self.assertRaisesRegex(ValueError, "absolute"):
            SandboxPolicy(writable_roots=(codex_only(Path("relative")),))
        with self.assertRaisesRegex(ValueError, "absolute"):
            SandboxPolicy(writable_roots=(codex_only("/not-a-path"),))

    def test_order_insensitive_lists_render_sorted_and_deduplicated(self) -> None:
        environment = Environment(
            name="test",
            sandbox=SandboxPolicy(
                writable_roots=(Path("/z"), Path("/a"), Path("/z")),
                network_allowed_domains=("z.example", "a.example", "z.example"),
                network_allowed_mach_lookups=("z.mach", "a.mach"),
                network_allowed_unix_sockets=(Path("/z.sock"), Path("/a.sock")),
            ),
            env_vars=(EnvVar("ZED", value="z"), EnvVar("ALPHA", source="host")),
            rules=(
                RuleSet(
                    name="cli",
                    rules=(allow(shell("zz")), allow(shell("aa")), allow(shell("zz"))),
                    sandbox_excluded_commands=("zz *", "aa *", "zz *"),
                    sandbox_exclusion_reason="needs host services",
                ),
            ),
        )

        codex = CodexAdapter().render(environment)
        claude = ClaudeAdapter().render(environment)

        self.assertEqual(
            codex["sandbox_workspace_write"]["writable_roots"], ["/a", "/z"]
        )
        self.assertEqual(
            list(codex["features"]["network_proxy"]["domains"]),
            ["a.example", "z.example"],
        )
        include_only = codex["shell_environment_policy"]["include_only"]
        self.assertEqual(include_only, sorted(set(include_only)))
        self.assertEqual(claude["permissions"]["allow"], ["Bash(aa *)", "Bash(zz *)"])
        self.assertEqual(
            claude["sandbox"]["filesystem"]["allowWrite"], ["/a", "/tmp", "/z"]
        )
        network = claude["sandbox"]["network"]
        self.assertEqual(network["allowedDomains"], ["a.example", "z.example"])
        self.assertEqual(network["allowMachLookup"], ["a.mach", "z.mach"])
        self.assertEqual(network["allowUnixSockets"], ["/a.sock", "/z.sock"])
        self.assertEqual(claude["sandbox"]["excludedCommands"], ["aa *", "zz *"])

    def test_network_allowed_mach_lookups_render_only_for_claude(self) -> None:
        environment = Environment(
            name="test",
            sandbox=SandboxPolicy(
                network_allowed_mach_lookups=("com.apple.trustd.agent",)
            ),
        )

        codex = CodexAdapter().render(environment)
        claude = ClaudeAdapter().render(environment)

        self.assertFalse(codex["sandbox_workspace_write"]["network_access"])
        self.assertNotIn("features", codex)
        self.assertEqual(
            claude["sandbox"]["network"]["allowMachLookup"],
            ["com.apple.trustd.agent"],
        )

    def test_network_allowed_unix_sockets_render_only_for_claude(self) -> None:
        environment = Environment(
            name="test",
            sandbox=SandboxPolicy(
                network_allowed_unix_sockets=(
                    Path("/Users/example/.docker/run/docker.sock"),
                )
            ),
        )

        codex = CodexAdapter().render(environment)
        claude = ClaudeAdapter().render(environment)

        self.assertFalse(codex["sandbox_workspace_write"]["network_access"])
        self.assertEqual(
            claude["sandbox"]["network"]["allowUnixSockets"],
            ["/Users/example/.docker/run/docker.sock"],
        )

    def test_rule_set_sandbox_exclusions_render_only_for_claude(self) -> None:
        environment = Environment(
            name="test",
            rules=(
                RuleSet(
                    name="xcode",
                    rules=(allow(shell("xcodebuild")),),
                    sandbox_excluded_commands=("xcodebuild *",),
                    sandbox_exclusion_reason="Xcode services are unreachable.",
                ),
            ),
        )

        codex = CodexAdapter().render(environment)
        claude = ClaudeAdapter().render(environment)

        self.assertNotIn("xcodebuild", str(codex))
        self.assertEqual(claude["sandbox"]["excludedCommands"], ["xcodebuild *"])

    def test_workspace_write_renders_claude_accept_edits_and_strict_sandbox(
        self,
    ) -> None:
        rendered = ClaudeAdapter().render(Environment(name="test"))

        self.assertEqual(rendered["permissions"]["defaultMode"], "acceptEdits")
        self.assertEqual(
            rendered["sandbox"],
            {
                "enabled": True,
                "autoAllowBashIfSandboxed": True,
                "allowUnsandboxedCommands": False,
                "filesystem": {"allowWrite": ["/tmp"]},
            },
        )

    def test_sandbox_policy_only_supports_workspace_write(self) -> None:
        with self.assertRaisesRegex(ValueError, "workspace-write"):
            SandboxPolicy(mode="read-only")  # type: ignore[arg-type]

    def test_sandbox_policy_requires_absolute_writable_roots(self) -> None:
        with self.assertRaisesRegex(ValueError, "absolute paths"):
            SandboxPolicy(writable_roots=(Path("relative/cache"),))

    def test_trust_children_expands_git_repos_and_devcontainer_mirrors(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = root / "app"
            app.mkdir()
            (app / ".git").mkdir()
            (app / ".devcontainer").mkdir()
            (app / ".devcontainer" / "devcontainer.json").write_text("{}")
            notes = root / "notes"
            notes.mkdir()
            (notes / ".git").mkdir()
            nested = root / "nested"
            nested.mkdir()
            (nested / ".git").mkdir()
            (nested / ".devcontainer" / "base").mkdir(parents=True)
            (nested / ".devcontainer" / "base" / "devcontainer.json").write_text("{}")
            cache = root / "cache"
            cache.mkdir()

            environment = Environment(
                name="test",
                trusted_projects=(
                    trust_children(
                        root,
                        only_git_repos=True,
                        devcontainer_mirror="/home/vscode",
                    ),
                ),
            )

            rendered = CodexAdapter().render(environment)
            ClaudeAdapter().write(environment, root / "claude")
            claude_config = json.loads(
                (root / "claude" / "claude.config.json").read_text()
            )

        self.assertEqual(
            rendered["projects"],
            {
                str(app): {"trust_level": "trusted"},
                "/home/vscode/app": {"trust_level": "trusted"},
                "/home/vscode/nested": {"trust_level": "trusted"},
                str(nested): {"trust_level": "trusted"},
                str(notes): {"trust_level": "trusted"},
            },
        )
        self.assertEqual(
            sorted(
                claude_config["_harnessFactory"]["trustedProjects"],
                key=lambda project: project["path"],
            ),
            sorted(
                [
                    {"path": str(app), "trustLevel": "trusted"},
                    {"path": str(nested), "trustLevel": "trusted"},
                    {"path": str(notes), "trustLevel": "trusted"},
                    {"path": "/home/vscode/app", "trustLevel": "trusted"},
                    {"path": "/home/vscode/nested", "trustLevel": "trusted"},
                ],
                key=lambda project: project["path"],
            ),
        )

    def test_claude_trust_merge_only_sets_acceptance_flag(self) -> None:
        state = {
            "numStartups": 2,
            "projects": {
                "/repo/existing": {
                    "hasTrustDialogAccepted": False,
                    "lastSessionId": "keep-me",
                },
            },
        }

        merged, changed = merge_trusted_projects(state, ["/repo/existing", "/repo/new"])

        self.assertEqual(changed, ["/repo/existing", "/repo/new"])
        self.assertEqual(merged["numStartups"], 2)
        self.assertEqual(
            merged["projects"]["/repo/existing"],
            {"hasTrustDialogAccepted": True, "lastSessionId": "keep-me"},
        )
        self.assertEqual(
            merged["projects"]["/repo/new"], {"hasTrustDialogAccepted": True}
        )
        self.assertFalse(state["projects"]["/repo/existing"]["hasTrustDialogAccepted"])

    def test_adapters_materialize_agent_configs(self) -> None:
        environment = Environment(
            name="test",
            agents=(
                Agent(
                    name="explorer",
                    description="Explore repositories.",
                    developer_instructions="Report findings.",
                    reasoning_tier="cheapest",
                ),
            ),
        )

        with TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            CodexAdapter().write(environment, output_dir / "codex")
            ClaudeAdapter().write(environment, output_dir / "claude")

            self.assertTrue(
                (output_dir / "codex" / "agents" / "explorer.toml").is_file()
            )
            self.assertTrue(
                (output_dir / "claude" / "agents" / "explorer.md").is_file()
            )

    def test_adapters_materialize_instruction_files(self) -> None:
        with TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            instruction_file = output_dir / "python-workflow.md"
            instruction_file.write_text(
                "# Python Workflow\n\nUse `uv run --active`.",
                encoding="utf-8",
            )
            environment = Environment(
                name="test",
                instruction_sets=(instructions("shared", markdown(instruction_file)),),
            )

            CodexAdapter().write(environment, output_dir / "codex")
            ClaudeAdapter().write(environment, output_dir / "claude")

            codex_instructions = (output_dir / "codex" / "AGENTS.md").read_text()
            claude_instructions = (output_dir / "claude" / "CLAUDE.md").read_text()

        self.assertNotIn("<INSTRUCTIONS>", codex_instructions)
        self.assertNotIn("Generated by harness_factory", codex_instructions)
        self.assertNotIn("AGENTS.md instructions", codex_instructions)
        self.assertIn("## Python Workflow", codex_instructions)
        self.assertNotIn("<INSTRUCTIONS>", claude_instructions)
        self.assertIn("## Python Workflow", claude_instructions)

    def test_adapters_filter_harness_scoped_instruction_sets(self) -> None:
        environment = Environment(
            name="test",
            instruction_sets=(
                instructions(
                    "shared",
                    block("Shared", "Visible in both harnesses."),
                ),
                instructions(
                    "claude-only",
                    block("Claude Commands", "Visible only in Claude."),
                    harnesses=("claude",),
                ),
            ),
        )

        with TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            CodexAdapter().write(environment, output_dir / "codex")
            ClaudeAdapter().write(environment, output_dir / "claude")

            codex_instructions = (output_dir / "codex" / "AGENTS.md").read_text()
            claude_instructions = (output_dir / "claude" / "CLAUDE.md").read_text()

        self.assertIn("## Shared", codex_instructions)
        self.assertNotIn("## Claude Commands", codex_instructions)
        self.assertIn("## Shared", claude_instructions)
        self.assertIn("## Claude Commands", claude_instructions)

    def test_claude_instructions_list_sandbox_excluded_commands(self) -> None:
        environment = Environment(
            name="test",
            instruction_sets=(
                instructions(
                    "shared",
                    block("Shared", "Both."),
                    sandbox_exclusions(),
                    block("Later", "After exclusions."),
                ),
            ),
            rules=(
                RuleSet(
                    name="simulator",
                    sandbox_excluded_commands=("xcrun *", "swift *"),
                    sandbox_exclusion_reason="CoreSimulator is unreachable.",
                    rules=(allow(shell("xcrun")),),
                ),
            ),
        )

        with TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            CodexAdapter().write(environment, output_dir / "codex")
            ClaudeAdapter().write(environment, output_dir / "claude")

            codex_instructions = (output_dir / "codex" / "AGENTS.md").read_text()
            claude_instructions = (output_dir / "claude" / "CLAUDE.md").read_text()

        self.assertIn("## Shared\n\nBoth.\n\n## Later", codex_instructions)
        self.assertIn(
            "## Shared\n\nBoth.\n\n"
            "## Sandbox-Excluded Commands\n\n"
            f"{CLAUDE_SANDBOX_EXCLUSION_INTRO}\n\n"
            "- `xcrun *`, `swift *`: CoreSimulator is unreachable.\n\n"
            "## Later",
            claude_instructions,
        )

    def test_instruction_file_body_headings_must_be_nested(self) -> None:
        with TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            instruction_file = output_dir / "review.md"
            instruction_file.write_text(
                "# Review\n\n## Gemini\n\nUse as leads.",
                encoding="utf-8",
            )
            environment = Environment(
                name="test",
                instruction_sets=(instructions("shared", markdown(instruction_file)),),
            )

            with self.assertRaisesRegex(ValueError, "body headings"):
                CodexAdapter().write(environment, output_dir / "codex")

    def test_codex_materializes_harness_scoped_home_files(self) -> None:
        with TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            source = output_dir / "notify-source.sh"
            source.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            environment = Environment(
                name="test",
                home_files=(
                    HomeFile(
                        relative_path=Path("notify.sh"),
                        source_path=source,
                        executable=True,
                        harnesses=("codex",),
                    ),
                ),
            )

            CodexAdapter().write(environment, output_dir / "codex")
            ClaudeAdapter().write(environment, output_dir / "claude")

            codex_notify = output_dir / "codex" / "notify.sh"
            claude_notify = output_dir / "claude" / "notify.sh"

            self.assertEqual(codex_notify.read_text(), source.read_text())
            self.assertTrue(os.access(codex_notify, os.X_OK))
            self.assertFalse(claude_notify.exists())

    def test_notification_renders_for_codex_and_claude(self) -> None:
        with TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            source = output_dir / "notify-source.sh"
            source.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            environment = Environment(
                name="test",
                notification=Notification(
                    script=HomeFile(
                        relative_path=Path("notify.sh"),
                        source_path=source,
                        executable=True,
                    )
                ),
            )

            codex = CodexAdapter().render(environment)
            ClaudeAdapter().write(environment, output_dir / "claude")
            claude_settings = json.loads(
                (output_dir / "claude" / "settings.json").read_text()
            )

            self.assertEqual(
                codex["notify"],
                ["bash", "-lc", "${CODEX_HOME:-$HOME/.codex}/notify.sh"],
            )
            self.assertTrue((output_dir / "claude" / "notify.sh").is_file())
            self.assertTrue(os.access(output_dir / "claude" / "notify.sh", os.X_OK))
            self.assertEqual(
                claude_settings["hooks"]["Notification"][0]["hooks"][0]["type"],
                "command",
            )
            self.assertIn(
                str((output_dir / "claude" / "notify.sh").resolve()),
                claude_settings["hooks"]["Notification"][0]["hooks"][0]["command"],
            )

    def test_notification_uses_factory_owned_script_by_default(self) -> None:
        with TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            environment = Environment(name="test", notification=Notification())

            CodexAdapter().write(environment, output_dir / "codex")
            ClaudeAdapter().write(environment, output_dir / "claude")

            codex_notify = output_dir / "codex" / "notify.sh"
            claude_notify = output_dir / "claude" / "notify.sh"

            self.assertIn("afplay", codex_notify.read_text())
            self.assertEqual(codex_notify.read_text(), claude_notify.read_text())
            self.assertTrue(os.access(codex_notify, os.X_OK))
            self.assertTrue(os.access(claude_notify, os.X_OK))

    def test_disabled_notification_copies_script_without_enabling_hooks(self) -> None:
        with TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            environment = Environment(
                name="test", notification=Notification(enabled=False)
            )

            codex = CodexAdapter().render(environment)
            CodexAdapter().write(environment, output_dir / "codex")
            ClaudeAdapter().write(environment, output_dir / "claude")
            claude_settings = json.loads(
                (output_dir / "claude" / "settings.json").read_text()
            )

            self.assertNotIn("notify", codex)
            self.assertNotIn("tui", codex)
            self.assertNotIn("hooks", claude_settings)
            self.assertTrue((output_dir / "codex" / "notify.sh").is_file())
            self.assertTrue((output_dir / "claude" / "notify.sh").is_file())

    def test_tool_approvals_render_codex_mcp_tool_config(self) -> None:
        environment = Environment(
            name="test",
            base_mcp_servers=(
                ToolServer(
                    name="newrelic",
                    kind="http",
                    url="https://mcp.newrelic.com/mcp/",
                    tool_approvals=(approve_tool("get_entity"),),
                ),
            ),
        )

        rendered = CodexAdapter().render(environment)

        self.assertEqual(
            rendered["mcp_servers"]["newrelic"]["tools"]["get_entity"],
            {"approval_mode": "approve"},
        )

    def test_tool_approvals_render_claude_permissions(self) -> None:
        environment = Environment(
            name="test",
            base_mcp_servers=(
                ToolServer(
                    name="newrelic",
                    kind="http",
                    url="https://mcp.newrelic.com/mcp/",
                    tool_approvals=(
                        approve_tool("get_entity"),
                        ask_tool("analyze_transactions"),
                        deny_tool("delete_entity"),
                    ),
                ),
            ),
        )

        rendered = ClaudeAdapter().render(environment)

        self.assertIn("mcp__newrelic__get_entity", rendered["permissions"]["allow"])
        self.assertIn(
            "mcp__newrelic__analyze_transactions", rendered["permissions"]["ask"]
        )
        self.assertIn("mcp__newrelic__delete_entity", rendered["permissions"]["deny"])
        self.assertNotIn("mcpServers", rendered)

    def test_claude_settings_use_native_file_shapes(self) -> None:
        environment = Environment(
            name="test",
            env_vars=(EnvVar("GH_CONFIG_DIR", value="/tmp/gh-claude"),),
            base_mcp_servers=(
                ToolServer(
                    name="newrelic",
                    kind="http",
                    url="https://mcp.newrelic.com/mcp/",
                ),
            ),
            agents=(
                Agent(
                    name="explorer",
                    description="Explore repositories.",
                    developer_instructions="Report findings.",
                    reasoning_tier="cheapest",
                ),
            ),
            context_window_size=claude_only(300_000),
        )

        with TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            ClaudeAdapter().write(environment, output_dir)
            settings = json.loads((output_dir / "settings.json").read_text())
            mcp_config = json.loads((output_dir / ".mcp.json").read_text())
            self.assertFalse((output_dir / "claude.config.json").exists())
            agent_content = (output_dir / "agents" / "explorer.md").read_text()

        self.assertEqual(settings["env"], {"GH_CONFIG_DIR": "/tmp/gh-claude"})
        self.assertNotIn("personality", settings)
        self.assertNotIn("mcpServers", settings)
        self.assertNotIn("agents", settings)
        self.assertNotIn("_harnessFactory", settings)
        self.assertIn("newrelic", mcp_config["mcpServers"])
        self.assertEqual(settings["autoCompactWindow"], 300_000)
        self.assertTrue(agent_content.startswith("---\n"))
        self.assertIn('name: "explorer"', agent_content)
        self.assertIn("Report findings.", agent_content)

    def test_rule_sets_render_to_codex_rules_and_claude_permissions(self) -> None:
        rules = RuleSet(
            name="git-safe",
            rules=(
                allow(shell("git", choice("status", "diff"))),
                ask(shell("git", choice("pull", "fetch"))),
                deny(shell("git", choice("push", "reset"))),
            ),
        )
        environment = Environment(name="test", rules=(rules,))

        claude = ClaudeAdapter().render(environment)

        self.assertEqual(
            claude["permissions"]["allow"],
            ["Bash(git diff *)", "Bash(git status *)"],
        )
        self.assertEqual(
            claude["permissions"]["ask"],
            ["Bash(git fetch *)", "Bash(git pull *)"],
        )
        self.assertEqual(
            claude["permissions"]["deny"],
            ["Bash(git push *)", "Bash(git reset *)"],
        )

        with TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            CodexAdapter().write(environment, output_dir)
            content = (output_dir / "rules" / "git-safe.rules").read_text()

        self.assertIn(
            'prefix_rule(pattern=["git", ["status", "diff"]], decision="allow")',
            content,
        )
        self.assertIn(
            'prefix_rule(pattern=["git", ["pull", "fetch"]], decision="prompt")',
            content,
        )
        self.assertIn(
            'prefix_rule(pattern=["git", ["push", "reset"]], decision="forbidden")',
            content,
        )

    def test_codex_policy_preview_omits_runtime_configuration(self) -> None:
        environment = Environment(
            name="test",
            instruction_sets=(
                instructions("shared", block("Workflow", "Use project tooling.")),
            ),
            rules=(RuleSet(name="project", rules=(allow(shell("uv", "run")),)),),
            env_vars=(EnvVar("SECRET", source="1password", value="unresolved"),),
        )

        with TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            CodexAdapter().write_policy_preview(environment, output_dir)

            self.assertEqual(
                (output_dir / "AGENTS.md").read_text(),
                "## Workflow\n\nUse project tooling.\n",
            )
            self.assertTrue((output_dir / "rules/project.rules").is_file())
            self.assertFalse((output_dir / "config.toml").exists())

    def test_claude_policy_preview_omits_secrets_and_mcp_configuration(self) -> None:
        environment = Environment(
            name="test",
            instruction_sets=(
                instructions("shared", block("Workflow", "Use project tooling.")),
            ),
            rules=(RuleSet(name="project", rules=(allow(shell("uv", "run")),)),),
            env_vars=(EnvVar("SECRET", source="1password", value="unresolved"),),
            base_mcp_servers=(
                ToolServer(name="private", kind="http", url="https://example.com"),
            ),
        )

        with TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            ClaudeAdapter().write_policy_preview(environment, output_dir)
            settings = json.loads((output_dir / "settings.json").read_text())

            self.assertIn("Bash(uv run *)", settings["permissions"]["allow"])
            self.assertTrue(settings["sandbox"]["enabled"])
            self.assertNotIn("env", settings)
            self.assertNotIn("mcpServers", settings)
            self.assertIn("## Workflow", (output_dir / "CLAUDE.md").read_text())

    def test_tree_diff_ignores_unmanaged_files_by_default(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            found = root / "found"
            expected = root / "expected"
            found.mkdir()
            expected.mkdir()
            (found / "state.sqlite").write_text("runtime", encoding="utf-8")

            self.assertEqual(diff_trees(found, expected), [])
            self.assertEqual(
                [
                    diff.kind
                    for diff in diff_trees(found, expected, include_removed=True)
                ],
                ["removed"],
            )

    def test_sync_tree_preserves_runtime_toml_keys(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            found = root / "found"
            expected = root / "expected"
            found.mkdir()
            expected.mkdir()
            (found / "config.toml").write_text(
                'model = "old"\n\n[plugins.runtime]\nenabled = true\n',
                encoding="utf-8",
            )
            (found / "state.sqlite").write_text("runtime", encoding="utf-8")
            (expected / "config.toml").write_text(
                'model = "new"\nmodel_reasoning_effort = "high"\n',
                encoding="utf-8",
            )

            sync_tree(found, expected)

            load = getattr(tomllib, "load", None)
            if load is None:
                config = tomllib.loads(
                    (found / "config.toml").read_text(encoding="utf-8")
                )
            else:
                with (found / "config.toml").open("rb") as handle:
                    config = load(handle)
            self.assertEqual(config["model"], "new")
            self.assertEqual(config["model_reasoning_effort"], "high")
            self.assertTrue(config["plugins"]["runtime"]["enabled"])
            self.assertEqual((found / "state.sqlite").read_text(), "runtime")

    def test_sync_tree_removes_only_retired_config_keys(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            found = root / "found"
            expected = root / "expected"
            found.mkdir()
            expected.mkdir()
            (found / "config.toml").write_text(
                "\n".join(
                    (
                        'model = "old"',
                        "",
                        "[mcp_servers.runtime]",
                        'url = "https://runtime.example.com"',
                        "",
                        "[mcp_servers.sentry]",
                        'url = "https://mcp.sentry.dev/mcp"',
                        "",
                    )
                ),
                encoding="utf-8",
            )
            (expected / "config.toml").write_text('model = "new"\n', encoding="utf-8")

            sync_tree(
                found,
                expected,
                config_key_removals={Path("config.toml"): (("mcp_servers", "sentry"),)},
            )

            config = tomllib.loads((found / "config.toml").read_text(encoding="utf-8"))
            self.assertEqual(config["model"], "new")
            self.assertIn("runtime", config["mcp_servers"])
            self.assertNotIn("sentry", config["mcp_servers"])

    def test_codex_deployment_copies_only_manifested_files(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            rendered_home = root / "rendered" / "codex" / "kardaj"
            target_home = root / "target"
            rendered_runtime = rendered_home / "computer-use"
            target_runtime = target_home / "computer-use"
            rendered_runtime.mkdir(parents=True)
            target_runtime.mkdir(parents=True)
            (rendered_home / "config.toml").write_text(
                'model = "new"\n', encoding="utf-8"
            )
            write_managed_files_manifest(rendered_home)
            (rendered_runtime / "config.json").write_text(
                '{"source": "rendered"}\n', encoding="utf-8"
            )
            (rendered_runtime / "session.toml").write_text(
                'source = "rendered"\n', encoding="utf-8"
            )
            rendered_system_skill = (
                rendered_home
                / "skills/.system/plugin-creator/scripts/identifier_validation.py"
            )
            rendered_system_skill.parent.mkdir(parents=True)
            rendered_system_skill.write_text("runtime skill\n", encoding="utf-8")
            (target_runtime / "config.json").write_text(
                '{"source": "runtime"}\n', encoding="utf-8"
            )

            with patch.object(
                Path,
                "rglob",
                side_effect=AssertionError("deployment scanned runtime paths"),
            ):
                deploy_rendered_home(
                    Environment(name="kardaj"),
                    "codex",
                    root / "rendered",
                    target_home,
                )

            self.assertEqual(
                (target_home / "config.toml").read_text(encoding="utf-8"),
                'model = "new"\n',
            )
            self.assertEqual(
                (target_runtime / "config.json").read_text(encoding="utf-8"),
                '{"source": "runtime"}\n',
            )
            self.assertFalse((target_runtime / "session.toml").exists())
            self.assertFalse(
                (
                    target_home
                    / "skills/.system/plugin-creator/scripts/identifier_validation.py"
                ).exists()
            )

    def test_codex_deployment_prunes_retired_mcp_from_agent_config(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            rendered_home = root / "rendered/codex/kardaj"
            rendered_agent = rendered_home / "agents/explorer.toml"
            rendered_agent.parent.mkdir(parents=True)
            (rendered_home / "config.toml").write_text(
                'model = "new"\n', encoding="utf-8"
            )
            rendered_agent.write_text('name = "explorer"\n', encoding="utf-8")
            write_managed_files_manifest(rendered_home)

            target_home = root / "target"
            target_agent = target_home / "agents/explorer.toml"
            target_agent.parent.mkdir(parents=True)
            target_agent.write_text(
                "\n".join(
                    (
                        'name = "explorer"',
                        "",
                        "[mcp_servers.runtime]",
                        'url = "https://runtime.example.com"',
                        "",
                        "[mcp_servers.openapi-tools]",
                        'command = "uvx"',
                        "",
                    )
                ),
                encoding="utf-8",
            )

            deploy_rendered_home(
                Environment(
                    name="kardaj",
                    agents=(Agent(name="explorer", description="Explore"),),
                    retired_mcp_servers=("openapi-tools",),
                ),
                "codex",
                root / "rendered",
                target_home,
            )

            config = tomllib.loads(target_agent.read_text(encoding="utf-8"))
            self.assertIn("runtime", config["mcp_servers"])
            self.assertNotIn("openapi-tools", config["mcp_servers"])

    def test_retired_agents_are_archived_during_render_and_deployment(self) -> None:
        names = ("explorer", "worker", "runner")
        old = Environment(
            name="test",
            agents=tuple(Agent(name=name, description=name) for name in names),
            harness_overrides={"codex": {"agents": {"max_threads": 4}}},
        )
        current = Environment(
            name="test",
            retired_agents=names,
            harness_overrides={"codex": {"agents": {"max_threads": 4}}},
        )
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            found, expected = root / "found", root / "expected"
            write_harness_homes(found, environments=(old,))
            for harness, suffix in (("codex", "toml"), ("claude", "md")):
                home = root / harness
                deploy_rendered_home(old, harness, found, home)
                (home / f"agents/explorer.{suffix}").write_text(
                    "local edits to preserve"
                )
                (home / f"agents/custom.{suffix}").write_text("unrelated agent")
            write_harness_homes(expected, environments=(current,))
            options = {
                "config_key_removals": retired_config_keys((current,)),
                "retired_paths": retired_home_files((current,)),
            }
            diffs = diff_trees(found, expected, **options)
            self.assertEqual(sum(diff.kind == "retired" for diff in diffs), 6)
            self.assertTrue((found / "codex/test/agents/explorer.toml").exists())
            self.assertFalse((found / ".harness-retired").exists())
            sync_tree(found, expected, **options)
            self.assertEqual(diff_trees(found, expected, **options), [])
            self.assertEqual(
                len(list((found / ".harness-retired").rglob("explorer.*"))), 2
            )
            for harness, suffix in (("codex", "toml"), ("claude", "md")):
                home = root / harness
                deploy_rendered_home(current, harness, found, home)
                for name in names:
                    self.assertFalse((home / f"agents/{name}.{suffix}").exists())
                self.assertEqual(
                    (home / f"agents/custom.{suffix}").read_text(), "unrelated agent"
                )
                archived = list((home / ".harness-retired").rglob(f"explorer.{suffix}"))
                self.assertEqual(len(archived), 1)
                self.assertEqual(archived[0].read_text(), "local edits to preserve")
                self.assertEqual(deploy_rendered_home(current, harness, found, home), 0)
            for home in (found / "codex/test", root / "codex"):
                config = tomllib.loads((home / "config.toml").read_text())
                self.assertEqual(config["agents"], {"max_threads": 4})

    def test_retirement_rejects_unsafe_paths_and_symlinks(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            found, expected = root / "found", root / "expected"
            found.mkdir()
            expected.mkdir()
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "explorer.md"
            sentinel.write_text("preserve")
            (found / "agents").symlink_to(outside, target_is_directory=True)
            for path in (Path("agents/explorer.md"), Path("../outside/explorer.md")):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    sync_tree(found, expected, retired_paths=frozenset((path,)))
            self.assertEqual(sentinel.read_text(), "preserve")
            self.assertFalse((found / ".harness-retired").exists())

        with self.assertRaises(ValueError):
            Environment(name="test", retired_agents=("../escape",))
        with self.assertRaises(ValueError):
            Environment(
                name="test",
                agents=(Agent(name="explorer", description="Explore"),),
                retired_agents=("explorer",),
            )

    def test_deployment_skips_excluded_paths(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            rendered_home = root / "rendered" / "claude" / "kardaj"
            target_home = root / "target"
            rendered_home.mkdir(parents=True)
            (rendered_home / "settings.json").write_text("{}\n", encoding="utf-8")
            (rendered_home / "CLAUDE.md").write_text("## Workflow\n", encoding="utf-8")
            write_managed_files_manifest(rendered_home)

            deploy_rendered_home(
                Environment(name="kardaj"),
                "claude",
                root / "rendered",
                target_home,
                excluded_paths=(Path("CLAUDE.md"),),
            )

            self.assertTrue((target_home / "settings.json").is_file())
            self.assertFalse((target_home / "CLAUDE.md").exists())

    def test_retired_env_vars_map_to_each_harness_config(self) -> None:
        removals = retired_config_keys(
            (
                Environment(
                    name="kardaj",
                    retired_env_vars=("GH_TOKEN",),
                ),
            )
        )

        self.assertEqual(
            removals[Path("codex/kardaj/config.toml")],
            (("shell_environment_policy", "set", "GH_TOKEN"),),
        )
        self.assertEqual(
            removals[Path("claude/kardaj/settings.json")],
            (("env", "GH_TOKEN"),),
        )

    def test_retired_mcp_servers_map_to_codex_agent_configs(self) -> None:
        removals = retired_config_keys(
            (
                Environment(
                    name="kardaj",
                    agents=(
                        Agent(name="explorer", description="Explore"),
                        Agent(
                            name="custom",
                            description="Custom",
                            config_file=Path("special/custom.toml"),
                        ),
                    ),
                    retired_mcp_servers=("openapi-tools",),
                ),
            )
        )
        expected = (("mcp_servers", "openapi-tools"),)

        self.assertEqual(removals[Path("codex/kardaj/config.toml")], expected)
        self.assertEqual(removals[Path("codex/kardaj/agents/explorer.toml")], expected)
        self.assertEqual(removals[Path("codex/kardaj/special/custom.toml")], expected)
        self.assertEqual(
            removals[Path("claude/kardaj/.mcp.json")],
            (("mcpServers", "openapi-tools"),),
        )

    def test_retired_notification_maps_to_each_harness_config(self) -> None:
        removals = retired_config_keys(
            (Environment(name="kardaj", retired_notification=True),)
        )

        self.assertEqual(
            removals[Path("codex/kardaj/config.toml")],
            (("notify",), ("tui", "notifications")),
        )
        self.assertEqual(
            removals[Path("claude/kardaj/settings.json")],
            (("hooks", "Notification"),),
        )

    def test_deployment_removes_only_retired_notification_keys(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            rendered = root / "rendered"
            environment = Environment(name="kardaj", retired_notification=True)

            codex_rendered = rendered / "codex/kardaj"
            codex_rendered.mkdir(parents=True)
            (codex_rendered / "config.toml").write_text(
                'model = "new"\n', encoding="utf-8"
            )
            write_managed_files_manifest(codex_rendered)
            codex_target = root / "codex-target"
            codex_target.mkdir()
            (codex_target / "config.toml").write_text(
                'notify = ["notify.sh"]\n\n[tui]\nnotifications = true\n\n[tui.runtime]\nkeep = true\n',
                encoding="utf-8",
            )

            deploy_rendered_home(environment, "codex", rendered, codex_target)

            codex = tomllib.loads(
                (codex_target / "config.toml").read_text(encoding="utf-8")
            )
            self.assertNotIn("notify", codex)
            self.assertNotIn("notifications", codex["tui"])
            self.assertTrue(codex["tui"]["runtime"]["keep"])

            claude_rendered = rendered / "claude/kardaj"
            claude_rendered.mkdir(parents=True)
            (claude_rendered / "settings.json").write_text(
                '{"model": "new"}\n', encoding="utf-8"
            )
            write_managed_files_manifest(claude_rendered)
            claude_target = root / "claude-target"
            claude_target.mkdir()
            (claude_target / "settings.json").write_text(
                json.dumps(
                    {
                        "hooks": {
                            "Notification": ["notify.sh"],
                            "Stop": ["keep-runtime-hook"],
                        }
                    }
                ),
                encoding="utf-8",
            )

            deploy_rendered_home(environment, "claude", rendered, claude_target)

            claude = json.loads(
                (claude_target / "settings.json").read_text(encoding="utf-8")
            )
            self.assertNotIn("Notification", claude["hooks"])
            self.assertEqual(claude["hooks"]["Stop"], ["keep-runtime-hook"])

    def test_live_review_reports_extra_claude_mcp_permission(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            live = root / "live" / "claude" / "work"
            expected = root / "expected" / "claude" / "work"
            live.mkdir(parents=True)
            expected.mkdir(parents=True)
            (live / "settings.json").write_text(
                json.dumps(
                    {
                        "permissions": {
                            "allow": [
                                "mcp__newrelic__get_entity",
                                "mcp__newrelic__list_accounts",
                            ]
                        }
                    }
                ),
                encoding="utf-8",
            )
            (expected / "settings.json").write_text(
                json.dumps({"permissions": {"allow": ["mcp__newrelic__get_entity"]}}),
                encoding="utf-8",
            )

            output = format_live_reviews(
                review_live_output(root / "live", root / "expected")
            )

        self.assertIn("work:", output)
        self.assertIn("claude:", output)
        self.assertIn("permissions.allow:", output)
        self.assertIn("mcp__newrelic__list_accounts", output)
        self.assertIn('approve_tool("list_accounts")', output)

    def test_live_review_reports_extra_codex_project_and_approval(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            live = root / "live" / "codex" / "work"
            expected = root / "expected" / "codex" / "work"
            live.mkdir(parents=True)
            expected.mkdir(parents=True)
            (live / "config.toml").write_text(
                "\n".join(
                    (
                        'model = "gpt-5.5"',
                        "",
                        '[projects."/repo/new"]',
                        'trust_level = "trusted"',
                        "",
                        "[mcp_servers.newrelic.tools.list_accounts]",
                        'approval_mode = "approve"',
                        "",
                    )
                ),
                encoding="utf-8",
            )
            (expected / "config.toml").write_text(
                'model = "gpt-5.5"\n', encoding="utf-8"
            )

            output = format_live_reviews(
                review_live_output(root / "live", root / "expected")
            )

        self.assertIn("trusted_projects:", output)
        self.assertIn("/repo/new", output)
        self.assertIn("mcp_tool_approvals:", output)
        self.assertIn("newrelic.list_accounts", output)
        self.assertIn('approve_tool("list_accounts")', output)

    def test_live_review_reports_extra_codex_rule(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            live = root / "live" / "codex" / "work" / "rules"
            expected = root / "expected" / "codex" / "work" / "rules"
            live.mkdir(parents=True)
            expected.mkdir(parents=True)
            (root / "live" / "codex" / "work" / "config.toml").write_text(
                'model = "gpt-5.5"\n',
                encoding="utf-8",
            )
            (root / "expected" / "codex" / "work" / "config.toml").write_text(
                'model = "gpt-5.5"\n',
                encoding="utf-8",
            )
            (expected / "default.rules").write_text(
                'prefix_rule(pattern=["rg"], decision="allow")\n',
                encoding="utf-8",
            )
            (live / "default.rules").write_text(
                "\n".join(
                    (
                        'prefix_rule(pattern=["rg"], decision="allow")',
                        'prefix_rule(pattern=["aws", "sts"], decision="allow")',
                    )
                ),
                encoding="utf-8",
            )

            output = format_live_reviews(
                review_live_output(root / "live", root / "expected")
            )

        self.assertIn("rules.default:", output)
        self.assertIn('{"decision":"allow","pattern":["aws","sts"]}', output)
        self.assertIn('allow(shell("aws", "sts")) on RuleSet', output)

    def test_live_review_treats_codex_rule_as_adopted_across_rule_sets(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            live = root / "live" / "codex" / "work" / "rules"
            expected = root / "expected" / "codex" / "work" / "rules"
            live.mkdir(parents=True)
            expected.mkdir(parents=True)
            (root / "live" / "codex" / "work" / "config.toml").write_text(
                'model = "gpt-5.5"\n',
                encoding="utf-8",
            )
            (root / "expected" / "codex" / "work" / "config.toml").write_text(
                'model = "gpt-5.5"\n',
                encoding="utf-8",
            )
            (live / "default.rules").write_text(
                'prefix_rule(pattern=["aws", "amplify", "get-app"], decision="allow")',
                encoding="utf-8",
            )
            (expected / "aws-cli.rules").write_text(
                'prefix_rule(pattern=["aws", "amplify", "get-app"], decision="allow")',
                encoding="utf-8",
            )

            output = format_live_reviews(
                review_live_output(root / "live", root / "expected")
            )

        self.assertNotIn("rules.default:", output)
        self.assertNotIn("aws.amplify.get-app", output)

    def test_live_review_reports_user_space_home_set(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            live = root / "live-user" / "codex"
            expected = root / "expected" / "codex" / "work"
            live.mkdir(parents=True)
            expected.mkdir(parents=True)
            (live / "config.toml").write_text(
                '[projects."/repo/user-only"]\ntrust_level = "trusted"\n',
                encoding="utf-8",
            )
            (expected / "config.toml").write_text("", encoding="utf-8")

            output = format_live_reviews(
                review_live_output(
                    root / "live",
                    root / "expected",
                    extra_home_sets=(
                        LiveHomeSet(
                            environment="user",
                            codex_live=live,
                            codex_expected=expected,
                            claude_live=root / "live-user" / "claude",
                            claude_expected=root / "expected" / "claude" / "work",
                        ),
                    ),
                )
            )

        self.assertIn("user:", output)
        self.assertIn("codex:", output)
        self.assertIn("/repo/user-only", output)


if __name__ == "__main__":
    unittest.main()
