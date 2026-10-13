import json
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from harness_factory import (
    Environment,
    EnvVar,
    HarnessScopedValue,
    SandboxPolicy,
    ToolInstall,
    ToolManifest,
    allow,
    ask,
    apply_tools,
    block,
    check_tool_vars,
    choice,
    deny,
    instructions,
    shell,
)
from harness_manifest import RuleSet, codex_only, to_dict, to_json
from harness_factory.exports import (
    Export,
    ExportError,
    ManifestExport,
    apply_exports,
    bullets,
)
from harness_secrets.process import (
    ExecutableUnavailable,
    OutputLimitExceeded,
    ProcessResult,
    ProcessTimeout,
    child_environment,
)

TOOL = ToolManifest(name="cli")
EXPORT = Export(
    executable="cli", title="CLI", required=True, body=bullets, commands=("cli",)
)


def policy(**changes: list) -> str:
    return json.dumps(
        {
            "schema": 1,
            "allow": [{"command": ["cli", "list"], "reason": "read"}],
            "deny": [{"command": ["native"], "reason": "use cli"}],
            "unsandboxed": [{"command": ["cli"], "reason": "host services"}],
            **changes,
        }
    )


def exported(export: Export, lockdown: str, tool: ToolManifest = TOOL) -> Environment:
    outputs = {"lockdown": lockdown, "instructions": "- Use `cli`.\n"}
    with (
        patch(
            "harness_factory.exports.trusted_executable",
            return_value="/nonexistent/cli" if export.required else None,
        ),
        patch(
            "harness_factory.exports._run",
            side_effect=lambda executable, command: outputs[command],
        ),
    ):
        return apply_exports(
            apply_tools(Environment(name="work"), tool),
            {"cli": export},
            bin_dir=Path("/nonexistent"),
        )


class ExportTests(unittest.TestCase):
    def test_policies_may_deny_anything_but_allow_only_their_own_commands(
        self,
    ) -> None:
        export = EXPORT

        environment = exported(export, policy())

        self.assertEqual(environment.tools[0].rules.name, "cli")
        self.assertEqual(environment.tools[0].instructions.blocks[0].title, "CLI")
        for changes, message in (
            ({"allow": [{"command": ["other"], "reason": "x"}]}, "may be allowed"),
            (
                {"unsandboxed": [{"command": ["other"], "reason": "x"}]},
                "may bypass the sandbox",
            ),
        ):
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(ExportError, message),
            ):
                exported(export, policy(**changes))

    def test_exports_without_commands_import_only_instructions(self) -> None:
        export = Export(executable="cli", title="CLI", required=True, body=bullets)

        environment = exported(export, "not read")

        self.assertIsNone(environment.tools[0].rules)

    def test_legacy_exports_use_the_bounded_runner(self):
        with (
            patch(
                "harness_factory.exports.trusted_executable",
                return_value="/managed/bin/cli",
            ),
            patch(
                "harness_factory.exports.run",
                side_effect=[
                    ProcessResult(0, policy(), ""),
                    ProcessResult(0, "- Use `cli`.\n", ""),
                ],
            ) as run,
        ):
            apply_exports(
                apply_tools(Environment(name="work"), TOOL),
                {"cli": EXPORT},
                bin_dir=Path("/managed/bin"),
            )
        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [["/managed/bin/cli", "lockdown"], ["/managed/bin/cli", "instructions"]],
        )

    def test_exports_replace_fallbacks_whatever_their_names(self) -> None:
        fallback = ToolManifest(
            name="cli",
            rules=RuleSet(name="cli-fallback", rules=(allow(shell("curl")),)),
            instructions=instructions("cli-docs", block("Old", "- old")),
        )

        environment = exported(EXPORT, policy(), fallback)

        self.assertEqual([rule_set.name for rule_set in environment.rules], ["cli"])
        self.assertEqual(
            [instruction_set.name for instruction_set in environment.instruction_sets],
            ["cli"],
        )

    def test_missing_optional_clis_keep_fallbacks_and_check_errors_are_wrapped(
        self,
    ) -> None:
        optional = replace(EXPORT, required=False)
        # An imported export would have given the tool a rule set.
        self.assertEqual(exported(optional, policy()).tools, (TOOL,))

        def reject(policy: RuleSet) -> None:
            raise ValueError("cli admin must be denied")

        with self.assertRaisesRegex(
            ExportError, "Invalid cli integration: cli admin must be denied"
        ):
            exported(replace(EXPORT, check_policy=reject), policy())


class ManifestExportTests(unittest.TestCase):
    def setUp(self):
        trust = patch(
            "harness_factory.exports.trusted_executable",
            side_effect=lambda candidates: str(candidates[0]),
        )
        self.trust = trust.start()
        self.addCleanup(trust.stop)
        self.install = ToolInstall(
            manager="brew", name="gh", source="gh", commands=("gh",)
        )
        self.local = ToolManifest(
            name="gh",
            installs=(self.install,),
            vars=("LOCAL_REQUIRED",),
            optional_vars=("TOKEN", "LOCAL_OPTIONAL"),
            rules=RuleSet(
                name="gh-safe",
                description="Application policy",
                rules=(deny(shell("git", "push")), allow(shell("gh", "help"))),
                tags=("local",),
            ),
            instructions=instructions(
                "gh-docs", block("Local", "Use the managed wrapper.")
            ),
            writable_roots=(Path("/local/gh"),),
            network_domains=("local.example.com",),
        )
        self.imported = ToolManifest(
            name="ggh",
            installs=(
                ToolInstall(
                    manager="uv",
                    name="ignored",
                    source="ignored",
                    commands=("ignored",),
                ),
            ),
            vars=("TOKEN",),
            optional_vars=("CACHE", "LOCAL_REQUIRED"),
            rules=RuleSet(
                name="ggh",
                rules=(
                    allow(shell("ggh", choice("list", "show"))),
                    deny(shell("native")),
                ),
                sandbox_excluded_commands=("ggh *",),
                sandbox_exclusion_reason="host credentials",
                tags=("cli",),
            ),
            instructions=instructions("ggh", block("Ggh", "Use `ggh`.")),
            writable_roots=(Path("~/.cache/ggh"), codex_only(Path("${CACHE}/data"))),
            network_domains=("api.example.com",),
        )
        self.environment = apply_tools(
            Environment(
                name="work",
                env_vars=(
                    EnvVar("TOKEN", source="host"),
                    EnvVar("LOCAL_REQUIRED", source="host"),
                ),
                sandbox=SandboxPolicy(writable_roots=(Path("/shared"),)),
            ),
            self.local,
        )
        self.export = ManifestExport(executable="ggh", commands=("ggh",))

    def apply(self, manifest=None, export=None, **kwargs):
        with patch(
            "harness_factory.exports._run",
            return_value=to_json(manifest or self.imported),
        ) as run:
            environment = apply_exports(
                self.environment,
                {"gh": export or self.export},
                bin_dir=Path("/managed/bin"),
                home=Path("/home/test"),
                **kwargs,
            )
        run.assert_called_once_with(Path("/managed/bin/ggh"), "manifest")
        return environment

    def test_alias_combines_cli_contributions_and_keeps_local_installs(self):
        environment = self.apply()
        tool = environment.tools[0]
        self.assertEqual(tool.name, "gh")
        self.assertEqual(tool.installs, (self.install,))
        self.assertEqual(tool.vars, ("TOKEN", "LOCAL_REQUIRED"))
        self.assertEqual(tool.optional_vars, ("CACHE", "LOCAL_OPTIONAL"))
        check_tool_vars(environment)
        self.assertEqual(environment.env_vars, self.environment.env_vars)
        self.assertEqual(tool.rules.name, "gh-safe")
        self.assertEqual(tool.rules.description, "Application policy")
        self.assertEqual(
            tool.rules.rules, self.imported.rules.rules + self.local.rules.rules
        )
        self.assertEqual(tool.rules.tags, ("cli", "local"))
        self.assertEqual(tool.rules.sandbox_excluded_commands, ("ggh *",))
        self.assertEqual(environment.rules, (tool.rules,))
        self.assertEqual(tool.instructions.name, "gh-docs")
        self.assertEqual(
            tool.instructions.blocks,
            self.imported.instructions.blocks + self.local.instructions.blocks,
        )
        self.assertEqual(environment.instruction_sets, (tool.instructions,))
        self.assertEqual(
            tool.writable_roots, (Path("/home/test/.cache/ggh"), Path("/local/gh"))
        )
        self.assertEqual(
            set(environment.sandbox.writable_roots),
            {Path("/shared"), Path("/local/gh"), Path("/home/test/.cache/ggh")},
        )
        self.assertEqual(tool.network_domains, ("api.example.com", "local.example.com"))

    def test_roots_and_domains_can_be_replaced_or_dropped_before_resolution(self):
        for roots, domains in (
            ((Path("/redirected"),), ("override.example.com",)),
            ((), ()),
        ):
            with self.subTest(roots=roots):
                tool = self.apply(
                    export=replace(
                        self.export, writable_roots=roots, network_domains=domains
                    )
                ).tools[0]
                self.assertEqual(tool.writable_roots, roots + self.local.writable_roots)
                self.assertEqual(
                    tool.network_domains, domains + self.local.network_domains
                )
        # A required portable root may be replaced without resolving its value.
        manifest = replace(
            self.imported, vars=("TOKEN", "ROOT"), writable_roots=(Path("${ROOT}"),)
        )
        self.apply(manifest=manifest, export=replace(self.export, writable_roots=()))

    def test_explicit_variable_values_resolve_optional_roots(self):
        tool = self.apply(variables={"CACHE": "~/cache"}).tools[0]
        self.assertIn(codex_only(Path("/home/test/cache/data")), tool.writable_roots)

    def test_each_harness_gets_only_its_variable_path(self):
        for root in (
            Path("${CACHE}/data"),
            HarnessScopedValue(
                codex=Path("${CACHE}/data"), claude=Path("${CACHE}/data")
            ),
        ):
            with self.subTest(root=root):
                environment = self.apply(
                    manifest=replace(self.imported, writable_roots=(root,)),
                    variables={
                        "CACHE": HarnessScopedValue(codex="/codex", claude="~/claude")
                    },
                )
                self.assertIn(
                    Path("/codex/data"), environment.sandbox.writable_roots_for("codex")
                )
                self.assertNotIn(
                    Path("/codex/data"),
                    environment.sandbox.writable_roots_for("claude"),
                )
                self.assertIn(
                    Path("/home/test/claude/data"),
                    environment.sandbox.writable_roots_for("claude"),
                )
                self.assertNotIn(
                    Path("/home/test/claude/data"),
                    environment.sandbox.writable_roots_for("codex"),
                )

    def test_harness_scoped_defaults_and_root_overrides_resolve(self):
        environment = self.apply(
            export=replace(self.export, writable_roots=(Path("${CACHE}"),)),
            variables={"CACHE": HarnessScopedValue(default="~/common", codex="/codex")},
        )
        self.assertIn(Path("/codex"), environment.sandbox.writable_roots_for("codex"))
        self.assertIn(
            Path("/home/test/common"), environment.sandbox.writable_roots_for("claude")
        )

    def test_optional_value_missing_for_one_harness_drops_only_its_root(self):
        tool = self.apply(
            manifest=replace(self.imported, writable_roots=(Path("${CACHE}/data"),)),
            variables={"CACHE": HarnessScopedValue(codex="/codex")},
        ).tools[0]
        self.assertEqual(
            tool.writable_roots,
            (codex_only(Path("/codex/data")), *self.local.writable_roots),
        )
        tool = self.apply(
            manifest=replace(
                self.imported,
                writable_roots=(
                    HarnessScopedValue(
                        default=Path("/default"), codex=Path("${CACHE}")
                    ),
                ),
            ),
            variables={"CACHE": HarnessScopedValue(claude="/claude")},
        ).tools[0]
        self.assertEqual(
            tool.writable_roots[0], HarnessScopedValue(claude=Path("/default"))
        )

    def test_required_value_is_checked_only_for_applicable_harnesses(self):
        manifest = replace(
            self.imported,
            vars=("ROOT",),
            optional_vars=(),
            writable_roots=(codex_only(Path("${ROOT}/data")),),
        )
        tool = self.apply(
            manifest=manifest, variables={"ROOT": HarnessScopedValue(codex="/codex")}
        ).tools[0]
        self.assertEqual(tool.writable_roots[0], codex_only(Path("/codex/data")))
        with self.assertRaisesRegex(
            ExportError, "claude:.*ROOT.*requires a path value"
        ):
            self.apply(
                manifest=replace(manifest, writable_roots=(Path("${ROOT}"),)),
                variables={"ROOT": HarnessScopedValue(codex="/codex")},
            )

    def test_supplied_invalid_scoped_optional_value_still_fails(self):
        for value in ("", "relative", "${OTHER}"):
            with self.subTest(value=value), self.assertRaises(ExportError):
                self.apply(variables={"CACHE": HarnessScopedValue(codex=value)})

    def test_imported_sets_are_used_when_local_sets_are_absent(self):
        self.environment = apply_tools(
            self.environment, replace(self.local, rules=None, instructions=None)
        )
        tool = self.apply().tools[0]
        self.assertEqual(tool.rules, self.imported.rules)
        self.assertEqual(tool.instructions, self.imported.instructions)

    def test_shared_contributions_are_deduplicated_and_exclusion_reasons_combined(self):
        local = replace(
            self.local,
            rules=replace(
                self.local.rules,
                rules=self.imported.rules.rules,
                sandbox_excluded_commands=("ggh *", "gh *"),
                sandbox_exclusion_reason="local host access",
            ),
            instructions=replace(
                self.local.instructions, blocks=self.imported.instructions.blocks
            ),
            writable_roots=(Path("/home/test/.cache/ggh"),),
            network_domains=self.imported.network_domains,
        )
        self.environment = apply_tools(self.environment, local)
        tool = self.apply().tools[0]
        self.assertEqual(tool.rules.rules, self.imported.rules.rules)
        self.assertEqual(tool.rules.sandbox_excluded_commands, ("ggh *", "gh *"))
        self.assertEqual(
            tool.rules.sandbox_exclusion_reason, "host credentials. local host access."
        )
        self.assertEqual(tool.instructions.blocks, self.imported.instructions.blocks)
        self.assertEqual(tool.writable_roots, (Path("/home/test/.cache/ggh"),))
        self.assertEqual(tool.network_domains, self.imported.network_domains)

    def test_exclusion_reasons_are_sentences_only_when_combined(self):
        for imported_reason, local_reason, expected in (
            (
                " ggh accesses the login Keychain. ",
                " the ggh shim caches GitHub tokens ",
                "ggh accesses the login Keychain. the ggh shim caches GitHub tokens.",
            ),
            ("CLI access!", "why access?", "CLI access! why access?"),
            ("host access", "local access.", "host access. local access."),
            (" host access ", " host access ", " host access "),
            (" host access ", None, " host access "),
        ):
            with self.subTest(imported=imported_reason, local=local_reason):
                imported = replace(
                    self.imported,
                    rules=replace(
                        self.imported.rules,
                        sandbox_exclusion_reason=imported_reason,
                    ),
                )
                local = replace(
                    self.local,
                    rules=replace(
                        self.local.rules,
                        sandbox_excluded_commands=("gh *",) if local_reason else (),
                        sandbox_exclusion_reason=local_reason,
                    ),
                )
                self.environment = apply_tools(self.environment, local)
                self.assertEqual(
                    self.apply(manifest=imported)
                    .tools[0]
                    .rules.sandbox_exclusion_reason,
                    expected,
                )

    def test_schemas_one_and_two_can_be_imported(self):
        for version in (1, 2):
            manifest = replace(
                self.imported, writable_roots=(Path("/cache/ggh"),), optional_vars=()
            )
            data = to_dict(manifest)
            data.pop("optional_vars")
            data["schema_version"] = version
            with (
                self.subTest(version=version),
                patch("harness_factory.exports._run", return_value=json.dumps(data)),
            ):
                environment = apply_exports(
                    self.environment, {"gh": self.export}, bin_dir=Path("/managed/bin")
                )
            self.assertIn(Path("/cache/ggh"), environment.tools[0].writable_roots)

    def test_portable_roots_require_explicit_home_and_required_path_values(self):
        with patch("harness_factory.exports._run", return_value=to_json(self.imported)):
            with self.assertRaisesRegex(ExportError, "requires home"):
                apply_exports(
                    self.environment, {"gh": self.export}, bin_dir=Path("/managed/bin")
                )
        manifest = replace(
            self.imported,
            vars=self.imported.vars + ("ROOT",),
            writable_roots=(Path("${ROOT}"),),
        )
        with self.assertRaisesRegex(ExportError, "ROOT.*requires a path value"):
            self.apply(manifest=manifest)

    def test_bounds_apply_to_imported_policy_before_local_policy_is_added(self):
        for rules, message in (
            ((allow(shell("other")),), "may be allowed"),
            ((ask(shell("other")),), "may be allowed"),
            ((allow(shell(choice("ggh", "other"), "list")),), "may be allowed"),
        ):
            with (
                self.subTest(rules=rules),
                self.assertRaisesRegex(ExportError, message),
            ):
                self.apply(
                    manifest=replace(
                        self.imported, rules=RuleSet(name="ggh", rules=rules)
                    )
                )
        with self.assertRaisesRegex(ExportError, "may bypass the sandbox"):
            self.apply(
                manifest=replace(
                    self.imported,
                    rules=replace(
                        self.imported.rules, sandbox_excluded_commands=("other *",)
                    ),
                )
            )
        # Choices in the command position are safe when every choice is trusted.
        self.apply(
            manifest=replace(
                self.imported,
                rules=RuleSet(
                    name="ggh", rules=(allow(shell(choice("ggh", "ggh"), "list")),)
                ),
            )
        )

    def test_cli_specific_policy_checks_run_before_combining(self):
        seen = []
        self.apply(export=replace(self.export, check_policy=seen.append))
        self.assertEqual(seen, [self.imported.rules])

        def reject(rules):
            raise ValueError("policy rejected")

        with self.assertRaisesRegex(
            ExportError, "Invalid ggh integration: policy rejected"
        ):
            self.apply(export=replace(self.export, check_policy=reject))

    def test_invalid_batch_never_applies_partial_results(self):
        environment = apply_tools(self.environment, TOOL)
        for text in (
            "{",
            json.dumps({**to_dict(self.imported), "schema_version": 99}),
            json.dumps({**to_dict(self.imported), "unknown": True}),
        ):
            with (
                self.subTest(text=text),
                patch(
                    "harness_factory.exports._run",
                    side_effect=[to_json(self.imported), text],
                ),
                patch("harness_factory.exports.apply_tools") as apply,
            ):
                with self.assertRaises(ExportError):
                    apply_exports(
                        environment,
                        {"gh": self.export, "cli": ManifestExport("cli", ("cli",))},
                        bin_dir=Path("/managed/bin"),
                        home=Path("/home/test"),
                    )
                apply.assert_not_called()
        self.assertEqual(environment.tools, (self.local, TOOL))

    def test_missing_optional_cli_and_unapplied_tools_are_not_run(self):
        self.trust.side_effect = None
        self.trust.return_value = None
        with patch("harness_factory.exports._run") as run:
            environment = apply_exports(
                self.environment,
                {"gh": replace(self.export, required=False), "unapplied": self.export},
                bin_dir=Path("/nonexistent"),
            )
            run.assert_not_called()
        self.assertEqual(environment, self.environment)
        self.trust.assert_called_once_with((Path("/nonexistent/ggh"),))

    def test_missing_required_cli_and_runner_failures_name_the_cli(self):
        with (
            patch("harness_factory.exports.trusted_executable", return_value=None),
            self.assertRaisesRegex(ExportError, "Cannot read ggh manifest"),
        ):
            apply_exports(
                self.environment, {"gh": self.export}, bin_dir=Path("/nonexistent")
            )
        for error in (
            ExecutableUnavailable("command unavailable"),
            ProcessTimeout("command timed out"),
            OutputLimitExceeded("command output limit exceeded"),
        ):
            with (
                self.subTest(error=error),
                patch("harness_factory.exports.run", side_effect=error) as run,
            ):
                with self.assertRaisesRegex(
                    ExportError, "Cannot read ggh manifest"
                ) as raised:
                    apply_exports(
                        self.environment,
                        {"gh": self.export},
                        bin_dir=Path("/managed/bin"),
                    )
                run.assert_called_once_with(
                    ["/managed/bin/ggh", "manifest"],
                    environment=child_environment(),
                    timeout=15,
                )
                self.assertIsNone(raised.exception.__cause__)

    def test_nonzero_exit_fails_without_exposing_captured_output(self):
        with patch(
            "harness_factory.exports.run",
            return_value=ProcessResult(3, "private stdout", "private stderr"),
        ):
            with self.assertRaisesRegex(
                ExportError, "Cannot read ggh manifest"
            ) as raised:
                apply_exports(
                    self.environment, {"gh": self.export}, bin_dir=Path("/managed/bin")
                )
        self.assertNotIn("private", str(raised.exception))

    def test_installed_optional_cli_with_invalid_output_does_not_use_fallback(self):
        with (
            patch("harness_factory.exports._run", return_value="invalid"),
        ):
            with self.assertRaisesRegex(ExportError, "Invalid ggh integration"):
                apply_exports(
                    self.environment,
                    {"gh": replace(self.export, required=False)},
                    bin_dir=Path("/managed/bin"),
                )

    def test_incompatible_instruction_scopes_fail_instead_of_widening_them(self):
        with self.assertRaisesRegex(ExportError, "same harnesses"):
            self.apply(
                manifest=replace(
                    self.imported,
                    instructions=replace(
                        self.imported.instructions, harnesses=("codex",)
                    ),
                )
            )

    def test_manifest_without_policy_or_instructions_keeps_local_entries(self):
        tool = self.apply(manifest=ToolManifest(name="ggh")).tools[0]
        self.assertEqual(tool, self.local)


class ExecutableTrustTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.executable = self.root / "cli"
        self.executable.write_text("#!/bin/sh\nexit 0\n")
        self.executable.chmod(0o755)
        self.environment = apply_tools(Environment(name="work"), TOOL)

    def test_symlink_resolves_to_trusted_file_for_both_export_paths(self):
        target = self.root / "real-cli"
        self.executable.rename(target)
        self.executable.symlink_to(target)
        outputs = {
            "manifest": to_json(ToolManifest(name="publisher")),
            "lockdown": policy(),
            "instructions": "- Use cli.",
        }
        for export in (ManifestExport("cli", ("cli",)), EXPORT):
            with (
                self.subTest(export=export),
                patch(
                    "harness_factory.exports._run",
                    side_effect=lambda executable, command: outputs[command],
                ) as run,
            ):
                apply_exports(self.environment, {"cli": export}, bin_dir=self.root)
                self.assertTrue(run.called)
                self.assertTrue(
                    all(call.args[0] == target for call in run.call_args_list)
                )

    def test_missing_or_untrusted_cli_preserves_optional_fallback_and_fails_required(
        self,
    ):
        for mode in (
            "missing",
            "not-executable",
            "writable-file",
            "writable-directory",
        ):
            self.root.chmod(0o700)
            self.executable.chmod(0o755)
            if mode == "missing":
                self.executable.unlink()
            elif mode == "not-executable":
                self.executable.chmod(0o644)
            elif mode == "writable-file":
                self.executable.chmod(0o777)
            else:
                self.root.chmod(0o777)
            for export in (ManifestExport("cli", ("cli",)), EXPORT):
                with (
                    self.subTest(mode=mode, export=export),
                    patch("harness_factory.exports._run") as run,
                ):
                    actual = apply_exports(
                        self.environment,
                        {"cli": replace(export, required=False)},
                        bin_dir=self.root,
                    )
                    self.assertEqual(actual, self.environment)
                    with self.assertRaisesRegex(
                        ExportError, "cli.*missing or untrusted"
                    ):
                        apply_exports(
                            self.environment, {"cli": export}, bin_dir=self.root
                        )
                    run.assert_not_called()
            if mode == "missing":
                self.executable.write_text("#!/bin/sh\nexit 0\n")
        self.root.chmod(0o700)


if __name__ == "__main__":
    unittest.main()
