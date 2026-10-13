import json
import unittest
from pathlib import Path

from harness_manifest import (
    SCHEMA_VERSION,
    RuleSet,
    ToolInstall,
    ToolManifest,
    allow,
    block,
    choice,
    claude_only,
    codex_only,
    deny,
    from_json,
    from_dict,
    instructions,
    markdown,
    sandbox_exclusions,
    shell,
    to_dict,
    to_json,
)


def full_manifest() -> ToolManifest:
    return ToolManifest(
        name="tool",
        installs=(
            ToolInstall(
                manager="uv",
                name="tool-cli",
                source="git+ssh://git@github.com/example/tool-cli.git@main",
                commands=("tool",),
                python="3.12",
                required=False,
                replaces=("old-tool-cli",),
            ),
            ToolInstall(
                manager="brew", name="helper", source="helper", commands=("h",)
            ),
        ),
        vars=("TOOL_TOKEN", "TOOL_CACHE_DIR"),
        optional_vars=("TOOL_PROFILE",),
        rules=RuleSet(
            name="tool",
            description="Tool lockdown.",
            tags=("cli",),
            rules=(
                allow(shell("tool", choice("list", "show")), justification="reads"),
                deny(shell("tool", "admin"), match=("tool admin x",), tags=("ops",)),
            ),
            sandbox_excluded_commands=("tool *",),
            sandbox_exclusion_reason="talks to host services",
        ),
        writable_roots=(Path("/cache/tool"), codex_only(Path("/state/tool"))),
        network_domains=("api.example.com",),
        instructions=instructions(
            "tool",
            block("Tool", "- Use `tool`."),
            sandbox_exclusions(),
            harnesses=("claude",),
        ),
    )


class ManifestValidationTests(unittest.TestCase):
    def test_sandbox_exclusions_require_a_command_prefix_and_wildcard(self):
        for command in ("xdev", "xdev list", "xdev*", "*", "xdev  *", "xdev * *"):
            with self.subTest(command=command), self.assertRaises(ValueError):
                RuleSet(
                    name="cli",
                    rules=(),
                    sandbox_excluded_commands=(command,),
                    sandbox_exclusion_reason="host services",
                )
        for command in ("xdev *", "xdev list *"):
            with self.subTest(command=command):
                RuleSet(
                    name="cli",
                    rules=(),
                    sandbox_excluded_commands=(command,),
                    sandbox_exclusion_reason="host services",
                )

    def test_optional_vars_are_unique_identifiers_disjoint_from_required_vars(self):
        for kwargs, message in (
            ({"optional_vars": ("A", "A")}, "unique names"),
            ({"optional_vars": ("A B",)}, "identifiers"),
            ({"optional_vars": "A"}, "tuple"),
            ({"vars": ("A",), "optional_vars": ("A",)}, "must not overlap"),
        ):
            with (
                self.subTest(kwargs=kwargs),
                self.assertRaisesRegex(ValueError, message),
            ):
                ToolManifest(name="cli", **kwargs)

    def test_invalid_manifests_and_installs_fail_on_construction(self) -> None:
        with self.assertRaisesRegex(ValueError, "unique names"):
            ToolManifest(name="a", vars=("TOKEN", "TOKEN"))
        with self.assertRaisesRegex(ValueError, "absolute"):
            ToolManifest(name="a", writable_roots=(Path("cache"),))
        with self.assertRaisesRegex(ValueError, "absolute"):
            ToolManifest(name="a", writable_roots=(claude_only(Path("cache")),))
        with self.assertRaisesRegex(ValueError, "commands"):
            ToolInstall(manager="uv", name="a", source="a", commands=())
        with self.assertRaisesRegex(ValueError, "only uv"):
            ToolInstall(
                manager="bun", name="a", source="a", commands=("a",), python="3.12"
            )
        with self.assertRaisesRegex(ValueError, "Homebrew"):
            ToolInstall(
                manager="brew", name="a", source="a", commands=("a",), required=False
            )
        with self.assertRaisesRegex(ValueError, "replace itself"):
            ToolInstall(
                manager="uv", name="a", source="a", commands=("a",), replaces=("a",)
            )


class SerializationTests(unittest.TestCase):
    def test_empty_rule_sets_are_rejected_in_every_manifest_schema(self):
        for version in (1, 2, 3):
            for rules in ({"name": "cli"}, {"name": "cli", "rules": []}):
                with (
                    self.subTest(version=version, rules=rules),
                    self.assertRaisesRegex(ValueError, "empty rule set; omit rules"),
                ):
                    from_dict(
                        {"schema_version": version, "name": "cli", "rules": rules}
                    )
            for extra in ({}, {"rules": None}):
                self.assertIsNone(
                    from_dict({"schema_version": version, "name": "cli", **extra}).rules
                )

    def test_exclusions_alone_are_a_nonempty_policy(self):
        tool = from_dict(
            {
                "schema_version": 3,
                "name": "cli",
                "rules": {
                    "name": "cli",
                    "sandbox_excluded_commands": ["cli *"],
                    "sandbox_exclusion_reason": "host services",
                },
            }
        )
        self.assertEqual(tool.rules.rules, ())
        self.assertEqual(tool.rules.sandbox_excluded_commands, ("cli *",))
        self.assertEqual(from_json(to_json(tool)), tool)

    def test_bare_exclusions_in_cli_json_fail_validation(self):
        data = to_dict(full_manifest())
        data["rules"]["sandbox_excluded_commands"] = ["tool"]
        with self.assertRaisesRegex(ValueError, "must end in ' \\*'"):
            from_json(json.dumps(data))

    def test_older_schemas_do_not_accept_optional_vars(self):
        for version in (1, 2):
            with (
                self.subTest(version=version),
                self.assertRaisesRegex(
                    ValueError, "unknown fields.*optional_vars.*schema_version 3"
                ),
            ):
                from_json(
                    json.dumps(
                        {"schema_version": version, "name": "cli", "optional_vars": []}
                    )
                )

    def test_every_field_round_trips_through_versioned_json(self) -> None:
        manifest = full_manifest()
        text = to_json(manifest)

        self.assertEqual(json.loads(text)["schema_version"], SCHEMA_VERSION)
        self.assertEqual(
            json.loads(text)["writable_roots"][1], {"codex": "/state/tool"}
        )
        self.assertEqual(
            json.loads(text)["rules"]["rules"][0]["command"],
            ["tool", ["list", "show"]],
        )
        self.assertEqual(from_json(text), manifest)
        self.assertEqual(from_json(to_json(ToolManifest(name="bare"))).name, "bare")

    def test_omitted_fields_take_model_defaults(self) -> None:
        self.assertEqual(
            from_json(json.dumps({"schema_version": SCHEMA_VERSION, "name": "bare"})),
            ToolManifest(name="bare"),
        )

    def test_unsupported_or_unknown_input_is_rejected(self) -> None:
        valid = to_dict(full_manifest())
        cases = {
            "schema_version": {**valid, "schema_version": SCHEMA_VERSION + 1},
            "unknown fields: \\['extra'\\]": {**valid, "extra": True},
            "install has unknown fields": {
                **valid,
                "installs": [{**valid["installs"][0], "pin": "1.0"}],
            },
            "harness-scoped": {**valid, "writable_roots": [{"cursor": "/x"}]},
            "arrays of string choices": {
                **valid,
                "rules": {
                    **valid["rules"],
                    "rules": [{**valid["rules"]["rules"][0], "command": [1]}],
                },
            },
            "invalid tool manifest": {"schema_version": SCHEMA_VERSION},
            "must be a JSON object": [],
        }
        rule = valid["rules"]["rules"][0]
        install = valid["installs"][0]
        rules = valid["rules"]
        # Types and allowed values are part of the contract, not just field names.
        cases |= {
            "schema_version True": {**valid, "schema_version": True},
            "rule effect must be one of": {
                **valid,
                "rules": {**rules, "rules": [{**rule, "effect": "Deny"}]},
            },
            "shell metacharacters": {
                **valid,
                "rules": {**rules, "rules": [{**rule, "command": ["t *", "x"]}]},
            },
            "nonempty strings": {
                **valid,
                "rules": {**rules, "rules": [{**rule, "command": ["", "x"]}]},
            },
            "rule match must be a tuple of strings": {
                **valid,
                "rules": {**rules, "rules": [{**rule, "match": "abc"}]},
            },
            "install manager must be one of": {
                **valid,
                "installs": [{**install, "manager": "npm"}],
            },
            "required must be a boolean": {
                **valid,
                "installs": [{**install, "required": "false"}],
            },
            "commands must be a tuple of strings": {
                **valid,
                "installs": [{**install, "commands": "xy"}],
            },
            "network_domains must be a tuple": {
                **valid,
                "network_domains": "example.com",
            },
            "tool name must be a nonempty string": {**valid, "name": 5},
            "rule set 'tool' tags must be a tuple": {
                **valid,
                "rules": {**rules, "tags": None},
            },
            "must start with a literal command": {
                **valid,
                "rules": {**rules, "sandbox_excluded_commands": ["*"]},
            },
            "sandbox_excluded_commands parts": {
                **valid,
                "rules": {**rules, "sandbox_excluded_commands": ["tool  *"]},
            },
            "must be a single line": {
                **valid,
                "rules": {**rules, "sandbox_exclusion_reason": "host\n- more"},
            },
            "vars must be identifiers": {**valid, "vars": ["A B"]},
            "network_domains must be host names": {
                **valid,
                "network_domains": ["*"],
            },
            "network_domains must be host names, got ''": {
                **valid,
                "network_domains": [""],
            },
            "harness must be one of": {
                **valid,
                "instructions": {**valid["instructions"], "harnesses": ["gemini"]},
            },
        }
        for message, data in cases.items():
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    from_json(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "not valid JSON"):
            from_json("{")

    def test_instruction_files_must_be_inlined_before_export(self) -> None:
        manifest = ToolManifest(
            name="tool", instructions=instructions("tool", markdown("/tool.md"))
        )

        with self.assertRaisesRegex(ValueError, "inline its files"):
            to_json(manifest)


if __name__ == "__main__":
    unittest.main()
