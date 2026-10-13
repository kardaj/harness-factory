import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from harness_manifest import (
    RuleSet,
    allow,
    choice,
    deny,
    dump_rule_set,
    load_rule_set,
    load_rule_sets,
    shell,
)


def rule_set(name: str) -> RuleSet:
    return RuleSet(
        name=name,
        description="Example lockdown.",
        rules=(
            allow(shell("tool", choice("list", "show")), justification="reads"),
            deny(
                shell(
                    "tool", choice(*(f"admin-command-{index}" for index in range(9)))
                ),
                match=("tool admin-command-1 x",),
            ),
        ),
        sandbox_excluded_commands=("tool *",),
        sandbox_exclusion_reason="talks to host services",
    )


class RuleFileTests(unittest.TestCase):
    def test_dumped_files_load_back_equal_and_name_defaults_to_the_stem(
        self,
    ) -> None:
        with TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "tool.toml").write_text(
                dump_rule_set(rule_set("tool"), "tool")
            )
            (directory / "work-tool.toml").write_text(
                dump_rule_set(rule_set("tool"), "work-tool")
            )
            (directory / "notes.txt").write_text("ignored")

            loaded = load_rule_sets(directory)

        self.assertEqual(
            loaded, {"tool": rule_set("tool"), "work-tool": rule_set("tool")}
        )
        self.assertNotIn("name =", dump_rule_set(rule_set("tool"), "tool"))
        self.assertIn('name = "tool"', dump_rule_set(rule_set("tool"), "work-tool"))
        self.assertTrue(
            all(
                len(line) <= 88
                for line in dump_rule_set(rule_set("tool"), "tool").splitlines()
                if not line.startswith(("justification", "sandbox_exclusion_reason"))
            )
        )

    def test_invalid_files_are_rejected_with_their_path(self) -> None:
        cases = {
            "schema_version": "schema_version = 2\nrules = []\n",
            "invalid TOML": "schema_version = \n",
            "unknown fields": 'schema_version = 1\nrules = []\nowner = "me"\n',
            "arrays of string choices": (
                'schema_version = 1\n[[rules]]\neffect = "allow"\ncommand = ["a", 1]\n'
            ),
            "invalid": 'schema_version = 1\n[[rules]]\ncommand = ["a"]\n',
        }
        with TemporaryDirectory() as temporary:
            for message, content in cases.items():
                with self.subTest(message=message):
                    path = Path(temporary) / "bad.toml"
                    path.write_text(content)
                    with self.assertRaisesRegex(ValueError, message):
                        load_rule_set(path)


if __name__ == "__main__":
    unittest.main()
