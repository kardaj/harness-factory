import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from harness_manifest import (
    SCHEMA_VERSION,
    HarnessScopedValue,
    ToolManifest,
    codex_only,
    from_json,
    load_manifest,
    resolve_manifest,
    to_json,
)


class PortableManifestTests(unittest.TestCase):
    def test_fixed_filename_requires_an_explicit_tool_name(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "tool-manifest.toml"
            path.write_text(
                'schema_version = 2\nname = "cli"\n[rules]\n[[rules.rules]]\neffect = "allow"\ncommand = ["cli"]\n'
            )
            self.assertEqual(load_manifest(path).name, "cli")
            self.assertEqual(load_manifest(path).rules.name, "cli")
            path.write_text("schema_version = 2\n")
            with self.assertRaisesRegex(ValueError, "explicit name"):
                load_manifest(path)

    def test_portable_paths_round_trip_without_reading_the_host(self):
        tool = ToolManifest(
            name="cli",
            vars=("CLI_HOME",),
            writable_roots=(
                Path("${CLI_HOME}"),
                codex_only(Path("~/.local/state/cli")),
            ),
        )
        self.assertEqual(SCHEMA_VERSION, 4)
        self.assertEqual(from_json(to_json(tool)), tool)
        self.assertEqual(json.loads(to_json(tool))["writable_roots"][0], "${CLI_HOME}")
        resolved = resolve_manifest(
            tool, home=Path("/home/test"), variables={"CLI_HOME": "~/work"}
        )
        self.assertEqual(
            resolved.writable_roots,
            (Path("/home/test/work"), codex_only(Path("/home/test/.local/state/cli"))),
        )
        self.assertEqual(tool.writable_roots[0], Path("${CLI_HOME}"))
        self.assertEqual(
            resolve_manifest(resolved, home=Path("/other"), variables={}), resolved
        )

    def test_invalid_templates_and_unresolved_values_fail(self):
        for root in (
            "relative",
            "~other/work",
            "${MISSING}",
            "${CLI_HOME}extra",
            "${CLI_HOME}/../outside",
        ):
            with self.subTest(root=root), self.assertRaises(ValueError):
                ToolManifest(
                    name="cli", vars=("CLI_HOME",), writable_roots=(Path(root),)
                )
        tool = ToolManifest(
            name="cli", vars=("CLI_HOME",), writable_roots=(Path("${CLI_HOME}/cache"),)
        )
        for values in (
            {},
            {"CLI_HOME": ""},
            {"CLI_HOME": "relative"},
            {"CLI_HOME": "${OTHER}"},
        ):
            with self.subTest(values=values), self.assertRaises(ValueError):
                resolve_manifest(tool, home=Path("/home/test"), variables=values)
        with self.assertRaisesRegex(ValueError, "absolute"):
            resolve_manifest(
                tool, home=Path("relative"), variables={"CLI_HOME": "/work"}
            )

    def test_variable_suffixes_and_scoped_values_resolve(self):
        tool = ToolManifest(
            name="cli",
            vars=("CLI_HOME",),
            writable_roots=(Path("${CLI_HOME}/cache"), Path("~")),
        )
        resolved = resolve_manifest(
            tool, home=Path("/home/test"), variables={"CLI_HOME": "/work"}
        )
        self.assertEqual(
            resolved.writable_roots, (Path("/work/cache"), Path("/home/test"))
        )

    def test_schema_one_migrates_but_does_not_accept_portable_paths(self):
        original = (
            '{"schema_version": 1, "name": "cli", "writable_roots": ["/cache/cli"]}'
        )
        migrated = from_json(original)
        self.assertEqual(migrated.writable_roots, (Path("/cache/cli"),))
        self.assertEqual(json.loads(to_json(migrated))["schema_version"], 4)
        with self.assertRaisesRegex(ValueError, "schema_version 1.*absolute"):
            from_json(
                '{"schema_version": 1, "name": "cli", "writable_roots": ["~/.cache/cli"]}'
            )

    def test_optional_roots_are_omitted_only_when_the_variable_is_absent(self):
        tool = ToolManifest(
            name="cli",
            optional_vars=("CLI_CACHE",),
            writable_roots=(
                Path("${CLI_CACHE}/data"),
                codex_only(Path("${CLI_CACHE}")),
                HarnessScopedValue(
                    default=Path("/default"), codex=Path("${CLI_CACHE}")
                ),
                Path("~/.local/state/cli"),
            ),
        )
        resolved = resolve_manifest(tool, home=Path("/home/test"), variables={})
        self.assertEqual(
            resolved.writable_roots,
            (
                HarnessScopedValue(claude=Path("/default")),
                Path("/home/test/.local/state/cli"),
            ),
        )
        defined = resolve_manifest(
            tool, home=Path("/home/test"), variables={"CLI_CACHE": "~/cache"}
        )
        self.assertEqual(defined.writable_roots[0], Path("/home/test/cache/data"))
        for value in ("", "relative", "${OTHER}"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                resolve_manifest(
                    tool, home=Path("/home/test"), variables={"CLI_CACHE": value}
                )

    def test_schema_two_migrates_with_portable_roots(self):
        tool = from_json(
            '{"schema_version": 2, "name": "cli", "vars": ["CLI_HOME"], '
            '"writable_roots": ["${CLI_HOME}", "~/.cache/cli"]}'
        )
        self.assertEqual(tool.optional_vars, ())
        self.assertEqual(json.loads(to_json(tool))["schema_version"], 4)
