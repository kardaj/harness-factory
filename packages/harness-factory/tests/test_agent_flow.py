import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import tomlkit

from harness_factory.agent_flow import sync_provider_homes


class ProviderHomeTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.settings = self.root / "config/settings.toml"
        self.homes = {
            "codex_home": self.root / "generated/codex/personal",
            "claude_home": self.root / "generated/claude/personal",
        }

    def write_settings(self, text: str) -> None:
        self.settings.parent.mkdir(parents=True, exist_ok=True)
        self.settings.write_text(text)

    def test_merge_preserves_personal_settings_comments_and_other_providers(
        self,
    ) -> None:
        self.write_settings(
            '# My personal work directory\nwork_home = "/other/work"\n'
            "updated = 2026-04-01\n"
            '[adapters.codex.env]\nCODEX_HOME = "/old" # managed default\n'
            'PERSONAL_OPTION = "keep"\n'
            '[adapters.claude.env]\nCLAUDE_CONFIG_DIR = "/old-claude"\n'
            '[adapters.other.env]\nOTHER_HOME = "/other"\n'
        )
        self.assertTrue(sync_provider_homes(self.settings, **self.homes))
        text = self.settings.read_text()
        document = tomlkit.parse(text)
        self.assertIn("# My personal work directory", text)
        self.assertIn("# managed default", text)
        self.assertIn("updated = 2026-04-01", text)
        self.assertEqual(document["work_home"], "/other/work")
        self.assertEqual(
            document["adapters"]["codex"]["env"]["PERSONAL_OPTION"], "keep"
        )
        self.assertEqual(document["adapters"]["other"]["env"]["OTHER_HOME"], "/other")
        for provider, key in (("codex", "CODEX_HOME"), ("claude", "CLAUDE_CONFIG_DIR")):
            self.assertEqual(
                document["adapters"][provider]["env"][key],
                str(self.homes[f"{provider}_home"]),
            )
        self.assertEqual(self.settings.stat().st_mode & 0o777, 0o600)
        before = self.settings.stat().st_mtime_ns
        self.assertFalse(sync_provider_homes(self.settings, **self.homes))
        self.assertEqual(self.settings.stat().st_mtime_ns, before)

    def test_preview_does_not_create_settings_or_parent_directories(self) -> None:
        self.assertTrue(sync_provider_homes(self.settings, **self.homes, apply=False))
        self.assertFalse(self.settings.parent.exists())
        self.assertTrue(sync_provider_homes(self.settings, **self.homes))
        self.assertFalse(sync_provider_homes(self.settings, **self.homes, apply=False))

    def test_preview_preserves_existing_content_and_modes(self) -> None:
        self.write_settings('work_home = "/personal"\n')
        original = self.settings.read_bytes()
        self.settings.chmod(0o644)
        self.assertTrue(sync_provider_homes(self.settings, **self.homes, apply=False))
        self.assertEqual(self.settings.read_bytes(), original)
        self.assertEqual(self.settings.stat().st_mode & 0o777, 0o644)

    def test_private_mode_is_repaired_without_changing_correct_content(self) -> None:
        sync_provider_homes(self.settings, **self.homes)
        original = self.settings.read_bytes()
        self.settings.chmod(0o644)
        self.assertTrue(sync_provider_homes(self.settings, **self.homes, apply=False))
        self.assertTrue(sync_provider_homes(self.settings, **self.homes))
        self.assertEqual(self.settings.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.settings.read_bytes(), original)

    def test_invalid_settings_are_not_overwritten_or_disclosed(self) -> None:
        cases = (
            'private = "secret-value\n',
            'work_home = "relative"\n',
            'adapters = "secret-value"\n',
            '[adapters]\nclaude = "secret-value"\n',
            '[adapters.codex]\nenv = "secret-value"\n',
            "[adapters.codex.env]\nOPTION = 7\n",
            '[adapters.claude.env]\n"INVALID=KEY" = "secret-value"\n',
        )
        for text in cases:
            with self.subTest(text=text):
                self.write_settings(text)
                with self.assertRaises(ValueError) as raised:
                    sync_provider_homes(self.settings, **self.homes)
                self.assertNotIn("secret-value", str(raised.exception))
                self.assertEqual(self.settings.read_text(), text)

    def test_symlink_is_rejected_without_modifying_its_target(self) -> None:
        target = self.root / "personal.toml"
        target.write_text("# Keep me\n")
        self.settings.parent.mkdir()
        self.settings.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlink"):
            sync_provider_homes(self.settings, **self.homes)
        self.assertEqual(target.read_text(), "# Keep me\n")
        self.assertTrue(self.settings.is_symlink())

    def test_failed_atomic_replacement_preserves_original_and_cleans_temporary(
        self,
    ) -> None:
        self.write_settings("# Keep me\n")
        with patch(
            "harness_factory.agent_flow.os.replace", side_effect=OSError("failed")
        ):
            with self.assertRaises(OSError):
                sync_provider_homes(self.settings, **self.homes)
        self.assertEqual(self.settings.read_text(), "# Keep me\n")
        self.assertEqual(list(self.settings.parent.iterdir()), [self.settings])

    def test_relative_provider_paths_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "absolute"):
            sync_provider_homes(
                self.settings,
                codex_home=Path("relative"),
                claude_home=self.homes["claude_home"],
            )
        self.assertFalse(self.settings.parent.exists())
