import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from harness_factory.onepassword_config import (
    OnePasswordConfigError,
    compose_onepassword_environments,
    load_onepassword_config,
)
from harness_factory import Environment, EnvVar


class OnePasswordConfigTests(unittest.TestCase):
    def test_declared_profile_without_secrets_is_inactive(self) -> None:
        config = self._load(
            """
[onepassword.profiles.personal]
description = "Personal 1Password account"
vault = "Harness Automation"
"""
        )

        self.assertEqual([profile.name for profile in config.profiles], ["personal"])
        self.assertEqual(config.active_profiles, ())
        self.assertEqual(config.secrets, ())

    def test_loads_secret_and_activates_its_profile(self) -> None:
        config = self._load(
            """
[onepassword.profiles.personal]
description = "Personal 1Password account"
vault = "Harness Automation"

[environments.kardaj.secrets.GH_TOKEN]
profile = "personal"
reference = "op://Harness Automation/GitHub/token"
"""
        )

        self.assertEqual(
            [profile.name for profile in config.active_profiles], ["personal"]
        )
        self.assertEqual(len(config.secrets), 1)
        self.assertEqual(config.secrets[0].environment, "kardaj")
        self.assertEqual(config.secrets[0].variable, "GH_TOKEN")
        self.assertTrue(config.secrets[0].required)

    def test_loads_optional_secret(self) -> None:
        config = self._load(
            """
[onepassword.profiles.personal]
description = "Personal 1Password account"
vault = "Harness Automation"

[environments.kardaj.secrets.HA_TOKEN]
profile = "personal"
reference = "op://Harness Automation/Home Assistant/token"
required = false
"""
        )

        self.assertFalse(config.secrets[0].required)

    def test_composes_secret_into_environment_model(self) -> None:
        config = self._load(
            """
[onepassword.profiles.personal]
description = "Personal 1Password account"
vault = "Harness Automation"

[environments.kardaj.secrets.NEW_SECRET]
profile = "personal"
reference = "op://Harness Automation/Example/token"
"""
        )

        (environment,) = compose_onepassword_environments(
            (
                Environment(
                    name="kardaj",
                    env_vars=(
                        EnvVar(
                            "NEW_SECRET",
                            source="1password",
                            value="environments.kardaj.secrets.NEW_SECRET",
                        ),
                    ),
                ),
            ),
            config,
        )

        self.assertEqual(len(environment.env_vars), 1)
        self.assertEqual(environment.env_vars[0].name, "NEW_SECRET")
        self.assertEqual(environment.env_vars[0].source, "1password")
        self.assertEqual(
            environment.env_vars[0].value,
            "environments.kardaj.secrets.NEW_SECRET",
        )

    def test_rejects_secret_not_linked_from_python_model(self) -> None:
        config = self._load(
            """
[onepassword.profiles.personal]
description = "Personal 1Password account"
vault = "Harness Automation"

[environments.kardaj.secrets.NEW_SECRET]
profile = "personal"
reference = "op://Harness Automation/Example/token"
"""
        )

        with self.assertRaisesRegex(OnePasswordConfigError, "not linked"):
            compose_onepassword_environments((Environment(name="kardaj"),), config)

    def test_rejects_secret_that_conflicts_with_python_env_var(self) -> None:
        config = self._load(
            """
[onepassword.profiles.personal]
description = "Personal 1Password account"
vault = "Harness Automation"

[environments.kardaj.secrets.GH_TOKEN]
profile = "personal"
reference = "op://Harness Automation/GitHub/token"
"""
        )

        with self.assertRaisesRegex(OnePasswordConfigError, "conflicts"):
            compose_onepassword_environments(
                (
                    Environment(
                        name="kardaj",
                        env_vars=(EnvVar("GH_TOKEN", value="authored-value"),),
                    ),
                ),
                config,
            )

    def test_rejects_secret_for_unknown_environment(self) -> None:
        config = self._load(
            """
[onepassword.profiles.personal]
description = "Personal 1Password account"
vault = "Harness Automation"

[environments.unknown.secrets.NEW_SECRET]
profile = "personal"
reference = "op://Harness Automation/Example/token"
"""
        )

        with self.assertRaisesRegex(OnePasswordConfigError, "unknown environment"):
            compose_onepassword_environments((Environment(name="kardaj"),), config)

    def test_rejects_undeclared_profile(self) -> None:
        with self.assertRaisesRegex(
            OnePasswordConfigError, "references undeclared profile 'work'"
        ):
            self._load(
                """
[onepassword.profiles.personal]
description = "Personal 1Password account"
vault = "Harness Automation"

[environments.work.secrets.GH_TOKEN]
profile = "work"
reference = "op://Harness Automation/GitHub/token"
"""
            )

    def test_rejects_non_onepassword_reference(self) -> None:
        with self.assertRaisesRegex(OnePasswordConfigError, "must start with 'op://'"):
            self._load(
                """
[onepassword.profiles.personal]
description = "Personal 1Password account"
vault = "Harness Automation"

[environments.kardaj.secrets.GH_TOKEN]
profile = "personal"
reference = "literal-secret"
"""
            )

    def _load(self, contents: str):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "secrets.toml"
            path.write_text(contents)
            return load_onepassword_config(path)


if __name__ == "__main__":
    unittest.main()
