import contextlib
import json
import stat
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from harness_factory.onepassword_config import (
    OnePasswordConfig,
    OnePasswordSecret,
    compose_onepassword_environments,
)
from harness_factory.onepassword import (
    SecretResolutionError,
    resolve_onepassword_environments,
)
from harness_secrets import (
    OnePasswordCommandFailed,
    OnePasswordProfile,
    OnePasswordRateLimited,
    SecretValue,
)
from harness_factory import (
    ClaudeAdapter,
    CodexAdapter,
    Environment,
    EnvVar,
)
from harness_factory.check import _summarize_process
from harness_factory.deploy import deploy_rendered_home
from harness_factory.managed_files import write_managed_files_manifest
from harness_factory.render import write_harness_homes
from harness_factory.serializers import dump_json, dump_toml
from harness_factory.tree_diff import diff_trees, format_tree_diffs, sync_tree


class FakeCredentialStore:
    def __init__(self, tokens: dict[str, str]):
        self.tokens = tokens
        self.calls: list[str] = []

    def get_token(self, profile: str) -> str | None:
        self.calls.append(profile)
        return self.tokens.get(profile)


class FakeOnePasswordClient:
    def __init__(
        self,
        values: dict[tuple[str, str], str],
        *,
        readable_vaults: set[tuple[str, str]] | None = None,
        active_tokens: set[str] | None = None,
        failure_text: str = "fake client failure containing sensitive material",
    ):
        self.values = values
        self.readable_vaults = readable_vaults
        self.active_tokens = active_tokens
        self.failure_text = failure_text
        self.read_calls: list[tuple[str, str]] = []
        self.authenticate_calls = 0
        self.vault_calls = 0

    def authenticate(self, token: str) -> bool:
        self.authenticate_calls += 1
        return self.active_tokens is None or token in self.active_tokens

    def vault_id(self, token: str, vault: str) -> str:
        self.vault_calls += 1
        if (
            self.readable_vaults is not None
            and (token, vault) not in self.readable_vaults
        ):
            raise OnePasswordCommandFailed()
        # The vault name doubles as its ID, so reads see the declared reference.
        return vault

    def read(self, token: str, reference: str) -> str:
        self.read_calls.append((token, reference))
        try:
            return self.values[(token, reference)]
        except KeyError as error:
            raise RuntimeError(self.failure_text) from error


def linked_environment(name: str, *variables: str) -> Environment:
    return Environment(
        name=name,
        env_vars=tuple(
            EnvVar(
                variable,
                source="1password",
                value=f"environments.{name}.secrets.{variable}",
            )
            for variable in variables
        ),
    )


class OnePasswordIntegrationTests(unittest.TestCase):
    def test_complete_profile_cache_avoids_repeat_cli_reads(self) -> None:
        reference = "op://Harness Automation/Example/token"
        config = OnePasswordConfig(
            profiles=(
                OnePasswordProfile("personal", "Personal", "Harness Automation"),
            ),
            secrets=(OnePasswordSecret("kardaj", "TOKEN", "personal", reference),),
        )
        environments = compose_onepassword_environments(
            (linked_environment("kardaj", "TOKEN"),), config
        )
        client = FakeOnePasswordClient(
            {("machine-service-token", reference): "cached-secret"}
        )

        class MemoryCache:
            values: dict[str, str] = {}
            cached_vault_id: str | None = None

            def get(self, profile, token, vault, references):
                return {r: self.values[r] for r in references if r in self.values}

            def vault_id(self, profile, token, vault):
                return self.cached_vault_id

            def put(self, profile, token, vault, values, vault_id):
                self.values = {**self.values, **values}
                self.cached_vault_id = vault_id or self.cached_vault_id

            def refreshing(self, profile):
                return contextlib.nullcontext()

        cache = MemoryCache()
        for _ in range(2):
            (resolved,) = resolve_onepassword_environments(
                environments,
                config,
                credential_store=FakeCredentialStore(
                    {"personal": "machine-service-token"}
                ),
                client=client,
                cache=cache,
            )
            self.assertEqual(resolved.env_vars[0].value, SecretValue("cached-secret"))
        client.values[("machine-service-token", reference)] = "refreshed-secret"
        (refreshed,) = resolve_onepassword_environments(
            environments,
            config,
            credential_store=FakeCredentialStore({"personal": "machine-service-token"}),
            client=client,
            cache=cache,
            bypass_cache=True,
        )
        self.assertEqual(refreshed.env_vars[0].value, SecretValue("refreshed-secret"))
        (reused,) = resolve_onepassword_environments(
            environments,
            config,
            credential_store=FakeCredentialStore({"personal": "machine-service-token"}),
            client=client,
            cache=cache,
        )
        self.assertEqual(reused.env_vars[0].value, SecretValue("refreshed-secret"))
        self.assertEqual(client.authenticate_calls, 0)
        self.assertEqual(client.vault_calls, 2)
        self.assertEqual(
            client.read_calls,
            [("machine-service-token", reference)] * 2,
        )

    def test_read_only_resolution_does_not_replace_cache(self) -> None:
        reference = "op://Harness Automation/Example/token"
        config = OnePasswordConfig(
            profiles=(
                OnePasswordProfile("personal", "Personal", "Harness Automation"),
            ),
            secrets=(OnePasswordSecret("kardaj", "TOKEN", "personal", reference),),
        )
        environments = compose_onepassword_environments(
            (linked_environment("kardaj", "TOKEN"),), config
        )
        client = FakeOnePasswordClient(
            {("machine-service-token", reference): "fresh-secret"}
        )
        writes: list[dict[str, str]] = []

        class MemoryCache:
            def get(self, profile, token, vault, references):
                return {reference: "existing-secret"}

            def vault_id(self, profile, token, vault):
                return None

            def put(self, profile, token, vault, values, vault_id):
                writes.append(values)

            def refreshing(self, profile):
                return contextlib.nullcontext()

        (resolved,) = resolve_onepassword_environments(
            environments,
            config,
            credential_store=FakeCredentialStore({"personal": "machine-service-token"}),
            client=client,
            cache=MemoryCache(),
            bypass_cache=True,
            update_cache=False,
        )
        self.assertEqual(resolved.env_vars[0].value, SecretValue("fresh-secret"))
        self.assertEqual(writes, [])

    def test_cache_write_failures_warn_without_failing_resolution(self) -> None:
        reference = "op://Vault/Item/value"
        config = OnePasswordConfig(
            profiles=(OnePasswordProfile("personal", "Personal", "Vault"),),
            secrets=(OnePasswordSecret("kardaj", "TOKEN", "personal", reference),),
        )
        environments = compose_onepassword_environments(
            (linked_environment("kardaj", "TOKEN"),), config
        )

        class BrokenCache:
            def get(self, profile, token, vault, references):
                return {}

            def vault_id(self, profile, token, vault):
                return None

            def put(self, profile, token, vault, values, vault_id):
                raise OSError("disk full secret-value")

            def refreshing(self, profile):
                return contextlib.nullcontext()

        with self.assertWarnsRegex(RuntimeWarning, "could not be written") as caught:
            (resolved,) = resolve_onepassword_environments(
                environments,
                config,
                credential_store=FakeCredentialStore({"personal": "service-token"}),
                client=FakeOnePasswordClient({("service-token", reference): "secret"}),
                cache=BrokenCache(),
            )
        self.assertEqual(resolved.env_vars[0].value, SecretValue("secret"))
        self.assertNotIn("secret-value", str(caught.warning))

    def test_rate_limit_is_not_reported_as_missing_vault_access(self) -> None:
        config = OnePasswordConfig(
            profiles=(OnePasswordProfile("personal", "Personal", "Vault"),),
            secrets=(
                OnePasswordSecret(
                    "kardaj", "TOKEN", "personal", "op://Vault/Item/value"
                ),
            ),
        )
        environments = compose_onepassword_environments(
            (linked_environment("kardaj", "TOKEN"),), config
        )
        client = FakeOnePasswordClient({})
        with patch.object(client, "vault_id", side_effect=OnePasswordRateLimited()):
            with self.assertRaises(SecretResolutionError) as raised:
                resolve_onepassword_environments(
                    environments,
                    config,
                    credential_store=FakeCredentialStore(
                        {"personal": "machine-service-token"}
                    ),
                    client=client,
                )
        self.assertIn("1Password request limit has been reached", str(raised.exception))
        self.assertNotIn("cannot read configured vault", str(raised.exception))

    def test_cache_bypass_disables_op_cli_daemon_cache(self) -> None:
        reference = "op://Vault/Item/value"
        config = OnePasswordConfig(
            profiles=(OnePasswordProfile("personal", "Personal", "Vault"),),
            secrets=(OnePasswordSecret("kardaj", "TOKEN", "personal", reference),),
        )
        environments = compose_onepassword_environments(
            (linked_environment("kardaj", "TOKEN"),), config
        )
        client = FakeOnePasswordClient({("service-token", reference): "secret"})
        with patch(
            "harness_factory.onepassword.OpOnePasswordClient", return_value=client
        ) as op_client:
            resolve_onepassword_environments(
                environments,
                config,
                credential_store=FakeCredentialStore({"personal": "service-token"}),
                bypass_cache=True,
            )
        op_client.assert_called_once_with(use_cli_cache=False)

    def test_selects_profile_token_and_deduplicates_reference_reads(self) -> None:
        reference = "op://Harness Automation/Example/token"
        config = OnePasswordConfig(
            profiles=(
                OnePasswordProfile("personal", "Personal", "Harness Automation"),
            ),
            secrets=(
                OnePasswordSecret("kardaj", "FIRST_SECRET", "personal", reference),
                OnePasswordSecret("kardaj", "SECOND_SECRET", "personal", reference),
            ),
        )
        environments = compose_onepassword_environments(
            (linked_environment("kardaj", "FIRST_SECRET", "SECOND_SECRET"),),
            config,
        )
        store = FakeCredentialStore({"personal": "machine-service-token"})
        client = FakeOnePasswordClient(
            {("machine-service-token", reference): "resolved-application-secret"}
        )

        (resolved,) = resolve_onepassword_environments(
            environments, config, credential_store=store, client=client
        )

        self.assertEqual(store.calls, ["personal"])
        self.assertEqual(client.read_calls, [("machine-service-token", reference)])
        self.assertEqual(
            [env_var.value for env_var in resolved.env_vars],
            [SecretValue("resolved-application-secret")] * 2,
        )

    def test_service_account_token_never_reaches_generated_output(self) -> None:
        reference = "op://Harness Automation/Example/token"
        config = OnePasswordConfig(
            profiles=(
                OnePasswordProfile("personal", "Personal", "Harness Automation"),
            ),
            secrets=(OnePasswordSecret("kardaj", "NEW_SECRET", "personal", reference),),
        )
        composed = compose_onepassword_environments(
            (linked_environment("kardaj", "NEW_SECRET"),), config
        )
        resolved = resolve_onepassword_environments(
            composed,
            config,
            credential_store=FakeCredentialStore({"personal": "machine-service-token"}),
            client=FakeOnePasswordClient(
                {("machine-service-token", reference): ("resolved-application-secret")}
            ),
        )

        with TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "output"
            write_harness_homes(output_dir, environments=resolved)
            generated = "\n".join(
                path.read_text(errors="ignore")
                for path in output_dir.rglob("*")
                if path.is_file()
            )

        self.assertIn("resolved-application-secret", generated)
        self.assertNotIn("machine-service-token", generated)

    def test_unresolved_optional_secret_is_omitted(self) -> None:
        reference = "op://Harness Automation/Optional/token"
        config = OnePasswordConfig(
            profiles=(
                OnePasswordProfile("personal", "Personal", "Harness Automation"),
            ),
            secrets=(
                OnePasswordSecret(
                    "kardaj",
                    "OPTIONAL_SECRET",
                    "personal",
                    reference,
                    required=False,
                ),
            ),
        )
        environments = compose_onepassword_environments(
            (linked_environment("kardaj", "OPTIONAL_SECRET"),), config
        )

        (resolved,) = resolve_onepassword_environments(
            environments,
            config,
            credential_store=FakeCredentialStore({"personal": "machine-service-token"}),
            client=FakeOnePasswordClient({}),
        )

        self.assertIsNone(resolved.env_vars[0].value)
        codex = json.dumps(CodexAdapter().render(resolved))
        claude = json.dumps(ClaudeAdapter().render(resolved))
        self.assertNotIn("OPTIONAL_SECRET", codex)
        self.assertNotIn("OPTIONAL_SECRET", claude)

    def test_failures_for_multiple_profiles_are_reported_together(self) -> None:
        config = OnePasswordConfig(
            profiles=(
                OnePasswordProfile("personal", "Personal", "Personal Vault"),
                OnePasswordProfile("work", "Work", "Work Vault"),
            ),
            secrets=(
                OnePasswordSecret(
                    "kardaj",
                    "PERSONAL_SECRET",
                    "personal",
                    "op://Personal Vault/Item/token",
                ),
                OnePasswordSecret(
                    "work",
                    "WORK_SECRET",
                    "work",
                    "op://Work Vault/Item/token",
                ),
            ),
        )
        environments = compose_onepassword_environments(
            (
                linked_environment("kardaj", "PERSONAL_SECRET"),
                linked_environment("work", "WORK_SECRET"),
            ),
            config,
        )

        with self.assertRaises(SecretResolutionError) as raised:
            resolve_onepassword_environments(
                environments,
                config,
                credential_store=FakeCredentialStore({}),
                client=FakeOnePasswordClient({}),
            )

        self.assertEqual(len(raised.exception.issues), 2)
        self.assertIn("kardaj.PERSONAL_SECRET", str(raised.exception))
        self.assertIn("work.WORK_SECRET", str(raised.exception))

    def test_secret_files_and_directories_use_restrictive_modes(self) -> None:
        environment = Environment(
            name="kardaj",
            env_vars=(
                EnvVar(
                    "NEW_SECRET",
                    value=SecretValue("resolved-application-secret"),
                    source="1password",
                ),
            ),
        )

        with TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "output"
            write_harness_homes(output_dir, environments=(environment,))

            self.assertEqual(
                stat.S_IMODE((output_dir / "codex" / "kardaj").stat().st_mode),
                0o700,
            )
            self.assertEqual(
                stat.S_IMODE(
                    (output_dir / "codex" / "kardaj" / "config.toml").stat().st_mode
                ),
                0o600,
            )
            self.assertEqual(
                stat.S_IMODE((output_dir / "claude" / "kardaj").stat().st_mode),
                0o700,
            )
            self.assertEqual(
                stat.S_IMODE(
                    (output_dir / "claude" / "kardaj" / "settings.json").stat().st_mode
                ),
                0o600,
            )

    def test_serializers_create_private_files_and_directories(self) -> None:
        data = {"env": {"NEW_SECRET": "resolved-application-secret"}}
        for dump, name in ((dump_json, "settings.json"), (dump_toml, "config.toml")):
            with self.subTest(name=name), TemporaryDirectory() as tmp:
                home = Path(tmp) / "output" / "home"
                path = home / name

                dump(data, path)

                self.assertIn("resolved-application-secret", path.read_text())
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(home.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(home.parent.stat().st_mode), 0o700)
                self.assertEqual([entry.name for entry in home.iterdir()], [name])

    def test_serializers_refuse_symlinked_targets(self) -> None:
        for dump, name in ((dump_json, "settings.json"), (dump_toml, "config.toml")):
            with self.subTest(name=name), TemporaryDirectory() as tmp:
                root = Path(tmp)
                destination = root / "personal.txt"
                destination.write_text("# Keep me\n")
                destination.chmod(0o644)
                path = root / name
                path.symlink_to(destination)

                with self.assertRaisesRegex(ValueError, "symlink"):
                    dump({"env": {"NEW_SECRET": "resolved-application-secret"}}, path)

                self.assertTrue(path.is_symlink())
                self.assertEqual(destination.read_text(), "# Keep me\n")
                self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o644)
                self.assertEqual(
                    sorted(entry.name for entry in root.iterdir()),
                    sorted([name, "personal.txt"]),
                )

    def test_diff_redacts_old_and_new_secret_values(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            found = root / "found"
            expected = root / "expected"
            found.mkdir()
            expected.mkdir()
            (found / "settings.json").write_text(
                json.dumps(
                    {"env": {"NEW_SECRET": "old-secret-value"}},
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            (expected / "settings.json").write_text(
                json.dumps(
                    {"env": {"NEW_SECRET": "new-secret-value"}},
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            output = format_tree_diffs(
                diff_trees(
                    found,
                    expected,
                    config_key_redactions={
                        Path("settings.json"): (("env", "NEW_SECRET"),)
                    },
                )
            )

        self.assertNotIn("old-secret-value", output)
        self.assertNotIn("new-secret-value", output)
        self.assertIn("<redacted>", output)

    def test_diff_redacts_existing_value_when_environment_map_changes(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            found = root / "found"
            expected = root / "expected"
            found.mkdir()
            expected.mkdir()
            (found / "settings.json").write_text(
                json.dumps(
                    {"env": {"REMOVED_SECRET": "removed-secret-value"}},
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            (expected / "settings.json").write_text(
                json.dumps(
                    {"env": {"NEW_SETTING": "non-secret-value"}},
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            output = format_tree_diffs(
                diff_trees(
                    found,
                    expected,
                    config_key_redactions={Path("settings.json"): (("env", "*"),)},
                )
            )

        self.assertNotIn("removed-secret-value", output)
        self.assertIn("<redacted>", output)

    def test_process_diagnostics_redact_environment_values(self) -> None:
        result = subprocess.CompletedProcess(
            args=["codex", "doctor"],
            returncode=1,
            stdout="",
            stderr="invalid value resolved-application-secret in config\n",
        )

        summary = _summarize_process(
            result, redacted_values=("resolved-application-secret",)
        )

        self.assertNotIn("resolved-application-secret", summary)
        self.assertIn("<redacted>", summary)

    def test_secret_env_var_repr_is_redacted(self) -> None:
        env_var = EnvVar(
            "NEW_SECRET",
            value=SecretValue("resolved-application-secret"),
            source="1password",
        )

        rendered = repr(env_var)

        self.assertNotIn("resolved-application-secret", rendered)
        self.assertIn("<redacted>", rendered)

    def test_sync_applies_managed_private_modes(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            found = root / "found"
            expected = root / "expected"
            found.mkdir(mode=0o755)
            expected.mkdir(mode=0o700)
            found_file = found / "settings.json"
            expected_file = expected / "settings.json"
            found_file.write_text("{}\n", encoding="utf-8")
            expected_file.write_text("{}\n", encoding="utf-8")
            found_file.chmod(0o644)
            expected_file.chmod(0o600)

            diffs = sync_tree(
                found,
                expected,
                managed_modes={Path("."): 0o700, Path("settings.json"): 0o600},
            )

            self.assertTrue(any(diff.kind == "mode" for diff in diffs))
            self.assertEqual(stat.S_IMODE(found.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(found_file.stat().st_mode), 0o600)

    def test_sync_creates_new_secret_files_with_private_modes(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            found = root / "found"
            expected = root / "expected"
            expected.mkdir(mode=0o700)
            expected_file = expected / "settings.json"
            expected_file.write_text(
                '{"env": {"NEW_SECRET": "resolved-application-secret"}}\n',
                encoding="utf-8",
            )
            expected_file.chmod(0o600)

            sync_tree(
                found,
                expected,
                managed_modes={Path("."): 0o700, Path("settings.json"): 0o600},
            )

            found_file = found / "settings.json"
            self.assertIn("resolved-application-secret", found_file.read_text())
            self.assertEqual(stat.S_IMODE(found.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(found_file.stat().st_mode), 0o600)
            self.assertEqual(
                [entry.name for entry in found.iterdir()], ["settings.json"]
            )

    def test_sync_refuses_symlinked_targets(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            found = root / "found"
            expected = root / "expected"
            found.mkdir()
            expected.mkdir()
            destination = root / "personal.json"
            destination.write_text("{}\n", encoding="utf-8")
            destination.chmod(0o644)
            (found / "settings.json").symlink_to(destination)
            (expected / "settings.json").write_text(
                '{"env": {"NEW_SECRET": "resolved-application-secret"}}\n',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "symlink"):
                sync_tree(
                    found,
                    expected,
                    managed_modes={Path("settings.json"): 0o600},
                )

            self.assertTrue((found / "settings.json").is_symlink())
            self.assertEqual(destination.read_text(), "{}\n")
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o644)
            self.assertEqual(
                [entry.name for entry in found.iterdir()], ["settings.json"]
            )

    def test_deployment_consumes_rendered_tree_and_preserves_private_modes(
        self,
    ) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            rendered_home = root / "rendered" / "codex" / "kardaj"
            rendered_home.mkdir(parents=True, mode=0o700)
            rendered_config = rendered_home / "config.toml"
            rendered_config.write_text(
                '[shell_environment_policy.set]\nNEW_SECRET = "rendered-value"\n',
                encoding="utf-8",
            )
            rendered_config.chmod(0o600)
            write_managed_files_manifest(rendered_home)
            target_home = root / "target"

            changes = deploy_rendered_home(
                linked_environment("kardaj", "NEW_SECRET"),
                "codex",
                root / "rendered",
                target_home,
            )

            self.assertGreater(changes, 0)
            self.assertEqual(
                (target_home / "config.toml").read_text(),
                rendered_config.read_text(),
            )
            self.assertEqual(stat.S_IMODE(target_home.stat().st_mode), 0o700)
            self.assertEqual(
                stat.S_IMODE((target_home / "config.toml").stat().st_mode),
                0o600,
            )


if __name__ == "__main__":
    unittest.main()
