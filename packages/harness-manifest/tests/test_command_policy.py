import json
import unittest
from copy import deepcopy

from harness_manifest.command_policy import parse_command_policy


def policy_payload() -> dict:
    return {
        "schema": 1,
        "allow": [{"command": ["broker"], "reason": "broker owns device access"}],
        "deny": [{"command": ["native", "device"], "reason": "use broker"}],
        "unsandboxed": [{"command": ["broker"], "reason": "host device services"}],
    }


class CommandPolicyTests(unittest.TestCase):
    def test_policy_preserves_prefixes_reasons_and_exclusions(self) -> None:
        rules = parse_command_policy(json.dumps(policy_payload()), name="devices")
        self.assertEqual(rules.rules[1].target.parts, ("native", "device"))
        self.assertEqual(rules.rules[1].justification, "use broker")
        self.assertEqual(rules.sandbox_exclusion_reason, "host device services")
        self.assertEqual(
            [(rule.effect, rule.target.parts) for rule in rules.rules],
            [("allow", ("broker",)), ("deny", ("native", "device"))],
        )
        self.assertEqual(rules.sandbox_excluded_commands, ("broker *",))

    def test_schema_and_entry_validation_rejects_unsafe_or_ambiguous_policies(
        self,
    ) -> None:
        malformed = ["not json", "[]"]
        for schema in (2, True, "1", None):
            policy = policy_payload()
            policy["schema"] = schema
            malformed.append(json.dumps(policy))
        policy = policy_payload()
        del policy["deny"]
        malformed.append(json.dumps(policy))
        for entry in (
            {"command": [], "reason": "empty prefix"},
            {"command": "broker", "reason": "wrong type"},
            {"command": ["broker", "*"], "reason": "wildcard"},
            {"command": ["broker;native"], "reason": "shell syntax"},
            {"command": ["broker device"], "reason": "ambiguous prefix"},
            {"command": ["broker"], "reason": ""},
            {"command": ["broker"], "reason": "reason\nextra"},
        ):
            policy = policy_payload()
            policy["unsandboxed"] = [entry]
            malformed.append(json.dumps(policy))
        for payload in malformed:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                parse_command_policy(payload, name="devices")

    def test_new_entries_in_supported_schema_are_imported(self) -> None:
        policy = deepcopy(policy_payload())
        policy["deny"].append({"command": ["another-native"], "reason": "new route"})
        imported = parse_command_policy(json.dumps(policy), name="devices")
        self.assertEqual(imported.rules[-1].target.parts, ("another-native",))
