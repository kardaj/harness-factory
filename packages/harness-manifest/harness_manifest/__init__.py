"""Dependency-free schema for portable agent tool manifests.

CLIs depend on this package to publish their own manifest; harness factories
read the versioned JSON form and apply it to environments.
"""

from harness_manifest.instructions import (
    InstructionBlock,
    InstructionFile,
    InstructionSet,
    SandboxExclusions,
    block,
    instructions,
    markdown,
    sandbox_exclusions,
)
from harness_manifest.manifest import (
    HarnessName,
    HarnessScopedValue,
    InstallManager,
    ToolInstall,
    ToolManifest,
    WritableRoot,
    claude_only,
    codex_only,
    has_relative_root,
    resolve_manifest,
    writable_root_paths,
)
from harness_manifest.command_policy import parse_command_policy
from harness_manifest.rule_files import dump_rule_set, load_rule_set, load_rule_sets
from harness_manifest.tool_files import load_manifest, load_manifests
from harness_manifest.rules import (
    Choice,
    Rule,
    RuleSet,
    ShellCommand,
    allow,
    ask,
    choice,
    deny,
    expand_shell_command,
    shell,
)
from harness_manifest.serialize import (
    SCHEMA_VERSION,
    from_dict,
    from_json,
    rule_set_from_dict,
    rule_set_to_dict,
    to_dict,
    to_json,
)

__all__ = [
    "SCHEMA_VERSION",
    "Choice",
    "HarnessName",
    "HarnessScopedValue",
    "InstallManager",
    "InstructionBlock",
    "InstructionFile",
    "InstructionSet",
    "Rule",
    "RuleSet",
    "SandboxExclusions",
    "ShellCommand",
    "ToolInstall",
    "ToolManifest",
    "WritableRoot",
    "allow",
    "ask",
    "block",
    "choice",
    "claude_only",
    "codex_only",
    "deny",
    "dump_rule_set",
    "expand_shell_command",
    "from_dict",
    "from_json",
    "has_relative_root",
    "resolve_manifest",
    "load_manifest",
    "load_manifests",
    "instructions",
    "load_rule_set",
    "load_rule_sets",
    "markdown",
    "parse_command_policy",
    "rule_set_from_dict",
    "rule_set_to_dict",
    "sandbox_exclusions",
    "shell",
    "to_dict",
    "to_json",
    "writable_root_paths",
]
