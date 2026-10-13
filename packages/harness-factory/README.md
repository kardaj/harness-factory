# Harness Factory

Harness Factory is a small Python library for describing agent homes once and rendering them into concrete Codex and Claude Code configuration directories.

The core value is a portable model for agent environments: instructions, MCP servers, tool approvals, sandbox policy, trusted projects, subagents, rule sets, and generated home files. Applications describe their environments in TOML files and Python, and this package renders and deploys them.

## What It Solves

Agent harness configuration tends to drift because each runtime has its own shape:

- Codex uses `config.toml`, `AGENTS.md`, per-agent TOML files, and `.rules` files.
- Claude Code uses `settings.json`, `.mcp.json`, `claude.config.json`, `CLAUDE.md`, and per-agent Markdown files.
- Live homes accumulate runtime state, installed plugins, caches, auth files, history, and local edits that should not be destroyed by regeneration.

Harness Factory lets a project keep a declarative source of truth while still preserving local runtime data.

## Core Features

- **Portable environment model**
  - `Environment` for an identity/account boundary.
  - `Mode` for task-specific overlays.
  - `HarnessScopedValue` for Codex-only or Claude-only values.
  - `EnvVar` for literal, host-provided, and locally resolved 1Password sources, with other keychain/file sources reserved for future integrations.

- **Codex and Claude adapters**
  - `CodexAdapter` renders `config.toml`, `AGENTS.md`, `agents/*.toml`, rules, MCP server config, network policy, trusted projects, notifications, and home files.
  - `ClaudeAdapter` renders `settings.json`, `.mcp.json`, `claude.config.json`, `CLAUDE.md`, agents, notifications, permissions, MCP config, and sandbox settings.

- **Instruction composition**
  - Inline instruction blocks with titles.
  - Markdown file inclusion.
  - Harness-scoped instruction sets for Codex-only or Claude-only guidance.
  - Markdown instruction files use one top `#` title; body headings must be `###` or deeper so merged harness files have one `##` section per source.
  - Named instruction sets that can be shared by all environments or layered per environment/mode.

- **Portable permission rules**
  - `allow`, `ask`, and `deny` shell command rules.
  - `choice(...)` expansion for command alternatives.
  - Codex rules render to `.rules` files.
  - Claude rules render to permission strings such as `Bash(git status *)`.
  - Rule set files (`harness_manifest.rule_files`): `load_rule_set` and `load_rule_sets(directory)` read one TOML rule set per file (`schema_version = 1`, then the rule set fields and `[[rules]]` tables with `effect`, `command`, and optional `justification`, `match`, `not_match`, and `tags`); a nested array in `command` is a choice, and `name` defaults to the file stem but may name a variant that shares a rendered name with another file. `dump_rule_set` writes the canonical layout, which loads back equal. Rule sets in tool manifest JSON use the same fields.
  - Tool files (`harness_manifest.tool_files`): `load_manifest(path, rule_sets)` and `load_manifests(directory, rule_sets)` read one TOML tool manifest per file with the fields and `schema_version` of the manifest JSON; `name` defaults to and must match the file stem, and `rules` is either the name of a rule set in `rule_sets` or an inline rule set table named after the tool by default.
  - Environment files (`harness_factory.environment_files`): `load_environments(directory, rule_sets=, instruction_sets=, tools=, variables=)` reads one TOML environment per file with `Environment` field names, `schema_version = 1`, and an optional `extends`; rule sets, instruction sets, and tools are referenced by name, `env_vars` and `base_mcp_servers` are tables keyed by name, and `${NAME}` takes caller-supplied values. Extending overrides scalars, replaces named entries (`env_vars`, `base_mcp_servers`, `rules`, `instruction_sets`) of the same name in place and appends new ones, appends other lists without repeats, merges `harness_overrides` recursively with lists replaced, and applies each file's tools after its own fields. An `EnvVar` `source` may be a `HarnessScopedValue` choosing `literal` or `host` per harness. `load_instruction_sets(path, root=)` reads named sets of markdown files, resolving relative paths against `root`, optionally ending with the sandbox exclusions list.
  - `harness_manifest.parse_command_policy` validates schema 1 CLI-exported JSON policies (`allow`, `deny`, and `unsandboxed` command-prefix entries with reasons) and converts them to a `RuleSet`. Applications own invoking their selected CLI and composing matching usage instructions; the parser rejects unknown schemas and ambiguous shell patterns before rendering.

- **Tool manifests**
  - The manifest schema lives in the dependency-free `harness_manifest` package (with the rule and instruction primitives it uses, rule set files, and the lockdown export parser) so CLIs can publish their own manifests; `harness_factory` re-exports the model. `harness_manifest.to_json` and `from_json` convert a manifest to and from versioned JSON (`schema_version` 3, with schemas 1 and 2 still readable), rejecting unknown versions and fields; omitted fields take their defaults, and instruction files must be inlined as blocks before export.
  - `ToolManifest` groups what one CLI contributes: its `ToolInstall` (manager, package name, source, commands, uv Python version, whether it is required, and the packages it replaces), `vars` (required environment variable names), `optional_vars` (accepted but not required names), a lockdown `RuleSet`, sandbox writable roots and network domains, and an instruction set. Required and optional names must be unique and disjoint. Portable roots may reference either list.
  - `apply_tools(environment, *tools)` records manifests in `Environment.tools` and lowers their contributions, replacing a reapplied tool and its earlier rule set and instruction set in place, whatever the new ones are named, dropping them when the new version has none, and appending new ones, so reapplication is idempotent. Tools that share a name or declare the same rule set or instruction set are rejected before lowering, and a tool may not claim a set the environment or another tool owns unless it is the identical set. `Environment` rejects repeated names among env vars, MCP servers, rule sets, instruction sets, and tools, and `EnvVar` rejects unknown sources.
  - CLI exports (`harness_factory.exports`): `apply_exports(environment, exports, bin_dir=, home=, variables=)` imports `<cli> manifest` with `ManifestExport`, combines it with local entries, and resolves portable roots using caller-supplied values. Manifest import is preferred. The legacy `Export` path still reads `lockdown` and `instructions` and replaces local fallbacks. Both paths run through `harness_secrets.process` and validate exported command bounds before applying changes.
  - Manifests declare variable names; each environment that applies a tool supplies the values, including secret references. `check_tool_vars(environment)` requires only `vars`; undefined `optional_vars` are left out without an error or a synthesized environment entry. Run it on final environments, because a shared base may apply a tool whose values each derived environment supplies.
  - A manifest lists its `installs`; one tool may need several, such as a Homebrew CLI and a uv credential shim. Managers are `uv`, `bun`, `brew`, and `cask`; Homebrew installs are always required and never replace packages.
  - Manifests never name environments: an environment selects its tools by applying them. `collect_installs(*environments)` returns the sorted union of their installs, for bootstraps that let any machine run any environment, and rejects one package declared two ways. A manifest with only `installs` contributes nothing to rendered output.
  - Install data is descriptive: applications own bootstrap and should verify that their installers agree with each manifest.

- **MCP server and tool approval modeling**
  - STDIO and HTTP MCP servers.
  - Per-server environment, headers, current tool config, and tool approvals.
  - `approve_tool`, `ask_tool`, and `deny_tool` render to native Codex and Claude approval surfaces.

- **Sandbox and network policy**
  - Portable sandbox policy currently supports one mode: `workspace-write`.
  - Codex renders `workspace-write` to its native sandbox mode, workspace-write options, and additional absolute writable roots.
  - Claude renders `workspace-write` as sandboxed Bash with `acceptEdits`, cwd-scoped writes, optional `/tmp` write allowance, additional absolute writable roots, and unsandboxed Bash disabled.
  - Writable roots, in a `SandboxPolicy` or a `ToolManifest`, may be wrapped in `codex_only` or `claude_only` to grant them to one harness; both adapters render their roots from the model, so roots never need a harness override.
  - Codex sandbox network proxy domain allowlist.
  - Claude sandbox network `allowedDomains` and narrowly scoped macOS Mach-service lookups.
  - Claude sandbox `excludedCommands`, derived from the `sandbox_excluded_commands` of included rule sets, which must be literal command words ending in ` *` and state a single-line `sandbox_exclusion_reason`; excluded commands still go through the permission rules.
  - Order-insensitive lists render sorted and deduplicated, so contributions from environments and tool manifests never reorder output: Codex writable roots, proxy domains and `include_only`, and Claude permission entries, write roots, domains, Mach lookups, Unix sockets and excluded commands. Harness overrides still replace a list as written.

- **Subagent rendering**
  - Portable `Agent` definitions with instructions, model tier, sandbox policy, MCP servers, rules, tools, and harness-specific overrides.
  - Codex agents render as `agents/*.toml`.
  - Claude agents render as `agents/*.md` with YAML front matter.

- **Trusted project expansion**
  - Direct trusted project paths.
  - Immediate child repo discovery with optional devcontainer path mirrors.

- **Home file materialization**
  - Static files can be copied into generated homes.
  - Notification scripts are modeled as home files and rendered per harness.

- **Non-destructive sync**
  - Each rendered home records an explicit managed-file manifest; deployment copies only those files into live homes without deleting or reading mutable runtime files.
  - JSON and TOML files are overlaid so generated keys update while runtime keys such as plugin state can survive.
  - Explicit `Environment.retired_agents` entries remove old Codex registrations and archive the corresponding Codex TOML and Claude Markdown definitions under `.harness-retired/`. Archives preserve local edits; unrelated agent files remain untouched, and symlinked retirement paths are refused.

- **Diff and check workflows**
  - `diff_trees` reports managed differences between found and expected output.
  - Config-key redaction hides rendered environment values in diffs, including legacy values present only in existing output.
  - Retired MCP servers are pruned from root harness configuration and managed Codex subagent TOML files while unrelated runtime keys remain intact.
  - Managed private modes enforce `0600` secret-bearing configs and `0700` profile directories during render and deployment.
  - The local renderer supports `--check`, `--diff`, and normal sync.
  - Generated homes can be validated with installed Codex/Claude CLIs when available.

- **Live drift review**
  - `review_live_output` compares live homes against a fresh render and reports live-only model candidates.
  - Current reviewers cover extra trusted projects, MCP servers, MCP tool approvals, and Claude permission entries.

## Importing installed CLI manifests

Apply the application's local manifest first, then call `apply_exports` before checking tool variables, resolving secrets, or writing output. Mapping keys are local tool names; `executable` selects the CLI in `bin_dir`, and its exported manifest name may differ. Start from fresh local tools for each render so removed CLI contributions do not become local entries on a later import. The library has no application imports or inventory of CLIs.

```python
from pathlib import Path

from harness_factory import Environment, HarnessScopedValue, RuleSet, ToolInstall, ToolManifest, apply_tools, check_tool_vars, deny, shell
from harness_factory.exports import ManifestExport, apply_exports

gh = ToolManifest(
    name="gh",
    installs=(ToolInstall(manager="brew", name="gh", source="gh", commands=("gh",)),),
    rules=RuleSet(name="gh-safe", rules=(deny(shell("gh", "repo", "delete")),)),
    writable_roots=(Path("/application/gh-state"),),
)
local = apply_tools(Environment(name="work"), gh)
environment = apply_exports(
    local,
    {"gh": ManifestExport(
        executable="ggh",
        commands=("ggh", "gh"),
        writable_roots=(Path("/application/ggh-cache"),),
    )},
    bin_dir=Path("/managed/bin"),
    home=Path("/application/home"),
    variables={},  # Explicit non-secret path values, if used by portable roots.
)
check_tool_vars(environment)  # Supply any required environment vars first.
```

The combine rule is deterministic, with imported entries before local entries and exact duplicates removed:

- The local tool `name` and `installs` are retained; exported installs are parsed and validated but never selected for bootstrap.
- Required variable names are unioned. Optional names are unioned with any name required by either side removed from the optional list. No variable values are fetched or added.
- Rules, tags, and sandbox exclusions are unioned into one rule set. Its name and description come from the local set when one exists, otherwise from the imported set. Distinct sandbox exclusion reasons are trimmed, given a final period if they lack terminal punctuation (`.`, `!`, or `?`), and joined with a single space, preserving their original case. Duplicate reasons are removed; a single reason is preserved unchanged. Rules retain their effects; combining does not turn a local deny into an allow.
- Instruction blocks are unioned into one instruction set, keeping its local name when present. When both sets exist they must target the same harnesses; incompatible scopes fail. A local policy or instruction set remains when the export omits it.
- Imported writable roots and network domains are followed by local entries. `ManifestExport.writable_roots` and `network_domains` default to `None`, which retains the CLI's contributions; an explicit tuple replaces the corresponding imported list, and `()` drops it. Local entries and environment-wide grants remain. Applications choose their locations; the library imposes no cache-location policy.

Portable roots are resolved after overrides and combination. Pass an absolute `home` whenever the resulting roots contain `~` or `${NAME}`, and supply path values in `variables`. Roots using missing optional variables are omitted; supplied invalid values and missing required path values fail. The importer never reads host variables or resolves secret references. If a root would need a secret-derived value, the application can replace it with an explicit non-secret path before import.

`variables` accepts `Mapping[str, str | HarnessScopedValue]`. A string applies to both harnesses; a scoped value selects its `codex` or `claude` value, falling back to its `default` when present. For example, pass `variables={"CLI_CACHE": HarnessScopedValue(codex="/codex/cache", claude="/claude/cache")}` when a manifest declares `CLI_CACHE`. Roots scoped to one harness use only that harness's value. An unscoped root resolves separately for each harness and grants each access only to its resulting path. A missing optional value drops the root for that harness without falling through to a different default root; a missing required value fails and names the affected harness. Empty or invalid supplied path values still fail.

Each export's `commands` is an explicit trust boundary supplied by the application, independent of tool names and installs. Exported allow and ask rules, including every choice in the first command position, and sandbox exclusions must start with one of these commands; exported deny rules may target anything. Checks run on imported policy before local policy is combined. `check_policy` may add CLI-specific validation.

Imports apply only to tools selected by the environment. Each executable is resolved through `harness_secrets.process.trusted_executable` before any command runs; pass an absolute `bin_dir`. Symlinks resolve to their trusted targets. The resolved target must be an executable regular file owned by root or the current user, with neither it nor its parent directory writable by group or others. A missing or untrusted optional executable (`required=False`) leaves the complete local fallback intact. A missing or untrusted required executable fails and names the CLI. A trusted optional executable with an invalid export also fails. Invalid JSON, unsupported schemas, invalid fields, unsafe exported commands, non-zero exits, timeouts, and excessive output fail before the batch is applied. Commands run with the runner's minimal `child_environment()`, a 15-second timeout, and a 1 MiB combined stdout/stderr limit; unrelated ambient variables are not inherited. Callers must finish all imports before secret resolution and output writes; `apply_exports` itself performs neither. Legacy `Export` retains its replacement behavior for `lockdown` and `instructions` while using the same executable checks, bounded runner, and command checks.

`harness-factory` 0.3.0 introduces `ManifestExport` as public API. CLI authors should validate their exports with `cli manifest | uv run --active python -m harness_manifest check` before publishing; `harness-manifest` 0.4.0 rejects empty policies and bare sandbox exclusions at the source.

## Minimal Example

```python
from pathlib import Path

from harness_factory import (
    CodexAdapter,
    ClaudeAdapter,
    Environment,
    EnvVar,
    RuleSet,
    SandboxPolicy,
    ToolServer,
    allow,
    approve_tool,
    shell,
    trust,
)

api = ToolServer(
    name="api-docs",
    kind="stdio",
    command="uvx",
    args=("--from", "openapi-tools-mcp", "openapi-tools-mcp"),
    tool_approvals=(approve_tool("spec_info"), approve_tool("spec_get")),
)

env = Environment(
    name="work",
    sandbox=SandboxPolicy(
        mode="workspace-write",
        allow_tmp=True,
        writable_roots=(Path("/Users/example/.cache/uv"),),
        network_allowed_domains=("api.github.com",),
        network_allowed_mach_lookups=("com.apple.trustd.agent",),
    ),
    env_vars=(EnvVar("GH_TOKEN", source="host"),),
    base_mcp_servers=(api,),
    rules=(
        RuleSet(
            name="read-only-git",
            rules=(allow(shell("git", "status")), allow(shell("git", "diff"))),
        ),
    ),
    trusted_projects=(trust(Path("~/src/project")),),
)

CodexAdapter().write(env, Path("output/codex/work"))
ClaudeAdapter().write(env, Path("output/claude/work"))
```

## Package Boundary

`harness_factory.projects` provides portable repository policies, GitHub slug normalization, read-only checkout inspection, checkout discovery, and project deployment planning. Callers supply registry entries, discovery roots, and a `ProjectOwner` that names their ownership record (`.codex/<name>-project.json`), rule file (`.codex/rules/<name>-project.rules`), and generated-file header. It uses the same native rule renderers as agent homes, preserves unrelated project settings, records added Claude permissions for later retirement, and refuses symlinked managed paths. Writes are limited to `.codex` and `.claude`; repository instructions and ignore files are neither read nor changed. Repository-specific registries and command-line workflows belong in the application layer.

`harness_factory` is the reusable library. Applications supply their definitions, tracked data, defaults, and command-line workflows. Dependencies flow from the application to `harness_factory` to `harness_manifest` and `harness_secrets`; production modules in `harness_factory` must never import an application, and both lower-level packages import only the Python 3.12+ standard library so any CLI can depend on them.

The package owns:

- environment models, adapters, serializers, tree comparison, and managed overlay behavior (tool manifests, rules, and instructions come from `harness_manifest`);
- configuration schemas and parsers whose file paths and policy values are supplied by callers;
- secret-resolution contracts, provider clients, redacted failures, and transformations from unresolved to resolved environment models;
- render and deployment primitives that operate on explicit environments, source directories, targets, redactions, and permission policies.

Applications own their environment files and definitions, tracked data such as their 1Password config, user and repository paths, Keychain service identifiers, environment selection, bootstrap and CLI orchestration, and the composition of these primitives into a render-and-deploy workflow. Values such as a config path or Keychain service name are passed into factory APIs instead of encoded as library defaults, and production modules never import an application.

The 1Password implementation follows this boundary: `harness_factory.onepassword_config` owns the schema, parser, and model composition; `harness_secrets` owns the credential-store, client, and cache contracts, their macOS Keychain and `op` providers (the cache takes its Keychain service, label, TTL, and lock directory from the caller), and per-profile resolution into opaque `SecretValue`s; `harness_factory.onepassword` maps those results onto environment variables, aggregates failures, and warns when a profile's cache could not be written; adapters reveal secret values only when writing generated configuration; `harness_factory.render` owns reusable rendering, redaction, validation, and mode helpers; and `harness_factory.deploy` owns non-destructive rendered-home deployment. Applications inject their paths, Keychain service identifier, environment inventory, and CLI choices.

## Next Steps

- a public CLI so applications without their own orchestration can render and deploy;
- a compatibility policy for Codex and Claude config schema changes.

## Local Commands

From the workspace root:

```bash
uv run --active python -m unittest discover -s packages/harness-factory/tests -t packages/harness-factory/tests
uv run --active python -m harness_factory --harness claude
```

## Known Limitations

- The model is intentionally conservative and covers the configuration surfaces its first application needed.
- 1Password-backed environment variables use a canonical tracked-config location as their Python `EnvVar.value`; reusable factory APIs validate and resolve that link before adapters render, while application-specific paths and credentials identifiers are injected by the application.
- The TOML serializer supports the subset emitted by Harness Factory, not arbitrary TOML.
- Live review is useful but not exhaustive; it currently focuses on common model drift categories.
- Codex and Claude are moving targets. Adapter tests should grow whenever a harness config surface is added.
