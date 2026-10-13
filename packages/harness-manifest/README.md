# harness-manifest

The tool manifest schema that CLIs publish so agent harnesses can expose them safely. It imports only the Python 3.12+ standard library, so any CLI can depend on it without pulling in a harness.

A `ToolManifest` declares a CLI's installs, required and optional environment variable names, its command rule set, sandbox writable roots and network domains, and agent instructions. The package also provides:

- `RuleSet`, `Rule`, `shell`, `choice`, `allow`, `ask`, and `deny` for command rules, and `instructions`, `block`, and `markdown` for instruction sets;
- `to_dict`/`from_dict` and `to_json`/`from_json` for the versioned form (`schema_version` 3; schemas 1 and 2 remain readable), which reject unknown versions and fields;
- `load_rule_set(s)` and `dump_rule_set` for one TOML rule set per file, and `load_manifest(s)` for one TOML tool manifest per file;
- `parse_command_policy` for a CLI's exported `lockdown` policy (schema 1).

Every dataclass validates its own fields, so manifests built in Python and parsed from JSON or TOML meet the same contract.

Manifest policies must contain at least one rule or sandbox exclusion. To declare no policy, omit `rules` or set it to `null` in JSON, and omit the `[rules]` table or named `rules` reference in TOML. An empty rule set is rejected with a message to omit `rules`. Exclusion-only policies are supported. Every `RuleSet.sandbox_excluded_commands` entry must be literal command words followed by ` *`, such as `xdev *` or `xdev list *`; a bare `xdev` is rejected because it excludes only the command without arguments. The legacy lockdown parser already produces these prefixes.

## Publishing a manifest

A CLI keeps its manifest in `tool-manifest.toml` at its repository root and prints it as versioned JSON from a `manifest` command, so harnesses can read the installed version. Depend on this package from the workspace repository:

```toml
[project]
dependencies = ["harness-manifest"]

[tool.uv.sources]
harness-manifest = { git = "ssh://git@github.com/kardaj/harness-factory.git", subdirectory = "packages/harness-manifest", branch = "main" }
```

Use the HTTPS form instead when you have no SSH key for GitHub:

```toml
[tool.uv.sources]
harness-manifest = { git = "https://github.com/kardaj/harness-factory.git", subdirectory = "packages/harness-manifest", branch = "main" }
```

## Checking a CLI manifest

Every CLI should test its actual `manifest` output with the checker in CI before publishing it. The checker applies every validation used by `from_json`, including supported schemas, unknown fields, variable declarations, rule sets, sandbox exclusion prefixes, instructions, and portable roots. With no path, or with `-`, it reads JSON from stdin:

```sh
set -o pipefail
cli manifest | uv run --active python -m harness_manifest check
```

Check the source TOML with the same loader consumers use:

```sh
uv run --active python -m harness_manifest check tool-manifest.toml
```

This path applies `load_manifest` validation, including the explicit name required by `tool-manifest.toml` and filename/name checks for named files. Named rule-set references require a caller-supplied registry when using the library loader; standalone CLI files should inline their rules. Success is silent and exits 0; invalid JSON or TOML, invalid manifest contents, and unreadable files print the error to stderr and exit 1. The checker does not resolve portable roots, read environment variables, invoke other CLIs, or resolve secrets.

## Required and optional variables

`vars` lists the variables a consumer must define. `optional_vars` lists variables the CLI accepts without requiring them to be set. Both lists default to empty, contain unique environment variable identifiers, and must not overlap. Neither list supplies values or loads secrets. For example, a CLI that can select credentials from a profile or individual fields can declare those inputs optional rather than requiring every consumer to configure all of them:

```toml
schema_version = 3
name = "asc"
optional_vars = ["ASC_PROFILE", "ASC_ISSUER_ID", "ASC_KEY_ID", "ASC_PRIVATE_KEY_PATH", "ASC_APP_ID", "ASC_FORMAT", "ASC_CACHE_DIR"]
```

The application supplies whichever variables its chosen invocation needs. CLI-specific relationships between optional inputs remain the CLI's responsibility. `harness_factory.check_tool_vars` checks only `vars` and leaves undefined optional variables out of the environment.

## Portable writable roots

`tool-manifest.toml` requires an explicit `name`; named files retain the filename/name check. Since schema 2, writable roots may use `~/` paths and `${NAME}` roots with an optional suffix. In schema 3, `NAME` may be declared in either `vars` or `optional_vars`. Absolute paths and harness-scoped paths remain supported. Parent traversal and nested substitutions in portable paths are rejected.

```toml
schema_version = 3
name = "cli"
vars = ["CLI_HOME"]
optional_vars = ["CLI_CACHE"]
writable_roots = ["${CLI_HOME}", "${CLI_CACHE}/data", "~/.local/state/cli"]
```

The CLI exports these expressions unchanged. Before applying a manifest to an environment, the harness calls `resolve_manifest(manifest, home=home_path, variables=values)` with its own absolute home path and variable values. Variable values used in roots must be absolute paths or `~/` paths. A root using an optional variable absent from `values` is omitted, including its applicable harness scopes; a supplied but empty or invalid value still fails. A root using a missing required variable fails. Resolution never reads host environment variables, looks up files, or evaluates shell expressions. `SandboxPolicy` still requires resolved absolute roots.

## Schema migration

New JSON and TOML use schema 3. Schemas 1 and 2 remain readable without `optional_vars`; schema 1 keeps its absolute-root restriction, and schema 2 keeps its portable-root support. Reading either and serializing it again emits schema 3 with `optional_vars = []`. To use optional variables, change `schema_version` to 3 and move the relevant names from `vars` to `optional_vars`; older schema versions reject the new field even when empty. Rule set file and command-policy schemas remain at version 1. Applications using `harness_factory.exports.ManifestExport` can import the installed CLI's manifest directly, keeping installation choices and any local policy in their application.

Package 0.4.0 tightens validation without changing the schema version: replace bare sandbox exclusions with command prefixes ending in ` *`, and remove empty policies instead of exporting an empty rule set. These checks also apply when reading schemas 1 and 2.
