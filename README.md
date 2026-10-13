# harness-factory

Describe agent environments once and render them into Codex and Claude Code configuration homes, with tool policies that the CLIs themselves publish.

This repository is a uv workspace with three packages:

| Package | Purpose | Dependencies |
| --- | --- | --- |
| [`harness-manifest`](packages/harness-manifest/README.md) | Tool manifest schema, command rules, and instructions that CLIs publish | standard library only |
| [`harness-secrets`](packages/harness-secrets/README.md) | 1Password retrieval with a rate-limit-friendly macOS Keychain cache and bounded CLI runner | standard library only |
| [`harness-factory`](packages/harness-factory/README.md) | Environment model, TOML environment files, adapters, rendering, and non-destructive deployment | the two above and `tomlkit` |

Applications compose these into their own environments; the libraries never hold user paths, credentials identifiers, or environment inventories.

## Installing one package

Each package installs on its own from a Git subdirectory. Internal consumers follow `main`:

```toml
[tool.uv.sources]
harness-manifest = { git = "ssh://git@github.com/kardaj/harness-factory.git", subdirectory = "packages/harness-manifest", branch = "main" }
```

Use the HTTPS form instead when you have no SSH key for GitHub:

```toml
[tool.uv.sources]
harness-manifest = { git = "https://github.com/kardaj/harness-factory.git", subdirectory = "packages/harness-manifest", branch = "main" }
```

The packages are versioned separately: `harness-manifest` 0.4.0, `harness-secrets` 0.2.0, and `harness-factory` 0.3.0. Compatibility between a CLI and a harness is guarded by each format's own `schema_version`. Manifest schema 3 adds optional variables and keeps schemas 1 and 2 readable. CLI authors can validate manifest output with `uv run --active python -m harness_manifest check`. Applications can import trusted installed CLIs' manifests with `harness_factory.exports.ManifestExport`, including per-harness variable values; legacy lockdown/instructions exports remain supported.

## Development

```bash
uv sync
uv run --active python -m unittest discover -s packages/harness-manifest/tests -t packages/harness-manifest/tests
uv run --active python -m unittest discover -s packages/harness-secrets/tests -t packages/harness-secrets/tests
uv run --active python -m unittest discover -s packages/harness-factory/tests -t packages/harness-factory/tests
uv run --active ruff check packages && uv run --active ruff format --check packages
```
