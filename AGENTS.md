## Scope

This repository holds three Python packages for agent harnesses, developed together as a uv workspace and published separately: `harness-manifest`, `harness-secrets`, and `harness-factory`.

## Package boundary

- `harness_manifest` is the tool manifest schema CLIs depend on. It imports only the Python 3.12+ standard library.
- `harness_secrets` is 1Password and macOS Keychain retrieval. It imports only the Python 3.12+ standard library.
- `harness_factory` builds on both and may also use `tomlkit`.
- No package holds application data: user paths, Keychain service names and labels, environment inventories, and project owner names are passed in by callers. Each package's `test_package_boundary` enforces its imports.

## Contracts

- Versioned formats (tool manifest JSON, rule set and tool files, environment files, lockdown exports, the Keychain cache entry) reject unknown versions and fields. Change a format only with a new `schema_version` and a migration path.
- Rendering must stay deterministic, and deployment must never delete files it does not own.
- Secrets must never reach command arguments, `repr`, logs, or exception messages.

## Development

- Use `uv run` for Python. Tests use `unittest`; run each package's suite with `uv run python -m unittest discover -s packages/<package>/tests -t packages/<package>/tests`.
- Run `uv run ruff check --fix` then `uv run ruff format` on edited Python files.
- Keep each Markdown paragraph or list item on one line.
- Update the package README when public behavior changes.
