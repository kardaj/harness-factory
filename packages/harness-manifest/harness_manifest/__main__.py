"""Validate a CLI's manifest output or its source TOML file."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from harness_manifest import from_json, load_manifest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m harness_manifest")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="validate a CLI tool manifest")
    check.add_argument(
        "path", nargs="?", help="tool-manifest.toml path; omit or use - for JSON stdin"
    )
    options = parser.parse_args(argv)
    try:
        if options.path is None or options.path == "-":
            from_json(sys.stdin.read())
        else:
            load_manifest(Path(options.path))
    except (ValueError, OSError) as error:
        print(f"harness-manifest: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
