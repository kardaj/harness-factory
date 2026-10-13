import ast
import sys
import unittest
from pathlib import Path


class PackageBoundaryTests(unittest.TestCase):
    def test_secrets_package_imports_only_the_standard_library(self) -> None:
        package_dir = Path(__file__).resolve().parents[1]
        violations: list[str] = []

        for path in sorted(package_dir.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    modules = tuple(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    modules = (node.module or "",)
                else:
                    continue
                for module in modules:
                    top = module.partition(".")[0]
                    if top != "harness_secrets" and top not in sys.stdlib_module_names:
                        relative_path = path.relative_to(package_dir.parent)
                        violations.append(f"{relative_path}:{node.lineno}: {module}")

        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
