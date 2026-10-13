import ast
import unittest
from pathlib import Path


class PackageBoundaryTests(unittest.TestCase):
    def test_factory_modules_and_tests_do_not_import_harness_application(self) -> None:
        package_dir = Path(__file__).resolve().parents[1]
        violations: list[str] = []

        for path in sorted(package_dir.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                modules: tuple[str, ...]
                if isinstance(node, ast.Import):
                    modules = tuple(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module is not None:
                    modules = (node.module,)
                else:
                    continue
                for module in modules:
                    if module == "harness" or module.startswith("harness."):
                        relative_path = path.relative_to(package_dir.parent)
                        violations.append(f"{relative_path}:{node.lineno}: {module}")

        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
