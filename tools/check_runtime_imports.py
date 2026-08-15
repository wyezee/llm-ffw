"""Fail when runtime modules import a non-standard-library package."""

import ast
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "llm_ffw"


def imported_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.partition(".")[0])
    return roots


def main() -> None:
    violations: list[str] = []
    allowed = sys.stdlib_module_names | {"llm_ffw"}
    for path in sorted(PACKAGE.rglob("*.py")):
        for module in sorted(imported_roots(path) - allowed):
            violations.append(f"{path.relative_to(ROOT)}: {module}")
    if violations:
        raise SystemExit(
            "non-standard runtime imports found:\n" + "\n".join(violations)
        )
    print("runtime_imports=stdlib_only")


if __name__ == "__main__":
    main()
