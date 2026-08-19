from __future__ import annotations

import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DependencyGraphPolicyTests(unittest.TestCase):
    def test_excluded_pyproject_has_no_runtime_dependencies(self) -> None:
        configuration = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )

        self.assertEqual(
            configuration["project"]["dependencies"],
            [],
            "Remove the Dependabot pyproject.toml exclusion before adding "
            "runtime dependencies.",
        )

    def test_build_requirement_mirror_matches_pyproject(self) -> None:
        configuration = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        mirrored_requirements = [
            line.strip()
            for line in (ROOT / "requirements-build.txt")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]

        self.assertEqual(
            mirrored_requirements,
            configuration["build-system"]["requires"],
            "Keep requirements-build.txt synchronized with "
            "[build-system].requires.",
        )


if __name__ == "__main__":
    unittest.main()
