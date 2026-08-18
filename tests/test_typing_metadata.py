from pathlib import Path
import tomllib
from typing import get_type_hints
import unittest

from llm_ffw import AsyncFirewall, Firewall, RuleEngine, RuleScanner


ROOT = Path(__file__).resolve().parents[1]


class TypingMetadataTests(unittest.TestCase):
    def test_pep_561_marker_is_present_and_explicitly_packaged(self) -> None:
        marker = ROOT / "llm_ffw" / "py.typed"
        self.assertTrue(marker.is_file())
        self.assertEqual(marker.read_bytes(), b"")

        configuration = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(
            configuration["tool"]["setuptools"]["package-data"]["llm_ffw"],
            ["py.typed"],
        )

    def test_canonical_api_methods_expose_runtime_annotations(self) -> None:
        for public_method in (
            Firewall.sanitize_input,
            AsyncFirewall.sanitize_input,
            RuleEngine.process,
            RuleScanner.scan,
        ):
            with self.subTest(method=public_method.__qualname__):
                hints = get_type_hints(public_method)
                self.assertIs(hints["text"], str)
                self.assertIn("return", hints)


if __name__ == "__main__":
    unittest.main()
