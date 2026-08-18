import time
import unittest

from benchmarks.synthetic_data import synthetic_token
from llm_ffw import BUILTIN_SECRET_CATALOG, RuleScanner


class ProviderCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scanner = RuleScanner()

    def test_every_provider_prefix_matches_its_declared_signature(self) -> None:
        for signature in BUILTIN_SECRET_CATALOG.signatures:
            for prefix in signature.prefixes:
                with self.subTest(signature=signature.signature_id, prefix=prefix):
                    value = synthetic_token(signature, prefix)
                    finding = self.scanner.scan(value)[0]

                    self.assertEqual(finding.span.start, 0)
                    self.assertEqual(finding.span.end, len(value))
                    self.assertEqual(
                        finding.metadata["signature_id"], signature.signature_id
                    )
                    self.assertEqual(finding.metadata["provider"], signature.provider)
                    self.assertEqual(finding.severity, signature.severity)
                    self.assertEqual(finding.action, signature.action)
                    self.assertNotIn(value, finding.message)
                    self.assertNotIn(value, finding.redacted_preview or "")

    def test_every_provider_prefix_rejects_a_short_suffix(self) -> None:
        for signature in BUILTIN_SECRET_CATALOG.signatures:
            for prefix in signature.prefixes:
                with self.subTest(signature=signature.signature_id, prefix=prefix):
                    value = synthetic_token(signature, prefix)[:-1]
                    self.assertEqual(self.scanner.scan(value), ())

    def test_every_provider_prefix_enforces_left_boundary(self) -> None:
        for signature in BUILTIN_SECRET_CATALOG.signatures:
            for prefix in signature.prefixes:
                with self.subTest(signature=signature.signature_id, prefix=prefix):
                    value = synthetic_token(signature, prefix)
                    self.assertEqual(
                        self.scanner.scan(signature.boundary_chars[0] + value), ()
                    )

    def test_expanded_catalog_is_linear_on_long_adversarial_input(self) -> None:
        prefixes = tuple(
            prefix
            for signature in BUILTIN_SECRET_CATALOG.signatures
            for prefix in signature.prefixes
        )
        unit = " ".join(prefix + "!" * 8 for prefix in prefixes) + " "
        text = (unit * (1_000_000 // len(unit) + 1))[:1_000_000]

        started = time.perf_counter()
        findings = self.scanner.scan(text)
        elapsed = time.perf_counter() - started

        self.assertEqual(findings, ())
        self.assertLess(elapsed, 2.0)


if __name__ == "__main__":
    unittest.main()
