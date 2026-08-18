import time
import unittest

from llm_ffw import (
    BUILTIN_SECRET_CATALOG,
    Action,
    RuleScanner,
    SecretCatalog,
    SecretSignature,
    SignatureStatus,
    Severity,
)
from llm_ffw.rules import SecretsRule


_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_WORD = _ALNUM + "_"


def _signature(
    *,
    signature_id: str = "example.api_token",
    prefix: str = "ex_",
    minimum: int = 8,
    maximum: int | None = 32,
) -> SecretSignature:
    return SecretSignature(
        signature_id=signature_id,
        provider="example",
        secret_type="example_token",
        prefixes=(prefix,),
        suffix_chars=_ALNUM,
        min_suffix_chars=minimum,
        max_suffix_chars=maximum,
        boundary_chars=_WORD,
        source="internal://security/token-format",
    )


class SecretCatalogTests(unittest.TestCase):
    def test_builtin_catalog_is_versioned_and_exposed_by_rule(self) -> None:
        rule = SecretsRule()

        self.assertIs(rule.catalog, BUILTIN_SECRET_CATALOG)
        self.assertEqual(rule.catalog.catalog_id, "llm_ffw.builtin.secrets")
        self.assertEqual(rule.catalog.version, "3.0.0")
        self.assertEqual(len(rule.catalog.signatures), 28)
        self.assertEqual(
            sum(len(signature.prefixes) for signature in rule.catalog.signatures),
            47,
        )
        self.assertEqual(
            len({signature.provider for signature in rule.catalog.signatures}),
            13,
        )

    def test_builtin_catalog_excludes_twilio_api_key_identifiers(self) -> None:
        api_key_sid = "SK" + "a" * 32

        self.assertNotIn(
            "twilio",
            {signature.provider for signature in BUILTIN_SECRET_CATALOG.signatures},
        )
        self.assertEqual(RuleScanner().scan(api_key_sid), ())

    def test_custom_catalog_matches_without_file_or_network_loading(self) -> None:
        signature = _signature()
        catalog = SecretCatalog(
            catalog_id="acme.production",
            version="2026.08.15",
            signatures=(signature,),
        )
        token = "ex_" + "A1b2" * 3

        findings = RuleScanner(rules=(SecretsRule(catalog),)).scan("token=" + token)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.metadata["signature_id"], "example.api_token")
        self.assertEqual(finding.metadata["provider"], "example")
        self.assertEqual(finding.metadata["catalog_id"], "acme.production")
        self.assertEqual(finding.metadata["catalog_version"], "2026.08.15")
        self.assertEqual(finding.metadata["signature_status"], "active")
        self.assertNotIn(token, finding.message)
        self.assertNotIn(token, finding.redacted_preview or "")
        self.assertNotIn(token, tuple(finding.metadata.values()))

    def test_legacy_status_is_preserved_as_safe_metadata(self) -> None:
        signature = SecretSignature(
            signature_id="example.legacy_token",
            provider="example",
            secret_type="example_token",
            prefixes=("old_",),
            suffix_chars=_ALNUM,
            min_suffix_chars=8,
            max_suffix_chars=8,
            boundary_chars=_WORD,
            source="internal://security/legacy-token",
            status=SignatureStatus.LEGACY,
        )
        catalog = SecretCatalog("acme.legacy", "2", (signature,))

        finding = RuleScanner(rules=(SecretsRule(catalog),)).scan("old_A1b2C3d4")[0]

        self.assertEqual(finding.metadata["signature_status"], "legacy")

    def test_nested_prefixes_choose_the_longest_signature(self) -> None:
        catalog = SecretCatalog(
            catalog_id="acme.nested",
            version="1",
            signatures=(
                _signature(signature_id="example.short", prefix="tok_"),
                _signature(
                    signature_id="example.long",
                    prefix="tok_live_",
                    minimum=12,
                ),
            ),
        )

        self.assertEqual(
            RuleScanner(rules=(SecretsRule(catalog),)).scan("tok_live_" + "A" * 11),
            (),
        )

    def test_rejects_duplicate_prefix_ownership(self) -> None:
        with self.assertRaisesRegex(ValueError, "unique"):
            SecretCatalog(
                catalog_id="acme.ambiguous",
                version="1",
                signatures=(
                    _signature(signature_id="example.first", prefix="tok_"),
                    _signature(signature_id="example.second", prefix="tok_"),
                ),
            )

    def test_signature_controls_action_severity_and_required_ending(self) -> None:
        signature = SecretSignature(
            signature_id="example.review_id",
            provider="example",
            secret_type="example_id",
            prefixes=("id_",),
            suffix_chars=_ALNUM,
            min_suffix_chars=8,
            max_suffix_chars=8,
            boundary_chars=_WORD,
            source="internal://security/review-id",
            severity=Severity.MEDIUM,
            action=Action.REVIEW,
            suffix_ending="ZZ",
        )
        scanner = RuleScanner(
            rules=(SecretsRule(SecretCatalog("acme.review", "1", (signature,))),)
        )

        self.assertEqual(scanner.scan("id_AAAAAAAA"), ())
        finding = scanner.scan("id_AAAAAAZZ")[0]
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertEqual(finding.action, Action.REVIEW)
        self.assertIsNone(finding.redacted_preview)

    def test_rejects_unsafe_catalog_fields(self) -> None:
        invalid_builders = (
            lambda: _signature(signature_id="Example.Token"),
            lambda: SecretSignature(
                signature_id="example.token",
                provider="example",
                secret_type="example_token",
                prefixes=("ex_(.*)",),
                suffix_chars=_ALNUM,
                min_suffix_chars=8,
                max_suffix_chars=32,
                boundary_chars=_WORD,
                source="internal://security/token-format",
            ),
            lambda: SecretCatalog("acme.catalog", "bad version", (_signature(),)),
            lambda: SecretSignature(
                signature_id="example.token",
                provider="example",
                secret_type="example_token",
                prefixes=("ex_",),
                suffix_chars=_ALNUM,
                min_suffix_chars=8,
                max_suffix_chars=32,
                boundary_chars=_ALNUM,
                source="internal://security/token-format",
            ),
            lambda: SecretSignature(
                signature_id="example.token",
                provider="example",
                secret_type="example_token",
                prefixes=("ex_",),
                suffix_chars=_ALNUM,
                min_suffix_chars=8,
                max_suffix_chars=32,
                boundary_chars=_WORD,
                source="internal://security/token-format\nforged",
            ),
            lambda: SecretSignature(
                signature_id="example.token",
                provider="example",
                secret_type="example_token",
                prefixes=("ex_",),
                suffix_chars=_ALNUM + "-",
                min_suffix_chars=8,
                max_suffix_chars=None,
                boundary_chars=_WORD,
                source="internal://security/token-format",
            ),
            lambda: SecretCatalog(
                "acme.catalog",
                "1",
                (_signature(), _signature()),
            ),
        )
        for builder in invalid_builders:
            with self.subTest(builder=builder), self.assertRaises((TypeError, ValueError)):
                builder()

    def test_longest_prefix_controls_suffix_length(self) -> None:
        value = "sk-proj-" + "A" * 19

        self.assertEqual(RuleScanner().scan(value), ())

    def test_custom_signature_enforces_boundaries_and_maximum_length(self) -> None:
        catalog = SecretCatalog("acme.catalog", "1", (_signature(maximum=8),))
        scanner = RuleScanner(rules=(SecretsRule(catalog),))

        for value in (
            "aex_A1b2C3d4",
            "ex_A1b2C3d4_",
            "ex_A1b2C3d4Z",
        ):
            with self.subTest(value=value):
                self.assertEqual(scanner.scan(value), ())

        self.assertEqual(len(scanner.scan("ex_A1b2C3d4")), 1)

    def test_prefix_index_remains_fast_on_long_non_match(self) -> None:
        signatures = tuple(
            _signature(signature_id=f"example.token_{index}", prefix=f"P{index:03d}_")
            for index in range(100)
        )
        scanner = RuleScanner(
            rules=(SecretsRule(SecretCatalog("acme.large", "1", signatures)),)
        )
        text = ("P000_" + "!" * 10) * 66_666

        started = time.perf_counter()
        findings = scanner.scan(text)
        elapsed = time.perf_counter() - started

        self.assertEqual(findings, ())
        self.assertLess(elapsed, 2.0)


if __name__ == "__main__":
    unittest.main()
