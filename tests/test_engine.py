from dataclasses import replace
import unittest

from llm_ffw import Action, Finding, RuleScanner, RuleScannerConfig, ScanScope, Span
from llm_ffw.rules import SecretsRule


def _key(marker: str) -> str:
    return "sk-" + marker * 24


class ScannerTests(unittest.TestCase):
    def test_default_limit_supports_large_contexts(self) -> None:
        self.assertEqual(RuleScannerConfig().max_input_chars, 8_000_000)
        self.assertTrue(RuleScannerConfig().enable_invisible_characters)
        self.assertTrue(RuleScannerConfig().enable_unicode_tag_smuggling)
        self.assertTrue(RuleScannerConfig().enable_bidi_controls)
        self.assertTrue(RuleScannerConfig().enable_payment_cards)
        self.assertTrue(RuleScannerConfig().enable_private_keys)
        self.assertTrue(RuleScannerConfig().enable_jwt_tokens)

    def test_default_scanner_has_secure_baseline_rules(self) -> None:
        scanner = RuleScanner()

        self.assertEqual(
            tuple(rule.rule_id for rule in scanner.rules),
            (
                "pii.payment_card",
                "secrets.detected",
                "secrets.jwt_token",
                "secrets.private_key",
                "unicode.bidi_controls",
                "unicode.invisible_characters",
                "unicode.tag_smuggling",
            ),
        )
        self.assertEqual(
            next(
                rule.scopes
                for rule in scanner.rules
                if rule.rule_id == "secrets.detected"
            ),
            frozenset((ScanScope.INPUT, ScanScope.OUTPUT)),
        )

    def test_secure_baseline_rules_can_be_explicitly_disabled(self) -> None:
        scanner = RuleScanner(
            config=RuleScannerConfig(
                enable_invisible_characters=False,
                enable_unicode_tag_smuggling=False,
                enable_bidi_controls=False,
                enable_payment_cards=False,
                enable_private_keys=False,
                enable_jwt_tokens=False,
            )
        )

        self.assertEqual(
            tuple(rule.rule_id for rule in scanner.rules),
            ("secrets.detected",),
        )

    def test_secrets_rule_scans_input_and_output(self) -> None:
        value = _key("S")
        scanner = RuleScanner()

        self.assertEqual(len(scanner.scan(value, scope=ScanScope.INPUT)), 1)
        self.assertEqual(len(scanner.scan(value, scope=ScanScope.OUTPUT)), 1)

    def test_findings_are_ordered_by_original_span(self) -> None:
        first = _key("A")
        second = "ghp_" + "b" * 36
        text = second + " then " + first

        findings = RuleScanner().scan(text)

        self.assertEqual(len(findings), 2)
        self.assertLess(findings[0].span.start, findings[1].span.start)

    def test_redacts_without_changing_unmatched_text(self) -> None:
        value = _key("C")
        text = "before " + value + " after"
        scanner = RuleScanner()

        redacted = scanner.redact(text)

        self.assertEqual(redacted, "before [REDACTED] after")
        self.assertNotIn(value, redacted)

    def test_redaction_merges_overlapping_spans(self) -> None:
        scanner = RuleScanner(rules=())
        template = RuleScanner(rules=(SecretsRule(),)).scan(_key("D"))[0]
        text = "abcdefghij"
        first = Finding(
            rule_id=template.rule_id,
            severity=template.severity,
            action=template.action,
            span=Span(2, 6),
            message=template.message,
        )
        second = Finding(
            rule_id=template.rule_id,
            severity=template.severity,
            action=template.action,
            span=Span(5, 8),
            message=template.message,
        )

        self.assertEqual(scanner.redact(text, (first, second)), "ab[REDACTED]ij")

    def test_redaction_ignores_findings_without_redact_action(self) -> None:
        value = _key("F")
        finding = RuleScanner().scan(value)[0]
        review_finding = replace(finding, action=Action.REVIEW)

        self.assertEqual(RuleScanner().redact(value, (review_finding,)), value)

    def test_rejects_oversized_input(self) -> None:
        scanner = RuleScanner(config=RuleScannerConfig(max_input_chars=5))

        with self.assertRaisesRegex(ValueError, "max_input_chars"):
            scanner.scan("123456")

    def test_rejects_duplicate_rule_ids(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate rule_id"):
            RuleScanner(rules=(SecretsRule(), SecretsRule()))

    def test_empty_rule_set_is_supported(self) -> None:
        self.assertEqual(RuleScanner(rules=()).scan(_key("E")), ())

    def test_rejects_non_string_input(self) -> None:
        with self.assertRaises(TypeError):
            RuleScanner().scan(None)  # type: ignore[arg-type]

    def test_rejects_non_boolean_rule_activation_configuration(self) -> None:
        for field_name in (
            "enable_invisible_characters",
            "enable_unicode_tag_smuggling",
            "enable_bidi_controls",
            "enable_payment_cards",
            "enable_private_keys",
            "enable_jwt_tokens",
        ):
            with self.subTest(field_name=field_name), self.assertRaises(TypeError):
                RuleScannerConfig(**{field_name: 1})  # type: ignore[arg-type]
