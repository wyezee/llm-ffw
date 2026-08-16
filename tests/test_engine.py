from dataclasses import replace
import unittest

from llm_ffw import Action, Finding, Scanner, ScannerConfig, ScanScope, Span
from llm_ffw.rules import SecretsRule


def _key(marker: str) -> str:
    return "sk-" + marker * 24


class ScannerTests(unittest.TestCase):
    def test_default_limit_supports_large_contexts(self) -> None:
        self.assertEqual(ScannerConfig().max_input_chars, 8_000_000)
        self.assertTrue(ScannerConfig().enable_invisible_characters)
        self.assertTrue(ScannerConfig().enable_payment_cards)
        self.assertTrue(ScannerConfig().enable_private_keys)

    def test_default_scanner_has_secure_baseline_rules(self) -> None:
        scanner = Scanner()

        self.assertEqual(
            tuple(rule.rule_id for rule in scanner.rules),
            (
                "pii.payment_card",
                "secrets.detected",
                "secrets.private_key",
                "unicode.invisible_characters",
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
        scanner = Scanner(
            config=ScannerConfig(
                enable_invisible_characters=False,
                enable_payment_cards=False,
                enable_private_keys=False,
            )
        )

        self.assertEqual(
            tuple(rule.rule_id for rule in scanner.rules),
            ("secrets.detected",),
        )

    def test_secrets_rule_scans_input_and_output(self) -> None:
        value = _key("S")
        scanner = Scanner()

        self.assertEqual(len(scanner.scan(value, scope=ScanScope.INPUT)), 1)
        self.assertEqual(len(scanner.scan(value, scope=ScanScope.OUTPUT)), 1)

    def test_findings_are_ordered_by_original_span(self) -> None:
        first = _key("A")
        second = "ghp_" + "b" * 36
        text = second + " then " + first

        findings = Scanner().scan(text)

        self.assertEqual(len(findings), 2)
        self.assertLess(findings[0].span.start, findings[1].span.start)

    def test_redacts_without_changing_unmatched_text(self) -> None:
        value = _key("C")
        text = "before " + value + " after"
        scanner = Scanner()

        redacted = scanner.redact(text)

        self.assertEqual(redacted, "before [REDACTED] after")
        self.assertNotIn(value, redacted)

    def test_redaction_merges_overlapping_spans(self) -> None:
        scanner = Scanner(rules=())
        template = Scanner(rules=(SecretsRule(),)).scan(_key("D"))[0]
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
        finding = Scanner().scan(value)[0]
        review_finding = replace(finding, action=Action.REVIEW)

        self.assertEqual(Scanner().redact(value, (review_finding,)), value)

    def test_rejects_oversized_input(self) -> None:
        scanner = Scanner(config=ScannerConfig(max_input_chars=5))

        with self.assertRaisesRegex(ValueError, "max_input_chars"):
            scanner.scan("123456")

    def test_rejects_duplicate_rule_ids(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate rule_id"):
            Scanner(rules=(SecretsRule(), SecretsRule()))

    def test_empty_rule_set_is_supported(self) -> None:
        self.assertEqual(Scanner(rules=()).scan(_key("E")), ())

    def test_rejects_non_string_input(self) -> None:
        with self.assertRaises(TypeError):
            Scanner().scan(None)  # type: ignore[arg-type]

    def test_rejects_non_boolean_rule_activation_configuration(self) -> None:
        for field_name in (
            "enable_invisible_characters",
            "enable_payment_cards",
            "enable_private_keys",
        ):
            with self.subTest(field_name=field_name), self.assertRaises(TypeError):
                ScannerConfig(**{field_name: 1})  # type: ignore[arg-type]
