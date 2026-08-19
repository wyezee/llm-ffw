import time
import unittest
from unittest.mock import patch

from llm_ffw import (
    AUDIT_POLICY,
    STRICT_POLICY,
    Action,
    BidiControlRule,
    Firewall,
    ProcessScannerPoolConfig,
    RuleEngine,
    RuleScanner,
    RuleScannerConfig,
    ScanScope,
)


_OVERRIDES = ("\u202d", "\u202e")
_EXPLICIT_FORMATTING = (
    "\u202a",
    "\u202b",
    "\u202c",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
)


class BidiControlRuleTests(unittest.TestCase):
    def test_rule_only_requests_the_bidi_inspection_pass(self) -> None:
        scanner = RuleScanner(rules=(BidiControlRule(),))
        with patch("llm_ffw.inspection._compute_unicode_security") as legacy:
            findings = scanner.scan("safe ‮ text")

        self.assertEqual(len(findings), 1)
        legacy.assert_not_called()

    def test_directional_overrides_are_removed_with_exact_safe_findings(self) -> None:
        scanner = RuleScanner(rules=(BidiControlRule(),))
        for control in _OVERRIDES:
            with self.subTest(control=ord(control)):
                text = f"before{control}after"
                finding = scanner.scan(text)[0]

                self.assertEqual(finding.rule_id, "unicode.bidi_controls")
                self.assertEqual(finding.severity.value, "high")
                self.assertIs(finding.action, Action.REMOVE)
                self.assertEqual(
                    (finding.span.start, finding.span.end),
                    (len("before"), len("before") + 1),
                )
                self.assertEqual(
                    finding.redacted_preview,
                    "[REMOVED:bidi_override]",
                )
                self.assertEqual(
                    finding.metadata,
                    {
                        "control_group": "directional_override",
                        "detector": "bounded_bidi_control_run",
                        "span_basis": "characters",
                        "unicode_version": "16.0.0",
                    },
                )
                self.assertNotIn(control, finding.message)
                self.assertNotIn(control, tuple(finding.metadata.values()))

    def test_other_explicit_controls_are_reviewed_without_mutation(self) -> None:
        scanner = RuleScanner(rules=(BidiControlRule(),))
        for control in _EXPLICIT_FORMATTING:
            with self.subTest(control=ord(control)):
                text = f"before{control}after"
                finding = scanner.scan(text)[0]

                self.assertEqual(finding.severity.value, "medium")
                self.assertIs(finding.action, Action.REVIEW)
                self.assertIsNone(finding.redacted_preview)
                self.assertEqual(
                    finding.metadata["control_group"],
                    "explicit_formatting",
                )
                self.assertEqual(scanner.redact(text), text)

    def test_implicit_marks_and_multilingual_text_are_preserved(self) -> None:
        text = (
            "English العربية עברית 123 "
            "\u061cArabic-mark \u200eleft-mark \u200fright-mark"
        )
        scanner = RuleScanner(rules=(BidiControlRule(),))

        self.assertEqual(scanner.scan(text), ())
        self.assertEqual(scanner.redact(text), text)

    def test_adjacent_groups_are_split_by_default_action(self) -> None:
        text = "a\u202e\u202d\u2066\u2067b"
        findings = RuleScanner(rules=(BidiControlRule(),)).scan(text)

        self.assertEqual(len(findings), 2)
        self.assertEqual(
            tuple(finding.action for finding in findings),
            (Action.REMOVE, Action.REVIEW),
        )
        self.assertEqual(
            tuple((finding.span.start, finding.span.end) for finding in findings),
            ((1, 3), (3, 5)),
        )

    def test_each_run_group_fails_closed_beyond_limit(self) -> None:
        scanner = RuleScanner(rules=(BidiControlRule(),))
        for control, group in (
            ("\u202e", "directional_override"),
            ("\u2068", "explicit_formatting"),
        ):
            with self.subTest(group=group):
                text = "x".join(control for _ in range(65))
                findings = scanner.scan(text)

                self.assertEqual(len(findings), 1)
                self.assertIs(findings[0].action, Action.BLOCK)
                self.assertEqual(findings[0].metadata["limit"], "64")
                self.assertEqual(findings[0].metadata["control_group"], group)

    def test_default_removes_override_then_rescans_revealed_secret(self) -> None:
        secret = "sk-" + "A" * 20
        text = secret[:2] + "\u202e" + secret[2:]

        result = RuleEngine().process(text)

        self.assertIs(result.decision, Action.REDACT)
        self.assertEqual(result.processed_text, "[REDACTED]")
        self.assertEqual(
            frozenset(finding.rule_id for finding in result.findings),
            frozenset(("unicode.bidi_controls", "secrets.detected")),
        )

    def test_balanced_strict_and_audit_preserve_policy_semantics(self) -> None:
        override = "left\u202eright"
        formatting = "left\u2068right\u2069"

        balanced_override = RuleEngine().process(override)
        balanced_formatting = RuleEngine().process(formatting)
        strict = RuleEngine(policy=STRICT_POLICY).process(formatting)
        audited = RuleEngine(policy=AUDIT_POLICY).process(override)

        self.assertIs(balanced_override.decision, Action.REMOVE)
        self.assertEqual(balanced_override.processed_text, "leftright")
        self.assertIs(balanced_formatting.decision, Action.REVIEW)
        self.assertEqual(balanced_formatting.processed_text, formatting)
        self.assertIs(strict.decision, Action.BLOCK)
        self.assertIsNone(strict.processed_text)
        self.assertIs(audited.decision, Action.REVIEW)
        self.assertEqual(audited.processed_text, override)

    def test_default_both_scopes_capability_and_explicit_disable(self) -> None:
        enabled = RuleScanner()
        disabled = RuleScanner(
            config=RuleScannerConfig(enable_bidi_controls=False)
        )
        text = "left\u202eright"

        self.assertEqual(len(enabled.scan(text, scope=ScanScope.INPUT)), 1)
        self.assertEqual(len(enabled.scan(text, scope=ScanScope.OUTPUT)), 1)
        self.assertEqual(disabled.scan(text), ())
        self.assertNotIn(
            "unicode.bidi_controls",
            tuple(rule.rule_id for rule in disabled.rules),
        )
        firewall = Firewall(
            pool_config=ProcessScannerPoolConfig(max_workers=1, max_in_flight=1)
        )
        capability = next(
            item
            for item in firewall.capabilities().rules
            if item.rule_id == "unicode.bidi_controls"
        )
        self.assertEqual(
            capability.scopes,
            (ScanScope.INPUT, ScanScope.OUTPUT),
        )
        with firewall:
            self.assertEqual(firewall.sanitize_input(text), "leftright")
            self.assertEqual(firewall.sanitize_output(text), "leftright")

    def test_config_requires_boolean_enablement(self) -> None:
        with self.assertRaisesRegex(TypeError, "enable_bidi_controls"):
            RuleScannerConfig(enable_bidi_controls=1)  # type: ignore[arg-type]

    def test_eight_million_character_paths_are_bounded(self) -> None:
        scanner = RuleScanner(rules=(BidiControlRule(),))
        cases = (
            ("x", False),
            ("é", False),
            ("x\u202e", True),
            ("x\u2068", True),
        )

        for unit, expect_block in cases:
            text = (unit * ((8_000_000 // len(unit)) + 1))[:8_000_000]
            started = time.perf_counter()
            findings = scanner.scan(text)
            elapsed = time.perf_counter() - started

            if expect_block:
                self.assertEqual(len(findings), 1)
                self.assertIs(findings[0].action, Action.BLOCK)
            else:
                self.assertEqual(findings, ())
            self.assertLess(elapsed, 2.0)


if __name__ == "__main__":
    unittest.main()
