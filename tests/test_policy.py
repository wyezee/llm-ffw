from dataclasses import FrozenInstanceError
import time
import unittest
from unittest.mock import patch

from benchmarks.synthetic_data import build_dataset
from llm_ffw import (
    AUDIT_POLICY,
    BALANCED_POLICY,
    STRICT_POLICY,
    Action,
    RuleEngine,
    FirewallPolicy,
    FirewallResult,
    InvisibleCharactersRule,
    PolicyOverride,
    ScanScope,
    RuleScanner,
    Severity,
    Span,
)
from llm_ffw.inspection import Inspection
from llm_ffw.rules import Rule, RuleMatch


def _secret(marker: str = "A") -> str:
    return "sk-" + marker * 20


class _UnicodeOnlyBlockRule(Rule):
    @property
    def rule_id(self) -> str:
        return "test.unicode_only_block"

    @property
    def purpose(self) -> str:
        return "Prove custom rules retain full original-text scanning."

    @property
    def scopes(self) -> frozenset[ScanScope]:
        return frozenset((ScanScope.INPUT,))

    def scan(self, inspection: Inspection) -> tuple[RuleMatch, ...]:
        index = inspection.text.find("\u200b")
        if index < 0:
            return ()
        return (
            RuleMatch(
                span=Span(index, index + 1),
                severity=Severity.HIGH,
                action=Action.BLOCK,
                message="Custom Unicode-sensitive block.",
            ),
        )


class FirewallPolicyTests(unittest.TestCase):
    def test_custom_rule_uses_full_original_scan_before_removal(self) -> None:
        scanner = RuleScanner(
            rules=(InvisibleCharactersRule(), _UnicodeOnlyBlockRule())
        )

        result = RuleEngine(scanner=scanner).process("a\u200bb")

        self.assertTrue(result.blocked)
        self.assertEqual(
            frozenset(finding.rule_id for finding in result.findings),
            frozenset(
                ("test.unicode_only_block", "unicode.invisible_characters")
            ),
        )

    def test_staged_canonicalization_preserves_legacy_pipeline_results(self) -> None:
        tag_payload = "".join(chr(0xE0000 + ord(char)) for char in "hidden")
        cases = (
            (BALANCED_POLICY, "sk-\u200b" + "A" * 20),
            (BALANCED_POLICY, "sk-" + tag_payload + "B" * 20),
            (STRICT_POLICY, "sk-\u200b" + "C" * 20 + " " + _secret("D")),
            (AUDIT_POLICY, "sk-" + tag_payload + "E" * 20),
        )
        for policy, text in cases:
            with self.subTest(policy=policy.policy_id, marker=text[-1]):
                reference_scanner = RuleScanner()
                initial = reference_scanner.scan(text)
                expected = policy.apply_with_rescan(
                    text,
                    initial,
                    scope=ScanScope.INPUT,
                    redaction_text=reference_scanner.config.redaction_text,
                    rescan=reference_scanner.scan,
                )

                actual = RuleEngine(scanner=RuleScanner(), policy=policy).process(text)

                self.assertEqual(actual, expected)

    def test_remove_path_skips_remaining_original_scan(self) -> None:
        scanner = RuleScanner()
        hidden_secret = "sk-\u200b" + "F" * 20

        with (
            patch.object(
                scanner,
                "_scan_remaining",
                wraps=scanner._scan_remaining,
            ) as remaining,
            patch.object(scanner, "scan", wraps=scanner.scan) as full_scan,
        ):
            result = RuleEngine(scanner=scanner).process(hidden_secret)

        self.assertEqual(remaining.call_count, 0)
        self.assertEqual(full_scan.call_count, 1)
        self.assertEqual(
            tuple(finding.rule_id for finding in result.findings),
            ("secrets.detected", "unicode.invisible_characters"),
        )
        self.assertEqual(result.processed_text, "[REDACTED]")

    def test_clean_and_block_paths_scan_remaining_rules_once(self) -> None:
        cases = (
            (BALANCED_POLICY, "safe"),
            (STRICT_POLICY, "sk-\u200b" + "G" * 20),
        )
        for policy, text in cases:
            scanner = RuleScanner()
            with (
                self.subTest(policy=policy.policy_id),
                patch.object(
                    scanner,
                    "_scan_remaining",
                    wraps=scanner._scan_remaining,
                ) as remaining,
                patch.object(scanner, "scan", wraps=scanner.scan) as full_scan,
            ):
                RuleEngine(scanner=scanner, policy=policy).process(text)

            self.assertEqual(remaining.call_count, 1)
            self.assertEqual(full_scan.call_count, 0)

    def test_balanced_policy_redacts_input_and_output_by_default(self) -> None:
        secret = _secret()
        firewall = RuleEngine()

        for scope in (ScanScope.INPUT, ScanScope.OUTPUT):
            with self.subTest(scope=scope):
                result = firewall.process(secret, scope=scope)
                self.assertEqual(result.policy_id, "llm_ffw.balanced")
                self.assertEqual(result.decision, Action.REDACT)
                self.assertEqual(result.processed_text, "[REDACTED]")
                self.assertFalse(result.blocked)
                self.assertEqual(result.findings[0].action, Action.REDACT)
                self.assertNotIn(secret, result.processed_text)
                self.assertNotIn(secret, result.findings[0].message)
                self.assertNotIn(
                    secret,
                    tuple(result.findings[0].metadata.values()),
                )

    def test_strict_policy_blocks_only_input_request(self) -> None:
        secret = _secret("B")
        firewall = RuleEngine(policy=STRICT_POLICY)

        blocked = firewall.process(secret, scope=ScanScope.INPUT)
        output = firewall.process(secret, scope=ScanScope.OUTPUT)
        following_request = firewall.process("safe", scope=ScanScope.INPUT)

        self.assertTrue(blocked.blocked)
        self.assertEqual(blocked.decision, Action.BLOCK)
        self.assertIsNone(blocked.processed_text)
        self.assertEqual(blocked.findings[0].action, Action.BLOCK)
        self.assertEqual(output.decision, Action.REDACT)
        self.assertEqual(output.processed_text, "[REDACTED]")
        self.assertEqual(following_request.decision, Action.ALLOW)
        self.assertEqual(following_request.processed_text, "safe")

    def test_audit_policy_reports_without_modifying_text(self) -> None:
        secret = _secret("C")

        result = RuleEngine(policy=AUDIT_POLICY).process(secret)

        self.assertEqual(result.decision, Action.REVIEW)
        self.assertEqual(result.processed_text, secret)
        self.assertEqual(result.findings[0].action, Action.REVIEW)

    def test_no_findings_allow_original_text(self) -> None:
        result = RuleEngine().process("safe")

        self.assertEqual(result.decision, Action.ALLOW)
        self.assertEqual(result.processed_text, "safe")
        self.assertEqual(result.findings, ())

    def test_policy_is_immutable_and_rejects_duplicate_or_unknown_rules(self) -> None:
        override = PolicyOverride(
            "secrets.detected",
            ScanScope.INPUT,
            Action.REVIEW,
        )
        policy = FirewallPolicy("acme.policy", "1", (override,))

        with self.assertRaises(FrozenInstanceError):
            policy.version = "2"  # type: ignore[misc]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            FirewallPolicy("acme.duplicate", "1", (override, override))
        unknown = FirewallPolicy(
            "acme.unknown",
            "1",
            (
                PolicyOverride(
                    "unknown.rule",
                    ScanScope.INPUT,
                    Action.BLOCK,
                ),
            ),
        )
        with self.assertRaisesRegex(ValueError, "unknown rule_id"):
            RuleEngine(policy=unknown)

    def test_result_rejects_decision_weaker_than_effective_findings(self) -> None:
        finding = RuleEngine(policy=STRICT_POLICY).process(_secret("D")).findings[0]

        with self.assertRaisesRegex(ValueError, "strongest"):
            FirewallResult(
                policy_id="acme.invalid",
                policy_version="1",
                scope=ScanScope.INPUT,
                decision=Action.ALLOW,
                processed_text="unsafe",
                findings=(finding,),
            )

    def test_eight_mb_redaction_is_linear_and_removes_all_catalog_values(self) -> None:
        dataset = build_dataset(8_000_000)

        started = time.perf_counter()
        result = RuleEngine().process(dataset.text)
        elapsed = time.perf_counter() - started

        self.assertEqual(result.decision, Action.REDACT)
        self.assertIsNotNone(result.processed_text)
        if result.processed_text is None:
            self.fail("redaction did not return processed text")
        self.assertEqual(
            result.processed_text.count("[REDACTED]"),
            len(dataset.expected_findings),
        )
        self.assertLess(elapsed, 2.0)


if __name__ == "__main__":
    unittest.main()
