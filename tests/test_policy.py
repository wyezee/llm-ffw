from dataclasses import FrozenInstanceError
import time
import unittest

from benchmarks.synthetic_data import build_dataset
from llm_ffw import (
    AUDIT_POLICY,
    BALANCED_POLICY,
    STRICT_POLICY,
    Action,
    Firewall,
    FirewallPolicy,
    FirewallResult,
    PolicyOverride,
    ScanScope,
)


def _secret(marker: str = "A") -> str:
    return "sk-" + marker * 20


class FirewallPolicyTests(unittest.TestCase):
    def test_balanced_policy_redacts_input_and_output_by_default(self) -> None:
        secret = _secret()
        firewall = Firewall()

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
        firewall = Firewall(policy=STRICT_POLICY)

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

        result = Firewall(policy=AUDIT_POLICY).process(secret)

        self.assertEqual(result.decision, Action.REVIEW)
        self.assertEqual(result.processed_text, secret)
        self.assertEqual(result.findings[0].action, Action.REVIEW)

    def test_no_findings_allow_original_text(self) -> None:
        result = Firewall().process("safe")

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
            Firewall(policy=unknown)

    def test_result_rejects_decision_weaker_than_effective_findings(self) -> None:
        finding = Firewall(policy=STRICT_POLICY).process(_secret("D")).findings[0]

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
        result = Firewall().process(dataset.text)
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
