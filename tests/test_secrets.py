import time
import unittest

from llm_ffw import Action, RuleScanner, Severity
from llm_ffw.rules import SecretsRule


def _openai_key() -> str:
    return "sk-" + "A1_" * 10


def _github_token() -> str:
    return "ghp_" + "aB3" * 12


def _aws_access_key_id() -> str:
    return "AKIA" + "A1B2" * 4


class SecretsRuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scanner = RuleScanner(rules=(SecretsRule(),))

    def test_matches_each_documented_secret_type(self) -> None:
        cases = (
            (_openai_key(), "openai_api_key"),
            (_github_token(), "github_token"),
            (_aws_access_key_id(), "aws_access_key_id"),
        )
        for value, expected_type in cases:
            with self.subTest(secret_type=expected_type):
                findings = self.scanner.scan("credential=" + value)

                self.assertEqual(len(findings), 1)
                finding = findings[0]
                self.assertEqual(finding.rule_id, "secrets.detected")
                self.assertEqual(finding.severity, Severity.HIGH)
                self.assertEqual(finding.action, Action.REDACT)
                self.assertEqual(finding.metadata["secret_type"], expected_type)
                self.assertEqual(finding.metadata["catalog_id"], "llm_ffw.builtin.secrets")
                self.assertEqual(finding.metadata["catalog_version"], "3.0.0")
                self.assertTrue(finding.metadata["signature_id"])
                self.assertTrue(finding.metadata["provider"])
                self.assertEqual(
                    finding.redacted_preview,
                    f"[REDACTED:{expected_type}]",
                )
                self.assertNotIn(value, finding.message)
                self.assertNotIn(value, finding.redacted_preview or "")

    def test_span_selects_exact_original_value_after_crlf(self) -> None:
        value = _github_token()
        text = "heading\r\ntoken=" + value + "\r\n"

        finding = self.scanner.scan(text)[0]

        self.assertEqual(text[finding.span.start : finding.span.end], value)

    def test_matches_openai_key_ending_in_hyphen(self) -> None:
        value = "sk-" + "A" * 23 + "-"

        finding = self.scanner.scan(value)[0]

        self.assertEqual((finding.span.start, finding.span.end), (0, len(value)))

    def test_does_not_match_lookalikes_or_short_values(self) -> None:
        lookalikes = (
            "sk-short",
            "ghp_too_short",
            "AKIA1234",
            "akia" + "A1B2" * 4,
            "ordinary prose with password and token words",
        )
        for text in lookalikes:
            with self.subTest(value_kind=text[:8]):
                self.assertEqual(self.scanner.scan(text), ())

    def test_adversarial_long_non_match_is_fast(self) -> None:
        text = ("sk-" + "!" * 97 + " ") * 2_000

        started = time.perf_counter()
        findings = self.scanner.scan(text)
        elapsed = time.perf_counter() - started

        self.assertEqual(findings, ())
        self.assertLess(elapsed, 2.0)

    def test_dense_matches_fail_closed_at_bounded_limit(self) -> None:
        token = "sk_test_" + "A" * 10
        text = " ".join((token,) * (SecretsRule.MAX_CANDIDATES + 1))

        findings = self.scanner.scan(text)

        self.assertEqual(len(findings), SecretsRule.MAX_CANDIDATES + 1)
        overflow = findings[-1]
        self.assertIs(overflow.action, Action.BLOCK)
        self.assertIs(overflow.severity, Severity.HIGH)
        self.assertEqual(
            overflow.metadata["reason"],
            "candidate_limit_exceeded",
        )
        self.assertEqual(overflow.span.end, len(text))

    def test_dense_long_input_remains_bounded_and_fast(self) -> None:
        token = "sk_test_" + "A" * 10
        text = (token + " ") * 400_000

        started = time.perf_counter()
        findings = self.scanner.scan(text)
        elapsed = time.perf_counter() - started

        self.assertEqual(len(findings), SecretsRule.MAX_CANDIDATES + 1)
        self.assertLess(elapsed, 2.0)
