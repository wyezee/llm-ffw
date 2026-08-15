import unittest

from llm_ffw import (
    AUDIT_POLICY,
    STRICT_POLICY,
    Action,
    ContentBlockedError,
    Firewall,
    LLMFirewall,
    LLMFirewallManager,
    PaymentCardConfig,
    PaymentCardRule,
    ProcessScannerPoolConfig,
    ScanScope,
    Scanner,
)


def _scanner(config: PaymentCardConfig | None = None) -> Scanner:
    return Scanner(rules=(PaymentCardRule(config),))


def _single_worker_config() -> ProcessScannerPoolConfig:
    return ProcessScannerPoolConfig(
        max_workers=1,
        max_in_flight=1,
        max_tasks_per_child=10,
    )


class PaymentCardConfigTests(unittest.TestCase):
    def test_rejects_invalid_limits_and_scopes(self) -> None:
        for value in (0, -1, True, 1_025):
            with self.subTest(value=value), self.assertRaises(
                (TypeError, ValueError)
            ):
                PaymentCardConfig(max_candidates=value)  # type: ignore[arg-type]
        for scopes in ((), ("input",), "input"):
            with self.subTest(scopes=scopes), self.assertRaises(
                (TypeError, ValueError)
            ):
                PaymentCardConfig(scopes=scopes)  # type: ignore[arg-type]

    def test_normalizes_scopes_deterministically(self) -> None:
        config = PaymentCardConfig(
            scopes=(ScanScope.OUTPUT, ScanScope.INPUT, ScanScope.OUTPUT)
        )
        self.assertEqual(config.scopes, (ScanScope.INPUT, ScanScope.OUTPUT))


class PaymentCardRuleTests(unittest.TestCase):
    def test_detects_official_synthetic_numbers_and_safe_formats(self) -> None:
        cases = (
            ("4242424242424242", "contiguous", "16"),
            ("5555 5555 5555 4444", "space_separated", "16"),
            ("3782-822463-10005", "hyphen_separated", "15"),
            ("6011111111111117", "contiguous", "16"),
        )
        scanner = _scanner()
        for value, format_name, digit_count in cases:
            with self.subTest(value=value):
                text = f"Use {value} only in a synthetic test."
                finding = scanner.scan(text, scope=ScanScope.INPUT)[0]
                self.assertEqual(finding.rule_id, "pii.payment_card")
                self.assertIs(finding.action, Action.REDACT)
                self.assertEqual(finding.severity.value, "high")
                self.assertEqual(finding.metadata["format"], format_name)
                self.assertEqual(finding.metadata["digit_count"], digit_count)
                self.assertEqual(
                    finding.redacted_preview, "[REDACTED:payment_card]"
                )
                self.assertEqual(text[finding.span.start : finding.span.end], value)

    def test_rejects_failed_luhn_and_non_candidates(self) -> None:
        safe = (
            "4242424242424241",
            "123456789012",
            "12345678901234567890",
            "4242--4242--4242--4242",
            "4242-4242 4242-4242",
            "４２４２４２４２４２４２４２４２",
            "0000000000000",
            "order 202608160001",
            "ordinary prose without numeric identifiers",
        )
        scanner = _scanner()
        for text in safe:
            with self.subTest(text=text):
                self.assertEqual(scanner.scan(text, scope=ScanScope.INPUT), ())

    def test_accepts_minimum_and_maximum_digit_boundaries(self) -> None:
        for value, expected_count in (
            ("4222222222222", "13"),
            ("4000000000000000006", "19"),
        ):
            with self.subTest(value=value):
                finding = _scanner().scan(value)[0]
                self.assertEqual(finding.metadata["digit_count"], expected_count)

    def test_does_not_match_a_subset_of_a_longer_numeric_run(self) -> None:
        values = (
            "942424242424242424242",
            "9 4242 4242 4242 4242",
            "4242 4242 4242 4242 9",
            "x942424242424242424242y",
        )
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(_scanner().scan(value), ())

    def test_applies_to_both_scopes_and_can_be_restricted(self) -> None:
        text = "4242 4242 4242 4242"
        for scope in (ScanScope.INPUT, ScanScope.OUTPUT):
            with self.subTest(scope=scope):
                self.assertEqual(len(_scanner().scan(text, scope=scope)), 1)
        output_only = _scanner(
            PaymentCardConfig(scopes=(ScanScope.OUTPUT,))
        )
        self.assertEqual(output_only.scan(text, scope=ScanScope.INPUT), ())
        self.assertEqual(len(output_only.scan(text, scope=ScanScope.OUTPUT)), 1)

    def test_finding_does_not_disclose_matched_digits(self) -> None:
        private_value = "4242 4242 4242 4242"
        finding = _scanner().scan(private_value)[0]
        exposed = finding.message + repr(dict(finding.metadata))
        self.assertNotIn(private_value, exposed)
        self.assertNotIn("4242", exposed)

    def test_candidate_limit_fails_closed_over_uninspected_remainder(self) -> None:
        text = "4242424242424241 then 5555555555554444 and trailing"
        scanner = _scanner(PaymentCardConfig(max_candidates=1))
        finding = scanner.scan(text)[0]

        self.assertIs(finding.action, Action.BLOCK)
        self.assertEqual(finding.metadata["reason"], "candidate_limit_exceeded")
        self.assertEqual(finding.span.start, text.index("5555"))
        self.assertEqual(finding.span.end, len(text))
        result = Firewall(scanner=scanner).process(text)
        self.assertEqual(
            result.processed_text,
            "4242424242424241 then [REDACTED]",
        )

    def test_eight_million_clean_characters_use_fast_non_match_path(self) -> None:
        self.assertEqual(_scanner().scan("a" * 8_000_000), ())

    def test_eight_million_digit_run_is_adversarial_non_match(self) -> None:
        self.assertEqual(_scanner().scan("9" * 8_000_000), ())

    def test_builtin_policies_redact_block_and_review(self) -> None:
        text = "Card 4242 4242 4242 4242"
        for scope in (ScanScope.INPUT, ScanScope.OUTPUT):
            with self.subTest(scope=scope):
                balanced = Firewall(scanner=_scanner()).process(text, scope=scope)
                strict = Firewall(
                    scanner=_scanner(), policy=STRICT_POLICY
                ).process(text, scope=scope)
                audit = Firewall(
                    scanner=_scanner(), policy=AUDIT_POLICY
                ).process(text, scope=scope)
                self.assertEqual(balanced.processed_text, "Card [REDACTED]")
                self.assertTrue(strict.blocked)
                self.assertIs(audit.decision, Action.REVIEW)
                self.assertEqual(audit.processed_text, text)


class PaymentCardFacadeTests(unittest.TestCase):
    def test_is_opt_in_and_advertises_bounded_configuration(self) -> None:
        disabled = LLMFirewall(pool_config=_single_worker_config())
        enabled = LLMFirewall(
            pool_config=_single_worker_config(),
            payment_card_config=PaymentCardConfig(max_candidates=32),
        )
        try:
            self.assertNotIn(
                "pii.payment_card",
                tuple(rule.rule_id for rule in disabled.capabilities().rules),
            )
            self.assertIn(
                "pii.payment_card",
                tuple(rule.rule_id for rule in enabled.capabilities().rules),
            )
            self.assertEqual(enabled.capabilities().payment_card.max_candidates, 32)
            card_capability = next(
                rule
                for rule in enabled.capabilities().rules
                if rule.rule_id == "pii.payment_card"
            )
            self.assertEqual(
                card_capability.scopes,
                (ScanScope.INPUT, ScanScope.OUTPUT),
            )
        finally:
            disabled.close()
            enabled.close()

    def test_worker_redacts_and_strict_policy_blocks(self) -> None:
        balanced = LLMFirewall(
            pool_config=_single_worker_config(),
            payment_card_config=PaymentCardConfig(),
        )
        strict = LLMFirewall(
            pool_config=_single_worker_config(),
            payment_card_config=PaymentCardConfig(),
            policy=STRICT_POLICY,
        )
        with balanced:
            self.assertEqual(
                balanced.sanitize_output("Card 4242424242424242"),
                "Card [REDACTED]",
            )
        with strict, self.assertRaises(ContentBlockedError) as raised:
            strict.sanitize_input("Card 4242424242424242")
        self.assertEqual(raised.exception.findings[0].rule_id, "pii.payment_card")

    def test_rejects_non_config_value(self) -> None:
        with self.assertRaises(TypeError):
            LLMFirewall(payment_card_config=True)  # type: ignore[arg-type]

    def test_manager_propagates_configuration(self) -> None:
        manager = LLMFirewallManager(
            pool_config=_single_worker_config(),
            payment_card_config=PaymentCardConfig(),
        ).start()
        try:
            self.assertIn(
                "pii.payment_card",
                tuple(rule.rule_id for rule in manager.capabilities().rules),
            )
            self.assertEqual(
                manager.sanitize_input("Card 4242424242424242"),
                "Card [REDACTED]",
            )
        finally:
            manager.close()


if __name__ == "__main__":
    unittest.main()
