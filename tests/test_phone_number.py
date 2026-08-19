import asyncio
import time
import unittest

from llm_ffw import (
    AUDIT_POLICY,
    STRICT_POLICY,
    Action,
    AsyncFirewall,
    ContentBlockedError,
    Firewall,
    FirewallManager,
    PhoneNumberConfig,
    PhoneNumberRule,
    ProcessScannerPoolConfig,
    RuleEngine,
    RuleScanner,
    ScanScope,
)


def _scanner(config: PhoneNumberConfig | None = None) -> RuleScanner:
    return RuleScanner(rules=(PhoneNumberRule(config),))


def _single_worker_config() -> ProcessScannerPoolConfig:
    return ProcessScannerPoolConfig(
        max_workers=1,
        max_in_flight=1,
        max_tasks_per_child=10,
    )


class PhoneNumberConfigTests(unittest.TestCase):
    def test_rejects_invalid_limits_and_scopes(self) -> None:
        for value in (0, -1, 1_025):
            with self.subTest(value=value), self.assertRaises(ValueError):
                PhoneNumberConfig(max_candidates=value)
        with self.assertRaises(TypeError):
            PhoneNumberConfig(max_candidates=True)
        for scopes in ((), ("input",), "input"):
            with self.subTest(scopes=scopes), self.assertRaises(
                (TypeError, ValueError)
            ):
                PhoneNumberConfig(scopes=scopes)  # type: ignore[arg-type]

    def test_normalizes_scopes_deterministically(self) -> None:
        config = PhoneNumberConfig(
            scopes=(ScanScope.OUTPUT, ScanScope.INPUT, ScanScope.OUTPUT)
        )
        self.assertEqual(config.scopes, (ScanScope.INPUT, ScanScope.OUTPUT))


class PhoneNumberRuleTests(unittest.TestCase):
    def test_is_opt_in_and_input_only_by_default(self) -> None:
        text = "Call +14155552671"
        self.assertEqual(RuleScanner().scan(text, scope=ScanScope.INPUT), ())
        scanner = _scanner()
        self.assertEqual(len(scanner.scan(text, scope=ScanScope.INPUT)), 1)
        self.assertEqual(scanner.scan(text, scope=ScanScope.OUTPUT), ())

    def test_detects_canonical_global_syntax_with_exact_spans(self) -> None:
        values = (
            "+1234567",
            "+14155552671",
            "+442079460958",
            "+919876543210",
            "+123456789012345",
        )
        scanner = _scanner()
        for value in values:
            text = f"contact <{value}>"
            with self.subTest(value=value):
                finding = scanner.scan(text)[0]
                self.assertEqual(
                    text[finding.span.start : finding.span.end],
                    value,
                )
                self.assertEqual(
                    finding.metadata["number_syntax"],
                    "conservative_e164_style",
                )
                self.assertEqual(
                    finding.metadata["validation"],
                    "syntax_and_length_only",
                )
                self.assertEqual(
                    finding.metadata["digit_count"],
                    str(len(value) - 1),
                )

    def test_supports_common_machine_readable_contexts(self) -> None:
        scanner = _scanner()
        value = "+14155552671"
        for text in (
            f"tel:{value}",
            f'{{"phone":"{value}"}}',
            f"phone={value}&synthetic=true",
            f"联系{value}中",
        ):
            with self.subTest(text=text):
                finding = scanner.scan(text)[0]
                self.assertEqual(
                    text[finding.span.start : finding.span.end],
                    value,
                )

    def test_rejects_noncanonical_and_embedded_lookalikes(self) -> None:
        cases = (
            "14155552671",
            "+1",
            "+123456",
            "+0123456789",
            "+1234567890123456",
            "id_A+14155552671",
            "value=1+14155552671",
            "++14155552671",
            "+１4155552671",
            "+1 415 555 2671",
            "+44-20-7946-0958",
            "+44 (0)20 7946 0958",
            "+44.20.7946.0958",
        )
        scanner = _scanner()
        for text in cases:
            with self.subTest(text=text):
                self.assertEqual(scanner.scan(text), ())

    def test_finding_and_redaction_do_not_disclose_number(self) -> None:
        value = "+14155552671"
        text = f"call {value}"
        finding = _scanner().scan(text)[0]
        self.assertIs(finding.action, Action.REDACT)
        self.assertEqual(finding.redacted_preview, "[REDACTED:phone_number]")
        self.assertNotIn(value, finding.message)
        self.assertNotIn(value, repr(finding))
        result = RuleEngine(scanner=_scanner()).process(text)
        self.assertEqual(result.processed_text, "call [REDACTED]")

    def test_candidate_limit_fails_closed_over_uninspected_remainder(self) -> None:
        scanner = _scanner(PhoneNumberConfig(max_candidates=1))
        text = "+14155552671 then +442079460958 trailing private data"
        findings = scanner.scan(text)
        self.assertEqual(len(findings), 2)
        overflow = findings[1]
        self.assertIs(overflow.action, Action.BLOCK)
        self.assertEqual(overflow.metadata["reason"], "candidate_limit_exceeded")
        self.assertEqual(overflow.span.start, text.index("+44"))
        self.assertEqual(overflow.span.end, len(text))

    def test_builtin_policies_redact_block_and_review(self) -> None:
        text = "call +14155552671"
        self.assertIs(
            RuleEngine(scanner=_scanner()).process(text).decision,
            Action.REDACT,
        )
        strict = RuleEngine(scanner=_scanner(), policy=STRICT_POLICY)
        self.assertIs(strict.process(text).decision, Action.BLOCK)
        audit = RuleEngine(scanner=_scanner(), policy=AUDIT_POLICY).process(text)
        self.assertIs(audit.decision, Action.REVIEW)
        self.assertEqual(audit.processed_text, text)

    def test_eight_million_character_adversarial_paths_are_bounded(self) -> None:
        scanner = _scanner()
        workloads = (
            "a" * 8_000_000,
            "+" * 8_000_000,
            ("a" * 7_999_983) + "+1234567890123456",
        )
        started = time.perf_counter()
        for text in workloads:
            self.assertEqual(scanner.scan(text), ())
        self.assertLess(time.perf_counter() - started, 4.0)


class PhoneNumberFacadeTests(unittest.TestCase):
    def test_facade_propagates_configuration_and_capabilities(self) -> None:
        config = PhoneNumberConfig(
            max_candidates=7,
            scopes=(ScanScope.INPUT, ScanScope.OUTPUT),
        )
        firewall = Firewall(
            pool_config=_single_worker_config(),
            phone_number_config=config,
        )
        capabilities = firewall.capabilities()
        self.assertIsNotNone(capabilities.phone_number)
        self.assertEqual(capabilities.phone_number.max_candidates, 7)
        self.assertIn(
            PhoneNumberRule.RULE_ID,
            tuple(rule.rule_id for rule in capabilities.rules),
        )
        with firewall:
            self.assertEqual(
                firewall.sanitize_output("call +14155552671"),
                "call [REDACTED]",
            )

    def test_manager_and_async_facade_preserve_opt_in_configuration(self) -> None:
        manager = FirewallManager(
            pool_config=_single_worker_config(),
            phone_number_config=PhoneNumberConfig(),
        )
        self.assertIsNotNone(manager.capabilities().phone_number)
        with manager:
            self.assertEqual(
                manager.sanitize_input("call +14155552671"),
                "call [REDACTED]",
            )

        asynchronous = AsyncFirewall(
            pool_config=_single_worker_config(),
            phone_number_config=PhoneNumberConfig(),
        )
        self.assertIsNotNone(asynchronous.capabilities().phone_number)

        async def exercise() -> None:
            async with asynchronous:
                self.assertEqual(
                    await asynchronous.sanitize_input("call +14155552671"),
                    "call [REDACTED]",
                )

        asyncio.run(exercise())

    def test_strict_facade_blocks_and_non_config_is_rejected(self) -> None:
        with self.assertRaises(ContentBlockedError):
            firewall = Firewall(
                pool_config=_single_worker_config(),
                phone_number_config=PhoneNumberConfig(),
                policy=STRICT_POLICY,
            )
            with firewall:
                firewall.sanitize_input("call +14155552671")
        with self.assertRaises(TypeError):
            Firewall(phone_number_config=object())  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
