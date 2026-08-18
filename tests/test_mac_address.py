import asyncio
import time
import unittest

from llm_ffw import (
    AUDIT_POLICY,
    STRICT_POLICY,
    Action,
    AsyncFirewall,
    ContentBlockedError,
    RuleEngine,
    Firewall,
    FirewallManager,
    MACAddressConfig,
    MACAddressRule,
    ProcessScannerPoolConfig,
    ScanScope,
    RuleScanner,
    StreamMode,
    StreamingSupport,
)


def _scanner(config: MACAddressConfig | None = None) -> RuleScanner:
    return RuleScanner(rules=(MACAddressRule(config),))


def _single_worker_config() -> ProcessScannerPoolConfig:
    return ProcessScannerPoolConfig(
        max_workers=1,
        max_in_flight=1,
        max_tasks_per_child=10,
    )


class MACAddressConfigTests(unittest.TestCase):
    def test_rejects_invalid_limits_and_scopes(self) -> None:
        for value in (0, -1, 1_025):
            with self.subTest(value=value), self.assertRaises(ValueError):
                MACAddressConfig(max_candidates=value)
        with self.assertRaises(TypeError):
            MACAddressConfig(max_candidates=True)
        for scopes in ((), ("input",), "input"):
            with self.subTest(scopes=scopes), self.assertRaises(
                (TypeError, ValueError)
            ):
                MACAddressConfig(scopes=scopes)  # type: ignore[arg-type]

    def test_normalizes_scopes_deterministically(self) -> None:
        config = MACAddressConfig(
            scopes=(ScanScope.OUTPUT, ScanScope.INPUT, ScanScope.OUTPUT)
        )
        self.assertEqual(config.scopes, (ScanScope.INPUT, ScanScope.OUTPUT))


class MACAddressRuleTests(unittest.TestCase):
    def test_is_opt_in_and_input_only_by_default(self) -> None:
        text = "adapter 02:1A:2B:3C:4D:5E"
        self.assertEqual(RuleScanner().scan(text, scope=ScanScope.INPUT), ())
        self.assertEqual(len(_scanner().scan(text, scope=ScanScope.INPUT)), 1)
        self.assertEqual(_scanner().scan(text, scope=ScanScope.OUTPUT), ())

    def test_detects_canonical_colon_and_hyphen_forms_with_exact_spans(self) -> None:
        cases = (
            ("00:00:00:00:00:00", "colon", "individual", "universal"),
            ("FF-FF-FF-FF-FF-FF", "hyphen", "group", "local"),
            ("02:1a:2B:3c:4D:5e", "colon", "individual", "local"),
            ("01-23-45-67-89-AB", "hyphen", "group", "universal"),
        )
        scanner = _scanner()
        for address, separator, kind, administration in cases:
            text = f"before ({address}) after"
            with self.subTest(address=address):
                finding = scanner.scan(text, scope=ScanScope.INPUT)[0]
                self.assertEqual(
                    text[finding.span.start : finding.span.end], address
                )
                self.assertEqual(finding.metadata["address_syntax"], "eui_48")
                self.assertEqual(finding.metadata["separator"], separator)
                self.assertEqual(finding.metadata["address_kind"], kind)
                self.assertEqual(
                    finding.metadata["administration"], administration
                )

    def test_rejects_noncanonical_invalid_and_embedded_lookalikes(self) -> None:
        cases = (
            "02:1A-2B:3C:4D:5E",
            "021A.2B3C.4D5E",
            "02:1A:2B:3C:4D",
            "02:1A:2B:3C:4D:5E:6F",
            "02:1A:2B:3C:4D:GG",
            "host02:1A:2B:3C:4D:5E",
            "02:1A:2B:3C:4D:5Ehost",
            "prefix_02:1A:2B:3C:4D:5E",
            "550e8400-e29b-41d4-a716-446655440000",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        )
        scanner = _scanner()
        for text in cases:
            with self.subTest(text=text):
                self.assertEqual(scanner.scan(text, scope=ScanScope.INPUT), ())

    def test_trims_sentence_period_without_matching_dotted_suffixes(self) -> None:
        address = "02:1A:2B:3C:4D:5E"
        text = f"Adapter {address}. Continue."
        finding = _scanner().scan(text, scope=ScanScope.INPUT)[0]
        self.assertEqual(text[finding.span.start : finding.span.end], address)
        self.assertEqual(
            _scanner().scan(
                f"Adapter {address}.example", scope=ScanScope.INPUT
            ),
            (),
        )

    def test_finding_and_redaction_do_not_disclose_address(self) -> None:
        address = "02:1A:2B:3C:4D:5E"
        text = f"adapter {address}"
        finding = _scanner().scan(text, scope=ScanScope.INPUT)[0]
        self.assertIs(finding.action, Action.REDACT)
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.redacted_preview, "[REDACTED:mac_address]")
        self.assertNotIn(address, finding.message)
        self.assertNotIn(address, repr(finding))
        result = RuleEngine(scanner=_scanner()).process(
            text, scope=ScanScope.INPUT
        )
        self.assertEqual(result.processed_text, "adapter [REDACTED]")

    def test_candidate_limit_fails_closed_over_uninspected_remainder(self) -> None:
        scanner = _scanner(MACAddressConfig(max_candidates=1))
        text = "02:00:00:00:00:01 then 02:00:00:00:00:02 trailing data"
        findings = scanner.scan(text, scope=ScanScope.INPUT)
        self.assertEqual(len(findings), 2)
        self.assertIs(findings[1].action, Action.BLOCK)
        self.assertEqual(
            findings[1].metadata["reason"], "candidate_limit_exceeded"
        )
        self.assertEqual(findings[1].span.end, len(text))

    def test_builtin_policies_redact_block_and_review(self) -> None:
        text = "adapter 02:1A:2B:3C:4D:5E"
        balanced = RuleEngine(scanner=_scanner()).process(
            text, scope=ScanScope.INPUT
        )
        self.assertEqual(balanced.decision, Action.REDACT)
        audit = RuleEngine(scanner=_scanner(), policy=AUDIT_POLICY).process(
            text, scope=ScanScope.INPUT
        )
        self.assertEqual(audit.decision, Action.REVIEW)
        self.assertEqual(audit.processed_text, text)
        with self.assertRaises(ContentBlockedError):
            firewall = Firewall(
                pool_config=_single_worker_config(),
                mac_address_config=MACAddressConfig(),
                policy=STRICT_POLICY,
            )
            with firewall:
                firewall.sanitize_input(text)

    def test_eight_million_character_adversarial_paths_are_bounded(self) -> None:
        scanner = _scanner()
        workloads = (
            "a" * 8_000_000,
            ":" * 8_000_000,
            ("0:" * 4_000_000)[:8_000_000],
            ("AA-AA-AA-AA-AA-A" * 500_000)[:8_000_000],
        )
        started = time.perf_counter()
        for text in workloads:
            self.assertEqual(scanner.scan(text, scope=ScanScope.INPUT), ())
        self.assertLess(time.perf_counter() - started, 4.0)


class MACAddressFacadeTests(unittest.TestCase):
    def test_facade_propagates_configuration_and_capabilities(self) -> None:
        config = MACAddressConfig(
            max_candidates=7,
            scopes=(ScanScope.INPUT, ScanScope.OUTPUT),
        )
        firewall = Firewall(
            pool_config=_single_worker_config(),
            mac_address_config=config,
        )
        capabilities = firewall.capabilities()
        self.assertIsNotNone(capabilities.mac_address)
        self.assertEqual(capabilities.mac_address.max_candidates, 7)
        self.assertIn(
            MACAddressRule.RULE_ID,
            tuple(rule.rule_id for rule in capabilities.rules),
        )
        stream = RuleEngine(scanner=_scanner()).stream()
        capability = next(
            item
            for item in stream.rule_capabilities
            if item.rule_id == MACAddressRule.RULE_ID
        )
        self.assertIs(capability.support, StreamingSupport.END_OF_STREAM)
        self.assertIs(stream.execution_mode, StreamMode.BUFFERED)
        with firewall:
            self.assertEqual(
                firewall.sanitize_output("adapter 02:1A:2B:3C:4D:5E"),
                "adapter [REDACTED]",
            )

    def test_manager_and_async_facade_preserve_opt_in_configuration(self) -> None:
        manager = FirewallManager(
            pool_config=_single_worker_config(),
            mac_address_config=MACAddressConfig(),
        )
        self.assertIsNotNone(manager.capabilities().mac_address)
        with manager:
            self.assertEqual(
                manager.sanitize_input("adapter 02:1A:2B:3C:4D:5E"),
                "adapter [REDACTED]",
            )

        asynchronous = AsyncFirewall(
            pool_config=_single_worker_config(),
            mac_address_config=MACAddressConfig(),
        )
        self.assertIsNotNone(asynchronous.capabilities().mac_address)

        async def exercise() -> None:
            async with asynchronous:
                self.assertEqual(
                    await asynchronous.sanitize_input(
                        "adapter 02:1A:2B:3C:4D:5E"
                    ),
                    "adapter [REDACTED]",
                )

        asyncio.run(exercise())

    def test_rejects_non_config_value(self) -> None:
        with self.assertRaises(TypeError):
            Firewall(mac_address_config=object())


if __name__ == "__main__":
    unittest.main()
