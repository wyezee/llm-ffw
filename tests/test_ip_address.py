import asyncio
import time
import unittest

from llm_ffw import (
    AUDIT_POLICY,
    STRICT_POLICY,
    Action,
    AsyncLLMFirewall,
    ContentBlockedError,
    Firewall,
    IPAddressConfig,
    IPAddressRule,
    LLMFirewall,
    LLMFirewallManager,
    ProcessScannerPoolConfig,
    ScanScope,
    Scanner,
    StreamMode,
    StreamingSupport,
)


def _scanner(config: IPAddressConfig | None = None) -> Scanner:
    return Scanner(rules=(IPAddressRule(config),))


def _single_worker_config() -> ProcessScannerPoolConfig:
    return ProcessScannerPoolConfig(
        max_workers=1,
        max_in_flight=1,
        max_tasks_per_child=10,
    )


class IPAddressConfigTests(unittest.TestCase):
    def test_rejects_invalid_limits_families_and_scopes(self) -> None:
        for value in (0, -1, 1_025):
            with self.subTest(value=value), self.assertRaises(ValueError):
                IPAddressConfig(max_candidates=value)
        with self.assertRaises(TypeError):
            IPAddressConfig(max_candidates=True)
        for field_name in ("include_ipv4", "include_ipv6"):
            with self.subTest(field_name=field_name), self.assertRaises(
                TypeError
            ):
                IPAddressConfig(**{field_name: 1})
        with self.assertRaises(ValueError):
            IPAddressConfig(include_ipv4=False, include_ipv6=False)
        for scopes in ((), ("input",), "input"):
            with self.subTest(scopes=scopes), self.assertRaises(
                (TypeError, ValueError)
            ):
                IPAddressConfig(scopes=scopes)  # type: ignore[arg-type]

    def test_normalizes_scopes_deterministically(self) -> None:
        config = IPAddressConfig(
            scopes=(ScanScope.OUTPUT, ScanScope.INPUT, ScanScope.OUTPUT)
        )
        self.assertEqual(config.scopes, (ScanScope.INPUT, ScanScope.OUTPUT))


class IPAddressRuleTests(unittest.TestCase):
    def test_is_opt_in_and_input_only_by_default(self) -> None:
        text = "internal host 192.168.10.12"
        self.assertEqual(Scanner().scan(text, scope=ScanScope.INPUT), ())
        scanner = _scanner()
        self.assertEqual(len(scanner.scan(text, scope=ScanScope.INPUT)), 1)
        self.assertEqual(scanner.scan(text, scope=ScanScope.OUTPUT), ())

    def test_detects_canonical_ipv4_with_exact_spans(self) -> None:
        cases = (
            ("0.0.0.0", "unspecified"),
            ("127.0.0.1", "loopback"),
            ("169.254.1.2", "link_local"),
            ("192.168.1.25", "private"),
            ("8.8.8.8", "global"),
            ("224.0.0.1", "multicast"),
            ("255.255.255.255", "private"),
        )
        scanner = _scanner()
        for address, address_class in cases:
            text = f"before ({address}):443 after"
            with self.subTest(address=address):
                finding = scanner.scan(text, scope=ScanScope.INPUT)[0]
                self.assertEqual(
                    text[finding.span.start : finding.span.end],
                    address,
                )
                self.assertEqual(finding.metadata["ip_version"], "4")
                self.assertEqual(
                    finding.metadata["address_class"],
                    address_class,
                )

    def test_detects_canonical_ipv6_forms(self) -> None:
        cases = (
            "::",
            "::1",
            "2001:db8::1",
            "2001:4860:4860::8888",
            "2001:db8:0:1:1:1:1:1",
            "::ffff:192.0.2.128",
        )
        scanner = _scanner()
        for address in cases:
            text = f"endpoint [{address}]."
            with self.subTest(address=address):
                findings = scanner.scan(text, scope=ScanScope.INPUT)
                self.assertEqual(len(findings), 1)
                finding = findings[0]
                self.assertEqual(
                    text[finding.span.start : finding.span.end],
                    address,
                )
                self.assertEqual(finding.metadata["ip_version"], "6")

    def test_trims_sentence_period_without_matching_dotted_suffixes(self) -> None:
        scanner = _scanner()
        for address in ("192.0.2.255", "2001:db8:0:1:1:1:1:1"):
            with self.subTest(address=address):
                text = f"Endpoint {address}. Continue."
                finding = scanner.scan(text, scope=ScanScope.INPUT)[0]
                self.assertEqual(
                    text[finding.span.start : finding.span.end],
                    address,
                )
        for text in (
            "host 192.0.2.1.example",
            "host 2001:db8:0:1:1:1:1:1.example",
        ):
            with self.subTest(text=text):
                self.assertEqual(scanner.scan(text, scope=ScanScope.INPUT), ())

    def test_rejects_noncanonical_invalid_and_embedded_lookalikes(self) -> None:
        cases = (
            "999.1.1.1",
            "192.168.1.999",
            "01.2.3.4",
            "1.2.3",
            "1.2.3.4.5",
            "host192.168.1.1",
            "192.168.1.1host",
            "2001:db8:::1",
            "2001:db8:1",
            "12:34:56",
            "release 1.2.3.4-beta",
        )
        scanner = _scanner()
        for text in cases:
            with self.subTest(text=text):
                self.assertEqual(scanner.scan(text, scope=ScanScope.INPUT), ())

    def test_address_families_can_be_selected_independently(self) -> None:
        text = "IPv4 192.168.1.1 and IPv6 2001:db8::1"
        ipv4 = _scanner(IPAddressConfig(include_ipv6=False)).scan(
            text,
            scope=ScanScope.INPUT,
        )
        ipv6 = _scanner(IPAddressConfig(include_ipv4=False)).scan(
            text,
            scope=ScanScope.INPUT,
        )
        self.assertEqual(tuple(item.metadata["ip_version"] for item in ipv4), ("4",))
        self.assertEqual(tuple(item.metadata["ip_version"] for item in ipv6), ("6",))

    def test_invalid_ipv6_shape_does_not_hide_embedded_ipv4(self) -> None:
        text = "endpoint 1:2:999:192.168.1.1"
        findings = _scanner().scan(text, scope=ScanScope.INPUT)
        self.assertEqual(len(findings), 1)
        self.assertEqual(
            text[findings[0].span.start : findings[0].span.end],
            "192.168.1.1",
        )

    def test_finding_and_redaction_do_not_disclose_address(self) -> None:
        address = "203.0.113.42"
        text = f"customer address {address}"
        finding = _scanner().scan(text, scope=ScanScope.INPUT)[0]
        self.assertIs(finding.action, Action.REDACT)
        self.assertEqual(finding.redacted_preview, "[REDACTED:ip_address]")
        self.assertNotIn(address, finding.message)
        self.assertNotIn(address, repr(finding))
        result = Firewall(scanner=_scanner()).process(
            text,
            scope=ScanScope.INPUT,
        )
        self.assertEqual(result.processed_text, "customer address [REDACTED]")

    def test_candidate_limit_fails_closed_over_uninspected_remainder(self) -> None:
        scanner = _scanner(IPAddressConfig(max_candidates=1))
        text = "999.999.999.999 then 192.168.1.1 trailing private data"
        finding = scanner.scan(text, scope=ScanScope.INPUT)[0]
        self.assertIs(finding.action, Action.BLOCK)
        self.assertEqual(
            finding.metadata["reason"],
            "candidate_limit_exceeded",
        )
        self.assertEqual(finding.span.end, len(text))
        result = Firewall(scanner=scanner).process(text, scope=ScanScope.INPUT)
        self.assertEqual(
            result.processed_text,
            "999.999.999.999 then [REDACTED]",
        )

    def test_builtin_policies_redact_block_and_review(self) -> None:
        text = "source 192.168.1.1"
        balanced = Firewall(scanner=_scanner()).process(
            text,
            scope=ScanScope.INPUT,
        )
        self.assertEqual(balanced.decision, Action.REDACT)
        with self.assertRaises(ContentBlockedError):
            firewall = LLMFirewall(
                pool_config=_single_worker_config(),
                ip_address_config=IPAddressConfig(),
                policy=STRICT_POLICY,
            )
            with firewall:
                firewall.sanitize_input(text)
        audit = Firewall(scanner=_scanner(), policy=AUDIT_POLICY).process(
            text,
            scope=ScanScope.INPUT,
        )
        self.assertEqual(audit.decision, Action.REVIEW)
        self.assertEqual(audit.processed_text, text)

    def test_eight_million_character_adversarial_paths_are_bounded(self) -> None:
        scanner = _scanner()
        workloads = (
            "a" * 8_000_000,
            ":" * 8_000_000,
            ("999." * 2_000_000)[:8_000_000],
        )
        started = time.perf_counter()
        for text in workloads:
            self.assertEqual(scanner.scan(text, scope=ScanScope.INPUT), ())
        self.assertLess(time.perf_counter() - started, 4.0)


class IPAddressFacadeTests(unittest.TestCase):
    def test_facade_propagates_configuration_and_capabilities(self) -> None:
        config = IPAddressConfig(
            max_candidates=7,
            include_ipv6=False,
            scopes=(ScanScope.INPUT, ScanScope.OUTPUT),
        )
        firewall = LLMFirewall(
            pool_config=_single_worker_config(),
            ip_address_config=config,
        )
        capabilities = firewall.capabilities()
        self.assertIsNotNone(capabilities.ip_address)
        self.assertEqual(capabilities.ip_address.max_candidates, 7)
        self.assertTrue(capabilities.ip_address.include_ipv4)
        self.assertFalse(capabilities.ip_address.include_ipv6)
        self.assertIn(
            IPAddressRule.RULE_ID,
            tuple(rule.rule_id for rule in capabilities.rules),
        )
        stream = Firewall(scanner=_scanner()).stream()
        ip_capability = next(
            item
            for item in stream.rule_capabilities
            if item.rule_id == IPAddressRule.RULE_ID
        )
        self.assertIs(ip_capability.support, StreamingSupport.END_OF_STREAM)
        self.assertIs(stream.execution_mode, StreamMode.BUFFERED)
        with firewall:
            self.assertEqual(
                firewall.sanitize_output("target 10.20.30.40"),
                "target [REDACTED]",
            )

    def test_manager_and_async_facade_preserve_opt_in_configuration(self) -> None:
        manager = LLMFirewallManager(
            pool_config=_single_worker_config(),
            ip_address_config=IPAddressConfig(),
        )
        self.assertIsNotNone(manager.capabilities().ip_address)
        with manager:
            self.assertEqual(
                manager.sanitize_input("host 10.1.2.3"),
                "host [REDACTED]",
            )

        asynchronous = AsyncLLMFirewall(
            pool_config=_single_worker_config(),
            ip_address_config=IPAddressConfig(),
        )
        self.assertIsNotNone(asynchronous.capabilities().ip_address)

        async def exercise() -> None:
            async with asynchronous:
                self.assertEqual(
                    await asynchronous.sanitize_input("host 10.1.2.3"),
                    "host [REDACTED]",
                )

        asyncio.run(exercise())

    def test_rejects_non_config_value(self) -> None:
        with self.assertRaises(TypeError):
            LLMFirewall(ip_address_config=object())


if __name__ == "__main__":
    unittest.main()
