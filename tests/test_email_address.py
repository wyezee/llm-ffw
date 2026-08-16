import asyncio
import time
import unittest

from llm_ffw import (
    AUDIT_POLICY,
    STRICT_POLICY,
    Action,
    AsyncLLMFirewall,
    ContentBlockedError,
    EmailAddressConfig,
    EmailAddressRule,
    Firewall,
    LLMFirewall,
    LLMFirewallManager,
    ProcessScannerPoolConfig,
    ScanScope,
    Scanner,
    StreamMode,
    StreamingSupport,
)


def _scanner(config: EmailAddressConfig | None = None) -> Scanner:
    return Scanner(rules=(EmailAddressRule(config),))


def _single_worker_config() -> ProcessScannerPoolConfig:
    return ProcessScannerPoolConfig(
        max_workers=1,
        max_in_flight=1,
        max_tasks_per_child=10,
    )


class EmailAddressConfigTests(unittest.TestCase):
    def test_rejects_invalid_limits_and_scopes(self) -> None:
        for value in (0, -1, 1_025):
            with self.subTest(value=value), self.assertRaises(ValueError):
                EmailAddressConfig(max_candidates=value)
        with self.assertRaises(TypeError):
            EmailAddressConfig(max_candidates=True)
        for scopes in ((), ("input",), "input"):
            with self.subTest(scopes=scopes), self.assertRaises(
                (TypeError, ValueError)
            ):
                EmailAddressConfig(scopes=scopes)  # type: ignore[arg-type]

    def test_normalizes_scopes_deterministically(self) -> None:
        config = EmailAddressConfig(
            scopes=(ScanScope.OUTPUT, ScanScope.INPUT, ScanScope.OUTPUT)
        )
        self.assertEqual(config.scopes, (ScanScope.INPUT, ScanScope.OUTPUT))


class EmailAddressRuleTests(unittest.TestCase):
    def test_is_opt_in_and_input_only_by_default(self) -> None:
        text = "Contact alice@example.com"
        self.assertEqual(Scanner().scan(text, scope=ScanScope.INPUT), ())
        scanner = _scanner()
        self.assertEqual(len(scanner.scan(text, scope=ScanScope.INPUT)), 1)
        self.assertEqual(scanner.scan(text, scope=ScanScope.OUTPUT), ())

    def test_detects_conservative_ascii_mailboxes_with_exact_spans(self) -> None:
        addresses = (
            "alice@example.com",
            "ALICE@EXAMPLE.COM",
            "first.last+tag@sub.example.co.uk",
            "customer_service@example.travel",
            "a@b.co",
            "user@example.xn--p1ai",
        )
        scanner = _scanner()
        for address in addresses:
            text = f"Contact <{address}>."
            with self.subTest(address=address):
                finding = scanner.scan(text, scope=ScanScope.INPUT)[0]
                self.assertEqual(
                    text[finding.span.start : finding.span.end],
                    address,
                )
                self.assertEqual(
                    finding.metadata["address_syntax"],
                    "conservative_ascii",
                )
                expected_kind = (
                    "punycode_dns_syntax"
                    if "xn--" in address
                    else "ascii_dns_syntax"
                )
                self.assertEqual(
                    finding.metadata["domain_kind"],
                    expected_kind,
                )

    def test_trims_sentence_period_and_supports_common_contexts(self) -> None:
        scanner = _scanner()
        cases = (
            "Email alice@example.com.",
            "mailto:alice@example.com",
            "URL https://example.test/?owner=alice@example.com&ok=1",
        )
        for text in cases:
            with self.subTest(text=text):
                findings = scanner.scan(text, scope=ScanScope.INPUT)
                self.assertEqual(len(findings), 1)
                self.assertEqual(
                    text[findings[0].span.start : findings[0].span.end],
                    "alice@example.com",
                )

    def test_rejects_noncanonical_invalid_and_embedded_lookalikes(self) -> None:
        cases = (
            "alice@example",
            "alice@localhost",
            ".alice@example.com",
            "alice.@example.com",
            "alice..smith@example.com",
            "alice@example..com",
            "alice@-example.com",
            "alice@example-.com",
            "alice@example.c",
            "alice@example.123",
            "alice@exam_ple.com",
            "a@b.com@c.com",
            "éAlice@example.com",
            "alice@example.comé",
            "alice@example.com_suffix",
            '"alice smith"@example.com',
            "alice@[192.0.2.1]",
        )
        scanner = _scanner()
        for text in cases:
            with self.subTest(text=text):
                self.assertEqual(scanner.scan(text, scope=ScanScope.INPUT), ())

    def test_enforces_standard_length_bounds(self) -> None:
        scanner = _scanner()
        valid_local = "a" * 64 + "@example.com"
        invalid_local = "a" * 65 + "@example.com"
        valid_label = "a@" + "b" * 63 + ".com"
        invalid_label = "a@" + "b" * 64 + ".com"
        self.assertEqual(len(scanner.scan(valid_local)), 1)
        self.assertEqual(scanner.scan(invalid_local), ())
        self.assertEqual(len(scanner.scan(valid_label)), 1)
        self.assertEqual(scanner.scan(invalid_label), ())

    def test_finding_and_redaction_do_not_disclose_address(self) -> None:
        address = "customer@example.com"
        text = f"contact {address}"
        finding = _scanner().scan(text, scope=ScanScope.INPUT)[0]
        self.assertIs(finding.action, Action.REDACT)
        self.assertEqual(
            finding.redacted_preview,
            "[REDACTED:email_address]",
        )
        self.assertNotIn(address, finding.message)
        self.assertNotIn(address, repr(finding))
        result = Firewall(scanner=_scanner()).process(
            text,
            scope=ScanScope.INPUT,
        )
        self.assertEqual(result.processed_text, "contact [REDACTED]")

    def test_multiple_addresses_are_ordered_and_redacted_together(self) -> None:
        text = "from alice@example.com to bob@example.org"
        result = Firewall(scanner=_scanner()).process(text)
        self.assertEqual(len(result.findings), 2)
        self.assertLess(
            result.findings[0].span.start,
            result.findings[1].span.start,
        )
        self.assertEqual(
            result.processed_text,
            "from [REDACTED] to [REDACTED]",
        )

    def test_candidate_limit_fails_closed_over_uninspected_remainder(self) -> None:
        scanner = _scanner(EmailAddressConfig(max_candidates=1))
        text = "not@valid then customer@example.com trailing private data"
        finding = scanner.scan(text, scope=ScanScope.INPUT)[0]
        self.assertIs(finding.action, Action.BLOCK)
        self.assertEqual(
            finding.metadata["reason"],
            "candidate_limit_exceeded",
        )
        self.assertEqual(finding.span.start, text.index("@", 4))
        self.assertEqual(finding.span.end, len(text))
        result = Firewall(scanner=scanner).process(text, scope=ScanScope.INPUT)
        self.assertEqual(
            result.processed_text,
            "not@valid then customer[REDACTED]",
        )

    def test_builtin_policies_redact_block_and_review(self) -> None:
        text = "contact customer@example.com"
        balanced = Firewall(scanner=_scanner()).process(
            text,
            scope=ScanScope.INPUT,
        )
        self.assertEqual(balanced.decision, Action.REDACT)
        with self.assertRaises(ContentBlockedError):
            firewall = LLMFirewall(
                pool_config=_single_worker_config(),
                email_address_config=EmailAddressConfig(),
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
            "@" * 8_000_000,
            ("a" * 7_999_992) + "@invalid",
        )
        started = time.perf_counter()
        self.assertEqual(scanner.scan(workloads[0]), ())
        dense = scanner.scan(workloads[1])
        self.assertEqual(len(dense), 1)
        self.assertEqual(
            dense[0].metadata["reason"],
            "candidate_limit_exceeded",
        )
        self.assertEqual(scanner.scan(workloads[2]), ())
        self.assertLess(time.perf_counter() - started, 4.0)


class EmailAddressFacadeTests(unittest.TestCase):
    def test_facade_propagates_configuration_and_capabilities(self) -> None:
        config = EmailAddressConfig(
            max_candidates=7,
            scopes=(ScanScope.INPUT, ScanScope.OUTPUT),
        )
        firewall = LLMFirewall(
            pool_config=_single_worker_config(),
            email_address_config=config,
        )
        capabilities = firewall.capabilities()
        self.assertIsNotNone(capabilities.email_address)
        self.assertEqual(capabilities.email_address.max_candidates, 7)
        self.assertIn(
            EmailAddressRule.RULE_ID,
            tuple(rule.rule_id for rule in capabilities.rules),
        )
        stream = Firewall(scanner=_scanner()).stream()
        email_capability = next(
            item
            for item in stream.rule_capabilities
            if item.rule_id == EmailAddressRule.RULE_ID
        )
        self.assertIs(
            email_capability.support,
            StreamingSupport.END_OF_STREAM,
        )
        self.assertIs(stream.execution_mode, StreamMode.BUFFERED)
        with firewall:
            self.assertEqual(
                firewall.sanitize_output("contact customer@example.com"),
                "contact [REDACTED]",
            )

    def test_manager_and_async_facade_preserve_opt_in_configuration(self) -> None:
        manager = LLMFirewallManager(
            pool_config=_single_worker_config(),
            email_address_config=EmailAddressConfig(),
        )
        self.assertIsNotNone(manager.capabilities().email_address)
        with manager:
            self.assertEqual(
                manager.sanitize_input("contact customer@example.com"),
                "contact [REDACTED]",
            )

        asynchronous = AsyncLLMFirewall(
            pool_config=_single_worker_config(),
            email_address_config=EmailAddressConfig(),
        )
        self.assertIsNotNone(asynchronous.capabilities().email_address)

        async def exercise() -> None:
            async with asynchronous:
                self.assertEqual(
                    await asynchronous.sanitize_input(
                        "contact customer@example.com"
                    ),
                    "contact [REDACTED]",
                )

        asyncio.run(exercise())

    def test_rejects_non_config_value(self) -> None:
        with self.assertRaises(TypeError):
            LLMFirewall(email_address_config=object())


if __name__ == "__main__":
    unittest.main()
