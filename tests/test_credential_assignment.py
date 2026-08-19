import asyncio
import time
import unittest

from llm_ffw import (
    AUDIT_POLICY,
    STRICT_POLICY,
    Action,
    AsyncFirewall,
    CredentialAssignmentCapability,
    CredentialAssignmentConfig,
    CredentialAssignmentRule,
    Firewall,
    FirewallConfig,
    FirewallManager,
    FirewallStream,
    IncrementalStreamingUnavailableError,
    ProcessScannerPoolConfig,
    RuleEngine,
    RuleScanner,
    ScanScope,
    StreamMode,
    StreamingSupport,
)


_CREDENTIAL = "synthetic-assigned-credential-123"


def _scanner(
    config: CredentialAssignmentConfig | None = None,
) -> RuleScanner:
    return RuleScanner(rules=(CredentialAssignmentRule(config),))


def _single_worker_config() -> ProcessScannerPoolConfig:
    return ProcessScannerPoolConfig(
        max_workers=1,
        max_in_flight=1,
        max_tasks_per_child=10,
    )


class CredentialAssignmentConfigTests(unittest.TestCase):
    def test_rejects_invalid_limits_keywords_and_scopes(self) -> None:
        for field_name, values in (
            ("max_candidates", (0, -1, True, 1_025)),
            ("max_value_chars", (0, -1, True, 65_537)),
        ):
            for value in values:
                with self.subTest(field_name=field_name, value=value), self.assertRaises(
                    (TypeError, ValueError)
                ):
                    CredentialAssignmentConfig(**{field_name: value})
        for keywords in (
            "tenant_key",
            ("UPPERCASE",),
            ("contains space",),
            ("x",),
            tuple(f"keyword_{index}" for index in range(257)),
        ):
            with self.subTest(keywords=type(keywords).__name__), self.assertRaises(
                (TypeError, ValueError)
            ):
                CredentialAssignmentConfig(additional_keywords=keywords)  # type: ignore[arg-type]
        for scopes in ((), (ScanScope.TOOL_CALL,), ("input",), "input"):
            with self.subTest(scopes=scopes), self.assertRaises(
                (TypeError, ValueError)
            ):
                CredentialAssignmentConfig(scopes=scopes)  # type: ignore[arg-type]

    def test_normalizes_configuration_without_disclosing_custom_names(self) -> None:
        config = CredentialAssignmentConfig(
            additional_keywords=("tenant.credential", "tenant_credential"),
            scopes=(ScanScope.OUTPUT, ScanScope.INPUT, ScanScope.OUTPUT),
        )
        self.assertEqual(config.additional_keywords, ("tenant_credential",))
        self.assertEqual(config.scopes, (ScanScope.INPUT, ScanScope.OUTPUT))
        self.assertNotIn("tenant_credential", repr(config))
        capability = CredentialAssignmentCapability(128, 8_192, 13)
        self.assertEqual(capability.keyword_count, 13)
        with self.assertRaises(ValueError):
            CredentialAssignmentCapability(128, 8_192, 0)


class CredentialAssignmentRuleTests(unittest.TestCase):
    def test_is_opt_in_and_supports_both_text_scopes(self) -> None:
        text = f"DB_PASSWORD={_CREDENTIAL}"
        self.assertEqual(RuleScanner().scan(text), ())
        self.assertEqual(len(_scanner().scan(text, scope=ScanScope.INPUT)), 1)
        self.assertEqual(len(_scanner().scan(text, scope=ScanScope.OUTPUT)), 1)

    def test_detects_supported_assignment_forms_with_exact_value_spans(self) -> None:
        cases = (
            f"AWS_SECRET_ACCESS_KEY={_CREDENTIAL}",
            f"DB_PASSWORD={_CREDENTIAL}",
            f"export API_SECRET={_CREDENTIAL}",
            f"client_secret: {_CREDENTIAL}",
            f'{{"client_secret":"{_CREDENTIAL}","enabled":true}}',
            f"'refresh_token': '{_CREDENTIAL}'",
            f"service.api-key={_CREDENTIAL}",
        )
        scanner = _scanner()
        for text in cases:
            with self.subTest(text=text[:30]):
                finding = scanner.scan(text)[0]
                self.assertEqual(
                    text[finding.span.start : finding.span.end],
                    _CREDENTIAL,
                )
                self.assertEqual(
                    finding.metadata["detector"],
                    "bounded_credential_assignment",
                )
                self.assertNotIn("field", finding.metadata)
                self.assertNotIn("keyword", finding.metadata)

    def test_custom_keywords_are_exact_normalized_extensions(self) -> None:
        config = CredentialAssignmentConfig(
            additional_keywords=("tenant.credential",)
        )
        scanner = _scanner(config)
        finding = scanner.scan(f"tenant-credential={_CREDENTIAL}")[0]
        self.assertEqual(finding.metadata["custom_keyword"], "true")
        self.assertEqual(
            scanner.scan(f"prefix_tenant_credential={_CREDENTIAL}"),
            (),
        )

    def test_rejects_placeholders_templates_and_non_assignment_text(self) -> None:
        cases = (
            "password=<password>",
            "password=${PASSWORD}",
            "password={{ password }}",
            "password=YOUR_PASSWORD",
            "password=REDACTED",
            '"api_key": "your-key-here"',
            "secret=not-a-built-in-generic-keyword",
            "password policy: rotate every 30 days",
            "The password: should remain private",
            "password_hash=not-a-credential-assignment",
            "client_secret=true",
            "client_secret=abc",
            '"password": {"nested": "value"}',
            '"password": ["value"]',
        )
        scanner = _scanner()
        for text in cases:
            with self.subTest(text=text):
                self.assertEqual(scanner.scan(text), ())

    def test_handles_quoted_escapes_and_malformed_values_without_disclosure(self) -> None:
        escaped = f'{{"api_key":"{_CREDENTIAL}\\\"suffix"}}'
        escaped_finding = _scanner().scan(escaped)[0]
        self.assertEqual(
            escaped[escaped_finding.span.start : escaped_finding.span.end],
            _CREDENTIAL + '\\"suffix',
        )

        malformed = f'password="{_CREDENTIAL}'
        finding = _scanner().scan(malformed)[0]
        self.assertEqual(
            finding.metadata["reason"],
            "malformed_assigned_credential",
        )
        self.assertNotIn(_CREDENTIAL, finding.message)
        self.assertNotIn(_CREDENTIAL, repr(finding))

    def test_candidate_and_value_limits_fail_closed(self) -> None:
        text = f"password={_CREDENTIAL}\napi_key={_CREDENTIAL}"
        findings = _scanner(
            CredentialAssignmentConfig(max_candidates=1)
        ).scan(text)
        self.assertEqual(len(findings), 2)
        self.assertEqual(
            findings[-1].metadata["reason"],
            "candidate_limit_exceeded",
        )
        self.assertIs(findings[-1].action, Action.BLOCK)

        oversized_text = "password=" + "Z" * 64
        oversized_scanner = _scanner(
            CredentialAssignmentConfig(max_value_chars=8)
        )
        oversized = oversized_scanner.scan(oversized_text)[0]
        self.assertEqual(
            oversized.metadata["reason"],
            "credential_limit_exceeded",
        )
        self.assertIs(oversized.action, Action.BLOCK)
        processed = RuleEngine(scanner=oversized_scanner).process(oversized_text)
        self.assertNotIn("Z", processed.processed_text)

        exact_boundary = _scanner(
            CredentialAssignmentConfig(max_value_chars=8)
        ).scan("password=12345678")[0]
        self.assertEqual(exact_boundary.metadata["reason"], "assigned_credential")
        one_over = _scanner(
            CredentialAssignmentConfig(max_value_chars=8)
        ).scan("password=123456789")[0]
        self.assertEqual(one_over.metadata["reason"], "credential_limit_exceeded")

    def test_policies_redact_block_and_review(self) -> None:
        text = f"password={_CREDENTIAL}"
        scanner = _scanner()
        balanced = RuleEngine(scanner=scanner).process(text)
        self.assertIs(balanced.decision, Action.REDACT)
        self.assertEqual(balanced.processed_text, "password=[REDACTED]")
        self.assertIs(
            RuleEngine(scanner=scanner, policy=STRICT_POLICY).process(text).decision,
            Action.BLOCK,
        )
        audited = RuleEngine(scanner=scanner, policy=AUDIT_POLICY).process(text)
        self.assertIs(audited.decision, Action.REVIEW)
        self.assertEqual(audited.processed_text, text)

    def test_streaming_buffers_complete_assignments_without_partial_leaks(self) -> None:
        stream = FirewallStream(scanner=_scanner())
        self.assertIs(stream.execution_mode, StreamMode.BUFFERED)
        self.assertIs(
            stream.rule_capabilities[0].support,
            StreamingSupport.END_OF_STREAM,
        )
        self.assertEqual(stream.feed("password=synthetic-assigned-"), "")
        self.assertEqual(stream.feed("credential-123"), "")
        self.assertEqual(stream.finish(), "password=[REDACTED]")
        with self.assertRaises(IncrementalStreamingUnavailableError):
            FirewallStream(scanner=_scanner(), mode=StreamMode.INCREMENTAL)

    def test_eight_million_character_paths_are_bounded(self) -> None:
        scanner = _scanner()
        clean = "a" * 8_000_000
        unrelated = ("ordinary_field=ordinary_value\n" * 300_000)[:8_000_000]
        oversized = "password=" + "Z" * (8_000_000 - len("password="))
        started = time.perf_counter()
        self.assertEqual(scanner.scan(clean), ())
        self.assertEqual(scanner.scan(unrelated), ())
        self.assertEqual(
            scanner.scan(oversized)[0].metadata["reason"],
            "credential_limit_exceeded",
        )
        # Keep a generous runaway guard; the dedicated benchmark owns the
        # production throughput and memory thresholds.
        self.assertLess(time.perf_counter() - started, 5.0)


class CredentialAssignmentFacadeTests(unittest.TestCase):
    def test_facades_propagate_configuration_and_capability(self) -> None:
        config = CredentialAssignmentConfig(
            max_candidates=7,
            max_value_chars=512,
            additional_keywords=("tenant_credential",),
        )
        firewall = Firewall(
            pool_config=_single_worker_config(),
            credential_assignment_config=config,
        )
        capability = firewall.capabilities().credential_assignment
        self.assertIsNotNone(capability)
        self.assertEqual(capability.max_candidates, 7)  # type: ignore[union-attr]
        self.assertEqual(capability.keyword_count, 13)  # type: ignore[union-attr]
        with firewall:
            self.assertEqual(
                firewall.sanitize_output(f"password={_CREDENTIAL}"),
                "password=[REDACTED]",
            )

        manager = FirewallManager(
            pool_config=_single_worker_config(),
            credential_assignment_config=config,
        )
        with manager:
            self.assertEqual(
                manager.sanitize_input(f"tenant_credential={_CREDENTIAL}"),
                "tenant_credential=[REDACTED]",
            )

        asynchronous = AsyncFirewall(
            pool_config=_single_worker_config(),
            credential_assignment_config=config,
        )

        async def exercise() -> None:
            async with asynchronous:
                self.assertEqual(
                    await asynchronous.sanitize_input(
                        f"client_secret={_CREDENTIAL}"
                    ),
                    "client_secret=[REDACTED]",
                )

        asyncio.run(exercise())

    def test_firewall_config_enables_rule_and_rejects_wrong_type(self) -> None:
        config = FirewallConfig(
            credential_assignment_config=CredentialAssignmentConfig()
        )
        self.assertIsNotNone(
            Firewall.from_config(config).capabilities().credential_assignment
        )
        with self.assertRaises(TypeError):
            Firewall(credential_assignment_config=object())


if __name__ == "__main__":
    unittest.main()
