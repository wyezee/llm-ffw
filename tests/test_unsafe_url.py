import time
import unittest

from llm_ffw import (
    AUDIT_POLICY,
    STRICT_POLICY,
    Action,
    ContentBlockedError,
    RuleEngine,
    Firewall,
    FirewallManager,
    ProcessScannerPoolConfig,
    ScanScope,
    RuleScanner,
    UnsafeURLConfig,
    UnsafeURLRule,
)


def _scanner(config: UnsafeURLConfig | None = None) -> RuleScanner:
    return RuleScanner(rules=(UnsafeURLRule(config),))


def _single_worker_config() -> ProcessScannerPoolConfig:
    return ProcessScannerPoolConfig(
        max_workers=1,
        max_in_flight=1,
        max_tasks_per_child=10,
    )


class UnsafeURLConfigTests(unittest.TestCase):
    def test_rejects_invalid_limits(self) -> None:
        for field_name in ("max_candidates", "max_url_chars"):
            with self.subTest(field_name=field_name), self.assertRaises(
                (TypeError, ValueError)
            ):
                UnsafeURLConfig(**{field_name: 0})
            with self.subTest(field_name=field_name), self.assertRaises(
                TypeError
            ):
                UnsafeURLConfig(**{field_name: True})
        with self.assertRaises(ValueError):
            UnsafeURLConfig(max_candidates=1_025)
        with self.assertRaises(ValueError):
            UnsafeURLConfig(max_url_chars=65_537)
        for scopes in ((), ("input",), "input"):
            with self.subTest(scopes=scopes), self.assertRaises(
                (TypeError, ValueError)
            ):
                UnsafeURLConfig(scopes=scopes)  # type: ignore[arg-type]

    def test_normalizes_scopes_deterministically(self) -> None:
        config = UnsafeURLConfig(
            scopes=(ScanScope.OUTPUT, ScanScope.INPUT, ScanScope.OUTPUT)
        )
        self.assertEqual(config.scopes, (ScanScope.INPUT, ScanScope.OUTPUT))


class UnsafeURLRuleTests(unittest.TestCase):
    def test_applies_to_input_and_output_by_default(self) -> None:
        scanner = _scanner()
        for scope in (ScanScope.INPUT, ScanScope.OUTPUT):
            with self.subTest(scope=scope):
                finding = scanner.scan("javascript:alert(1)", scope=scope)[0]
                self.assertEqual(finding.rule_id, "url.unsafe")

    def test_scopes_can_be_restricted_to_output(self) -> None:
        scanner = _scanner(UnsafeURLConfig(scopes=(ScanScope.OUTPUT,)))
        self.assertEqual(
            scanner.scan("javascript:alert(1)", scope=ScanScope.INPUT),
            (),
        )
        self.assertEqual(
            len(scanner.scan("javascript:alert(1)", scope=ScanScope.OUTPUT)),
            1,
        )

    def test_allows_public_web_urls_and_unrecognized_schemes(self) -> None:
        safe = (
            "https://example.com/path?q=1",
            "HTTP://8.8.8.8/resource",
            "mailto:security@example.com",
            "ordinary label:value prose",
            "notjavascript:alert(1)",
            "not_javascript:alert(1)",
        )
        scanner = _scanner()
        for text in safe:
            with self.subTest(text=text):
                self.assertEqual(
                    scanner.scan(text, scope=ScanScope.OUTPUT),
                    (),
                )

    def test_detects_dangerous_schemes_case_insensitively(self) -> None:
        cases = (
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            "vbscript:msgbox(1)",
            "data:text/html,<script>alert(1)</script>",
            "file:///etc/passwd",
        )
        scanner = _scanner()
        for text in cases:
            with self.subTest(text=text):
                finding = scanner.scan(text, scope=ScanScope.OUTPUT)[0]
                self.assertEqual(finding.rule_id, "url.unsafe")
                self.assertIs(finding.action, Action.REDACT)
                self.assertEqual(finding.metadata["reason"], "dangerous_scheme")
                self.assertEqual(
                    finding.redacted_preview,
                    "[REDACTED:unsafe_url]",
                )

    def test_detects_embedded_userinfo_without_disclosure(self) -> None:
        text = "Visit https://private-user:private-pass@example.com/path now."
        finding = _scanner().scan(text, scope=ScanScope.OUTPUT)[0]

        self.assertEqual(finding.metadata["reason"], "embedded_userinfo")
        self.assertNotIn("private-user", finding.message)
        self.assertNotIn("private-pass", repr(dict(finding.metadata)))
        self.assertEqual(text[finding.span.end], " ")

    def test_detects_local_and_non_public_targets(self) -> None:
        cases = (
            ("http://localhost/admin", "local_hostname"),
            ("http://service.localhost/admin", "local_hostname"),
            ("http://127.0.0.1/admin", "non_public_ip_literal"),
            ("http://10.0.0.1/admin", "non_public_ip_literal"),
            ("http://224.0.0.1/admin", "non_public_ip_literal"),
            ("http://[::1]/admin", "non_public_ip_literal"),
            ("http://[fe80::1]/admin", "non_public_ip_literal"),
            ("http://[ff02::1]/admin", "non_public_ip_literal"),
        )
        scanner = _scanner()
        for text, reason in cases:
            with self.subTest(text=text):
                finding = scanner.scan(text, scope=ScanScope.OUTPUT)[0]
                self.assertEqual(finding.metadata["reason"], reason)

    def test_detects_exact_cloud_metadata_hostnames_without_disclosure(self) -> None:
        cases = (
            "http://metadata.google.internal/computeMetadata/v1/private-value",
            "https://metadata.tencentyun.com/latest/meta-data/private-value",
            "http://METADATA.GOOGLE.INTERNAL./private-value",
        )
        scanner = _scanner()
        for text in cases:
            with self.subTest(text=text):
                finding = scanner.scan(text, scope=ScanScope.OUTPUT)[0]
                self.assertEqual(
                    finding.metadata["reason"], "cloud_metadata_hostname"
                )
                self.assertIs(finding.action, Action.REDACT)
                self.assertNotIn("private-value", finding.message)
                self.assertNotIn(
                    "private-value", repr(dict(finding.metadata))
                )

    def test_cloud_metadata_hostnames_require_an_exact_url_host(self) -> None:
        safe = (
            "https://metadata.google.internal.example.com/path",
            "https://notmetadata.tencentyun.com/path",
            "https://metadata.azure.com/path",
            "metadata.google.internal",
        )
        scanner = _scanner()
        for text in safe:
            with self.subTest(text=text):
                self.assertEqual(
                    scanner.scan(text, scope=ScanScope.OUTPUT),
                    (),
                )

    def test_detects_ambiguous_authorities(self) -> None:
        cases = (
            ("http://2130706433/admin", "ambiguous_numeric_host"),
            ("http://0x7f000001/admin", "ambiguous_numeric_host"),
            ("http://127%2e0%2e0%2e1/admin", "ambiguous_authority"),
            ("http://example.com\\@127.0.0.1/admin", "ambiguous_authority"),
            ("http://example.com:99999/admin", "ambiguous_authority"),
        )
        scanner = _scanner()
        for text, reason in cases:
            with self.subTest(text=text):
                finding = scanner.scan(text, scope=ScanScope.OUTPUT)[0]
                self.assertEqual(finding.metadata["reason"], reason)

    def test_trims_sentence_and_unmatched_markup_punctuation(self) -> None:
        text = "See (javascript:alert(1))."
        finding = _scanner().scan(text, scope=ScanScope.OUTPUT)[0]

        self.assertEqual(text[finding.span.start : finding.span.end], "javascript:alert(1)")
        result = RuleEngine(scanner=_scanner()).process(
            text,
            scope=ScanScope.OUTPUT,
        )
        self.assertEqual(result.processed_text, "See ([REDACTED]).")

    def test_candidate_limit_fails_closed(self) -> None:
        config = UnsafeURLConfig(max_candidates=1)
        text = "https://example.com https://example.org trailing"
        scanner = _scanner(config)
        finding = scanner.scan(
            text,
            scope=ScanScope.OUTPUT,
        )[0]

        self.assertIs(finding.action, Action.BLOCK)
        self.assertEqual(finding.metadata["reason"], "candidate_limit_exceeded")
        self.assertEqual(finding.metadata["limit"], "1")
        self.assertEqual(finding.span.end, len(text))
        balanced = RuleEngine(scanner=scanner).process(
            text,
            scope=ScanScope.OUTPUT,
        )
        self.assertEqual(balanced.processed_text, "https://example.com [REDACTED]")

    def test_candidate_overflow_also_redacts_earlier_unsafe_candidates(self) -> None:
        config = UnsafeURLConfig(max_candidates=1)
        text = "javascript:alert(1) https://example.org trailing"
        result = RuleEngine(scanner=_scanner(config)).process(
            text,
            scope=ScanScope.OUTPUT,
        )

        self.assertEqual(result.processed_text, "[REDACTED] [REDACTED]")
        self.assertEqual(len(result.findings), 2)

    def test_url_length_limit_fails_closed_without_disclosure(self) -> None:
        private_path = "private-value" * 20
        text = "https://example.com/" + private_path
        finding = _scanner(UnsafeURLConfig(max_url_chars=32)).scan(
            text,
            scope=ScanScope.OUTPUT,
        )[0]

        self.assertIs(finding.action, Action.BLOCK)
        self.assertEqual(finding.metadata["reason"], "url_too_long")
        self.assertNotIn(private_path, finding.message)
        self.assertNotIn(private_path, repr(dict(finding.metadata)))

    def test_eight_million_clean_characters_use_fast_non_match_path(self) -> None:
        self.assertEqual(
            _scanner().scan("a" * 8_000_000, scope=ScanScope.OUTPUT),
            (),
        )

    def test_overlapping_scheme_markers_scan_one_candidate_linearly(self) -> None:
        text = "http://" * 129 + "a" * 1_000_000

        started = time.perf_counter()
        findings = _scanner().scan(text, scope=ScanScope.OUTPUT)
        elapsed = time.perf_counter() - started

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].metadata["reason"], "url_too_long")
        self.assertLess(elapsed, 1.0)

    def test_builtin_policies_redact_block_and_review(self) -> None:
        text = "Open javascript:alert(1)"
        for scope in (ScanScope.INPUT, ScanScope.OUTPUT):
            with self.subTest(scope=scope):
                balanced = RuleEngine(scanner=_scanner()).process(text, scope=scope)
                strict = RuleEngine(
                    scanner=_scanner(), policy=STRICT_POLICY
                ).process(text, scope=scope)
                audit = RuleEngine(
                    scanner=_scanner(), policy=AUDIT_POLICY
                ).process(text, scope=scope)

                self.assertEqual(balanced.processed_text, "Open [REDACTED]")
                self.assertTrue(strict.blocked)
                self.assertIs(audit.decision, Action.REVIEW)
                self.assertEqual(audit.processed_text, text)


class UnsafeURLFacadeTests(unittest.TestCase):
    def test_is_opt_in_and_advertises_bounded_configuration(self) -> None:
        disabled = Firewall(pool_config=_single_worker_config())
        enabled = Firewall(
            pool_config=_single_worker_config(),
            unsafe_url_config=UnsafeURLConfig(
                max_candidates=32,
                max_url_chars=1_024,
            ),
        )

        self.assertNotIn(
            "url.unsafe",
            tuple(rule.rule_id for rule in disabled.capabilities().rules),
        )
        self.assertIn(
            "url.unsafe",
            tuple(rule.rule_id for rule in enabled.capabilities().rules),
        )
        self.assertEqual(enabled.capabilities().unsafe_url.max_candidates, 32)
        self.assertEqual(enabled.capabilities().unsafe_url.max_url_chars, 1_024)
        unsafe_capability = tuple(
            rule
            for rule in enabled.capabilities().rules
            if rule.rule_id == "url.unsafe"
        )[0]
        self.assertEqual(
            unsafe_capability.scopes,
            (ScanScope.INPUT, ScanScope.OUTPUT),
        )
        disabled.close()
        enabled.close()

    def test_worker_redacts_unsafe_input_and_output(self) -> None:
        firewall = Firewall(
            pool_config=_single_worker_config(),
            unsafe_url_config=UnsafeURLConfig(),
        )

        with firewall:
            self.assertEqual(
                firewall.sanitize_input("javascript:alert(1)"),
                "[REDACTED]",
            )
            self.assertEqual(
                firewall.sanitize_output("Open javascript:alert(1)"),
                "Open [REDACTED]",
            )

    def test_worker_strict_policy_blocks_unsafe_output(self) -> None:
        firewall = Firewall(
            pool_config=_single_worker_config(),
            unsafe_url_config=UnsafeURLConfig(),
            policy=STRICT_POLICY,
        )

        with firewall, self.assertRaises(ContentBlockedError) as raised:
            firewall.sanitize_output("http://127.0.0.1/admin")

        self.assertEqual(raised.exception.findings[0].rule_id, "url.unsafe")

    def test_rejects_non_config_value(self) -> None:
        with self.assertRaises(TypeError):
            Firewall(unsafe_url_config=True)  # type: ignore[arg-type]

    def test_manager_propagates_rule_configuration(self) -> None:
        manager = FirewallManager(
            pool_config=_single_worker_config(),
            unsafe_url_config=UnsafeURLConfig(),
        ).start()
        try:
            capabilities = manager.capabilities()
            self.assertIn(
                "url.unsafe",
                tuple(rule.rule_id for rule in capabilities.rules),
            )
            self.assertEqual(
                manager.sanitize_output("Open file:///private/path"),
                "Open [REDACTED]",
            )
        finally:
            manager.close()


if __name__ == "__main__":
    unittest.main()
