import unittest

from llm_ffw import (
    AUDIT_POLICY,
    STRICT_POLICY,
    Action,
    ContentBlockedError,
    Firewall,
    LLMFirewall,
    LLMFirewallManager,
    PrivateKeyConfig,
    PrivateKeyRule,
    ProcessScannerPoolConfig,
    ScanScope,
    Scanner,
    ScannerConfig,
)


def _block(label: str, body: str = "QUJDREVGR0hJSktMTU5PUA==") -> str:
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----"


def _scanner(config: PrivateKeyConfig | None = None) -> Scanner:
    return Scanner(rules=(PrivateKeyRule(config),))


def _single_worker_config() -> ProcessScannerPoolConfig:
    return ProcessScannerPoolConfig(
        max_workers=1,
        max_in_flight=1,
        max_tasks_per_child=10,
    )


class PrivateKeyConfigTests(unittest.TestCase):
    def test_rejects_invalid_limits_and_scopes(self) -> None:
        for field_name, values in (
            ("max_candidates", (0, -1, True, 257)),
            ("max_block_chars", (0, -1, True, 8_000_001)),
        ):
            for value in values:
                with self.subTest(field_name=field_name, value=value), self.assertRaises(
                    (TypeError, ValueError)
                ):
                    PrivateKeyConfig(**{field_name: value})  # type: ignore[arg-type]
        for scopes in ((), ("input",), "input"):
            with self.subTest(scopes=scopes), self.assertRaises(
                (TypeError, ValueError)
            ):
                PrivateKeyConfig(scopes=scopes)  # type: ignore[arg-type]

    def test_normalizes_scopes_deterministically(self) -> None:
        config = PrivateKeyConfig(
            scopes=(ScanScope.OUTPUT, ScanScope.INPUT, ScanScope.OUTPUT)
        )
        self.assertEqual(config.scopes, (ScanScope.INPUT, ScanScope.OUTPUT))


class PrivateKeyRuleTests(unittest.TestCase):
    def test_detects_supported_armored_formats(self) -> None:
        formats = {
            "PRIVATE KEY": "pkcs8",
            "ENCRYPTED PRIVATE KEY": "pkcs8_encrypted",
            "RSA PRIVATE KEY": "pkcs1_rsa",
            "DSA PRIVATE KEY": "dsa",
            "EC PRIVATE KEY": "sec1_ec",
            "OPENSSH PRIVATE KEY": "openssh",
            "PGP PRIVATE KEY BLOCK": "openpgp",
        }
        for label, format_name in formats.items():
            with self.subTest(label=label):
                value = _block(label)
                finding = _scanner().scan(f"before {value} after")[0]
                self.assertEqual(finding.rule_id, "secrets.private_key")
                self.assertIs(finding.action, Action.REDACT)
                self.assertEqual(finding.severity.value, "high")
                self.assertEqual(finding.metadata["format"], format_name)
                self.assertEqual(finding.redacted_preview, "[REDACTED:private_key]")

    def test_redacts_complete_block_in_both_scopes(self) -> None:
        value = _block("PRIVATE KEY")
        text = f"before {value} after"
        for scope in (ScanScope.INPUT, ScanScope.OUTPUT):
            with self.subTest(scope=scope):
                result = Firewall(scanner=_scanner()).process(text, scope=scope)
                self.assertEqual(result.processed_text, "before [REDACTED] after")

    def test_ignores_public_certificates_unknown_labels_and_lookalikes(self) -> None:
        safe = (
            _block("PUBLIC KEY"),
            _block("CERTIFICATE"),
            "-----BEGIN PRIVATE KEY----\nnot a marker",
            "-----begin private key-----\ncase sensitive",
            "ordinary prose",
        )
        for text in safe:
            with self.subTest(text=text[:40]):
                self.assertEqual(_scanner().scan(text), ())

    def test_missing_end_marker_contains_uninspected_remainder(self) -> None:
        text = "prefix " + "-----BEGIN PRIVATE KEY-----\nQUJD\ntrailing"
        finding = _scanner().scan(text)[0]
        self.assertIs(finding.action, Action.BLOCK)
        self.assertEqual(finding.metadata["reason"], "missing_end_marker")
        self.assertEqual(finding.span.end, len(text))
        result = Firewall(scanner=_scanner()).process(text)
        self.assertEqual(result.processed_text, "prefix [REDACTED]")

    def test_oversized_block_and_candidate_overflow_fail_closed(self) -> None:
        oversized = _block("PRIVATE KEY", "A" * 80) + " uninspected tail"
        finding = _scanner(PrivateKeyConfig(max_block_chars=64)).scan(oversized)[0]
        self.assertIs(finding.action, Action.BLOCK)
        self.assertEqual(finding.metadata["reason"], "block_size_exceeded")
        self.assertEqual(finding.span.end, len(oversized))
        self.assertEqual(
            Firewall(
                scanner=_scanner(PrivateKeyConfig(max_block_chars=64))
            ).process(oversized).processed_text,
            "[REDACTED]",
        )

        first = _block("EC PRIVATE KEY")
        second = _block("RSA PRIVATE KEY")
        text = first + " gap " + second + " tail"
        findings = _scanner(PrivateKeyConfig(max_candidates=1)).scan(text)
        self.assertEqual(len(findings), 2)
        self.assertEqual(
            findings[1].metadata["reason"], "candidate_limit_exceeded"
        )
        self.assertEqual(findings[1].span.end, len(text))

    def test_finding_does_not_disclose_body_or_markers(self) -> None:
        private_body = "UNIQUE_SYNTHETIC_PRIVATE_BODY_12345"
        value = _block("PRIVATE KEY", private_body)
        finding = _scanner().scan(value)[0]
        exposed = finding.message + finding.redacted_preview + repr(dict(finding.metadata))
        self.assertNotIn(private_body, exposed)
        self.assertNotIn("-----BEGIN", exposed)

    def test_scopes_can_be_restricted(self) -> None:
        value = _block("PRIVATE KEY")
        output_only = _scanner(PrivateKeyConfig(scopes=(ScanScope.OUTPUT,)))
        self.assertEqual(output_only.scan(value, scope=ScanScope.INPUT), ())
        self.assertEqual(len(output_only.scan(value, scope=ScanScope.OUTPUT)), 1)

    def test_long_clean_and_marker_dense_inputs_are_safe_non_matches(self) -> None:
        self.assertEqual(_scanner().scan("a" * 8_000_000), ())
        marker_dense = ("-----BEGIN CERTIFICATE-----" * 290_000)[:8_000_000]
        self.assertEqual(_scanner().scan(marker_dense), ())

    def test_builtin_policies_redact_block_and_review(self) -> None:
        value = _block("OPENSSH PRIVATE KEY")
        for scope in (ScanScope.INPUT, ScanScope.OUTPUT):
            with self.subTest(scope=scope):
                balanced = Firewall(scanner=_scanner()).process(value, scope=scope)
                strict = Firewall(
                    scanner=_scanner(), policy=STRICT_POLICY
                ).process(value, scope=scope)
                audit = Firewall(
                    scanner=_scanner(), policy=AUDIT_POLICY
                ).process(value, scope=scope)
                self.assertEqual(balanced.processed_text, "[REDACTED]")
                self.assertTrue(strict.blocked)
                self.assertIs(audit.decision, Action.REVIEW)
                self.assertEqual(audit.processed_text, value)


class PrivateKeyFacadeTests(unittest.TestCase):
    def test_is_default_opt_out_and_advertises_bounded_configuration(self) -> None:
        enabled = LLMFirewall(pool_config=_single_worker_config())
        disabled = LLMFirewall(
            scanner_config=ScannerConfig(enable_private_keys=False),
            pool_config=_single_worker_config(),
        )
        customized = LLMFirewall(
            pool_config=_single_worker_config(),
            private_key_config=PrivateKeyConfig(
                max_candidates=8,
                max_block_chars=65_536,
            ),
        )
        try:
            self.assertIn(
                "secrets.private_key",
                tuple(rule.rule_id for rule in enabled.capabilities().rules),
            )
            self.assertNotIn(
                "secrets.private_key",
                tuple(rule.rule_id for rule in disabled.capabilities().rules),
            )
            self.assertEqual(enabled.capabilities().private_key.max_candidates, 32)
            self.assertEqual(
                customized.capabilities().private_key.max_block_chars,
                65_536,
            )
        finally:
            enabled.close()
            disabled.close()
            customized.close()

    def test_rejects_config_when_rule_is_disabled(self) -> None:
        with self.assertRaisesRegex(ValueError, "enable_private_keys"):
            LLMFirewall(
                scanner_config=ScannerConfig(enable_private_keys=False),
                private_key_config=PrivateKeyConfig(),
            )

    def test_rejects_non_config_value(self) -> None:
        with self.assertRaises(TypeError):
            LLMFirewall(private_key_config=True)  # type: ignore[arg-type]

    def test_worker_redacts_and_manager_propagates_configuration(self) -> None:
        value = _block("PRIVATE KEY")
        manager = LLMFirewallManager(
            pool_config=_single_worker_config(),
            private_key_config=PrivateKeyConfig(max_candidates=8),
        ).start()
        try:
            self.assertEqual(manager.sanitize_input(value), "[REDACTED]")
            self.assertEqual(manager.capabilities().private_key.max_candidates, 8)
        finally:
            manager.close()

    def test_strict_process_policy_blocks_without_disclosure(self) -> None:
        value = _block("PRIVATE KEY", "UNIQUE_PRIVATE_VALUE")
        firewall = LLMFirewall(
            pool_config=_single_worker_config(),
            policy=STRICT_POLICY,
        )
        with firewall, self.assertRaises(ContentBlockedError) as raised:
            firewall.sanitize_output(value)
        self.assertEqual(raised.exception.findings[0].rule_id, "secrets.private_key")
        self.assertNotIn("UNIQUE_PRIVATE_VALUE", repr(raised.exception.__dict__))


if __name__ == "__main__":
    unittest.main()
