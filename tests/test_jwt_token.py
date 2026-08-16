import base64
import json
import unittest

from llm_ffw import (
    AUDIT_POLICY,
    STRICT_POLICY,
    Action,
    ContentBlockedError,
    Firewall,
    JWTTokenConfig,
    JWTTokenRule,
    LLMFirewall,
    LLMFirewallManager,
    ProcessScannerPoolConfig,
    ScanScope,
    Scanner,
    ScannerConfig,
)


def _encode(value: object) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _encode_raw(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _token(
    header: object | None = None,
    payload: object | None = None,
    signature: str | None = "c2lnbmF0dXJl",
) -> str:
    header = {"alg": "HS256", "typ": "JWT"} if header is None else header
    payload = {"sub": "synthetic-user", "iat": 1_516_239_022} if payload is None else payload
    signature = "" if signature is None else signature
    return f"{_encode(header)}.{_encode(payload)}.{signature}"


def _scanner(config: JWTTokenConfig | None = None) -> Scanner:
    return Scanner(rules=(JWTTokenRule(config),))


def _single_worker_config() -> ProcessScannerPoolConfig:
    return ProcessScannerPoolConfig(
        max_workers=1,
        max_in_flight=1,
        max_tasks_per_child=10,
    )


class JWTTokenConfigTests(unittest.TestCase):
    def test_rejects_invalid_limits_and_scopes(self) -> None:
        for field_name, values in (
            ("max_candidates", (0, -1, True, 1_025)),
            ("max_token_chars", (0, -1, True, 8_000_001)),
            ("max_json_depth", (0, -1, True, 257)),
            ("max_json_structure_tokens", (0, -1, True, 65_537)),
        ):
            for value in values:
                with self.subTest(field_name=field_name, value=value), self.assertRaises(
                    (TypeError, ValueError)
                ):
                    JWTTokenConfig(**{field_name: value})  # type: ignore[arg-type]
        for scopes in ((), ("input",), "input"):
            with self.subTest(scopes=scopes), self.assertRaises(
                (TypeError, ValueError)
            ):
                JWTTokenConfig(scopes=scopes)  # type: ignore[arg-type]

    def test_normalizes_scopes_deterministically(self) -> None:
        config = JWTTokenConfig(
            scopes=(ScanScope.OUTPUT, ScanScope.INPUT, ScanScope.OUTPUT)
        )
        self.assertEqual(config.scopes, (ScanScope.INPUT, ScanScope.OUTPUT))


class JWTTokenRuleTests(unittest.TestCase):
    def test_detects_rfc_7515_compact_jwt_example(self) -> None:
        value = (
            "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9."
            "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQog"
            "Imh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        )
        finding = _scanner().scan(value)[0]
        self.assertEqual(finding.metadata["algorithm_family"], "hmac")
        self.assertEqual(finding.span.end, len(value))

    def test_detects_typed_and_registered_claim_tokens(self) -> None:
        cases = (
            (_token(payload={"custom": True}), "jwt_type_header"),
            (
                _token(header={"alg": "RS256"}, payload={"iss": "synthetic"}),
                "registered_claim",
            ),
        )
        for value, reason in cases:
            with self.subTest(reason=reason):
                text = f"Bearer {value}"
                finding = _scanner().scan(text)[0]
                self.assertEqual(finding.rule_id, "secrets.jwt_token")
                self.assertIs(finding.action, Action.REDACT)
                self.assertEqual(finding.severity.value, "high")
                self.assertEqual(finding.metadata["reason"], reason)
                self.assertEqual(finding.redacted_preview, "[REDACTED:jwt_token]")
                self.assertEqual(text[finding.span.start : finding.span.end], value)

    def test_classifies_algorithm_without_disclosing_header_value(self) -> None:
        cases = (
            ("HS256", "hmac"),
            ("RS256", "rsa"),
            ("PS256", "rsa_pss"),
            ("ES256", "ecdsa"),
            ("EdDSA", "eddsa"),
            ("CUSTOM_PRIVATE_ALGORITHM", "other"),
        )
        for algorithm, family in cases:
            with self.subTest(algorithm=algorithm):
                value = _token(header={"alg": algorithm, "typ": "JWT"})
                finding = _scanner().scan(value)[0]
                self.assertEqual(finding.metadata["algorithm_family"], family)
                self.assertNotIn(algorithm, repr(dict(finding.metadata)))

    def test_detects_unsecured_jwt_only_with_empty_signature(self) -> None:
        unsecured = _token(
            header={"alg": "none", "typ": "JWT"}, signature=None
        )
        finding = _scanner().scan(unsecured)[0]
        self.assertEqual(finding.metadata["algorithm_family"], "none")
        self.assertEqual(
            _scanner().scan(unsecured + "unexpected-signature"),
            (),
        )

    def test_rejects_lookalikes_and_non_jwt_compact_values(self) -> None:
        duplicate_header = _encode_raw(b'{"alg":"HS256","alg":"RS256"}')
        duplicate_payload = _encode_raw(b'{"sub":"a","sub":"b"}')
        valid_header = _encode({"alg": "HS256", "typ": "JWT"})
        valid_payload = _encode({"sub": "synthetic"})
        safe = (
            "ordinary prose",
            "a.b.c",
            "one.two.three.four",
            "one.two.three.four.five",
            f"{_encode({'typ': 'JWT'})}.{valid_payload}.c2ln",
            f"{valid_header}.{_encode(['sub', 'synthetic'])}.c2ln",
            f"{_encode({'alg': 'HS256'})}.{_encode({'custom': True})}.c2ln",
            f"{valid_header}.{valid_payload}.",
            f"{_encode({'alg': 'none', 'typ': 'JWT'})}.{valid_payload}.c2ln",
            f"{duplicate_header}.{valid_payload}.c2ln",
            f"{valid_header}.{duplicate_payload}.c2ln",
            f"{valid_header}=.{valid_payload}.c2ln",
            f"{valid_header}.{valid_payload}.c2ln=",
            f"{valid_header}.{valid_payload}.AB",
        )
        for value in safe:
            with self.subTest(value=value[:60]):
                self.assertEqual(_scanner().scan(value), ())

    def test_redacts_complete_token_in_both_scopes(self) -> None:
        value = _token()
        text = f"before {value} after"
        for scope in (ScanScope.INPUT, ScanScope.OUTPUT):
            with self.subTest(scope=scope):
                result = Firewall(scanner=_scanner()).process(text, scope=scope)
                self.assertEqual(result.processed_text, "before [REDACTED] after")

    def test_candidate_and_size_limits_contain_uninspected_remainder(self) -> None:
        plausible_invalid = "eaaaaaaaaaaaaaa.e30.c2ln"
        valid = _token()
        text = plausible_invalid + " then " + valid + " tail"
        findings = _scanner(JWTTokenConfig(max_candidates=1)).scan(text)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].metadata["reason"], "candidate_limit_exceeded")
        self.assertEqual(findings[0].span.start, text.index(valid))
        self.assertEqual(findings[0].span.end, len(text))

        oversized = valid + " tail"
        size_finding = _scanner(JWTTokenConfig(max_token_chars=32)).scan(
            oversized
        )[0]
        self.assertEqual(size_finding.metadata["reason"], "token_size_exceeded")
        self.assertEqual(size_finding.span.end, len(oversized))
        self.assertEqual(
            Firewall(
                scanner=_scanner(JWTTokenConfig(max_token_chars=32))
            ).process(oversized).processed_text,
            "[REDACTED]",
        )

    def test_json_structure_limits_contain_uninspected_remainder(self) -> None:
        header = _encode({"alg": "HS256", "typ": "JWT"})
        deeply_nested_payload = _encode_raw(
            b'{"x":' + (b"[" * 2_000) + b"0" + (b"]" * 2_000) + b"}"
        )
        text = f"{header}.{deeply_nested_payload}.c2ln trailing"
        finding = _scanner().scan(text)[0]
        self.assertIs(finding.action, Action.BLOCK)
        self.assertEqual(finding.metadata["reason"], "json_limit_exceeded")
        self.assertEqual(finding.span.end, len(text))
        self.assertEqual(Firewall(scanner=_scanner()).process(text).processed_text, "[REDACTED]")

    def test_finding_does_not_disclose_token_header_or_claims(self) -> None:
        value = _token(
            header={"alg": "PRIVATE_ALGORITHM_NAME", "typ": "JWT"},
            payload={"sub": "UNIQUE_PRIVATE_SUBJECT"},
        )
        finding = _scanner().scan(value)[0]
        exposed = finding.message + finding.redacted_preview + repr(dict(finding.metadata))
        self.assertNotIn(value, exposed)
        self.assertNotIn("PRIVATE_ALGORITHM_NAME", exposed)
        self.assertNotIn("UNIQUE_PRIVATE_SUBJECT", exposed)

    def test_scopes_can_be_restricted(self) -> None:
        value = _token()
        output_only = _scanner(JWTTokenConfig(scopes=(ScanScope.OUTPUT,)))
        self.assertEqual(output_only.scan(value, scope=ScanScope.INPUT), ())
        self.assertEqual(len(output_only.scan(value, scope=ScanScope.OUTPUT)), 1)

    def test_original_span_is_preserved_after_crlf_normalization(self) -> None:
        value = _token()
        text = "before\r\n" + value + "\r\nafter"
        finding = _scanner().scan(text)[0]
        self.assertEqual(text[finding.span.start : finding.span.end], value)

    def test_long_clean_and_dot_dense_inputs_are_bounded(self) -> None:
        self.assertEqual(_scanner().scan("a" * 8_000_000), ())
        dot_dense = ("a.b.c " * 1_400_000)[:8_000_000]
        self.assertEqual(_scanner().scan(dot_dense), ())
        suffix = ".e30.c2ln"
        oversized = ("e" * (8_000_000 - len(suffix))) + suffix
        finding = _scanner().scan(oversized)[0]
        self.assertEqual(finding.metadata["reason"], "token_size_exceeded")
        self.assertEqual(finding.span.start, 0)
        self.assertEqual(finding.span.end, len(oversized))

    def test_builtin_policies_redact_block_and_review(self) -> None:
        value = _token()
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


class JWTTokenFacadeTests(unittest.TestCase):
    def test_is_default_opt_out_and_advertises_bounded_configuration(self) -> None:
        enabled = LLMFirewall(pool_config=_single_worker_config())
        disabled = LLMFirewall(
            scanner_config=ScannerConfig(enable_jwt_tokens=False),
            pool_config=_single_worker_config(),
        )
        customized = LLMFirewall(
            pool_config=_single_worker_config(),
            jwt_token_config=JWTTokenConfig(
                max_candidates=16,
                max_token_chars=65_536,
                max_json_depth=32,
                max_json_structure_tokens=2_048,
            ),
        )
        try:
            self.assertIn(
                "secrets.jwt_token",
                tuple(rule.rule_id for rule in enabled.capabilities().rules),
            )
            self.assertNotIn(
                "secrets.jwt_token",
                tuple(rule.rule_id for rule in disabled.capabilities().rules),
            )
            self.assertEqual(enabled.capabilities().jwt_token.max_candidates, 128)
            self.assertEqual(
                customized.capabilities().jwt_token.max_token_chars,
                65_536,
            )
            self.assertEqual(customized.capabilities().jwt_token.max_json_depth, 32)
        finally:
            enabled.close()
            disabled.close()
            customized.close()

    def test_rejects_invalid_or_disabled_configuration(self) -> None:
        with self.assertRaises(TypeError):
            LLMFirewall(jwt_token_config=True)  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "enable_jwt_tokens"):
            LLMFirewall(
                scanner_config=ScannerConfig(enable_jwt_tokens=False),
                jwt_token_config=JWTTokenConfig(),
            )

    def test_worker_redacts_and_manager_propagates_configuration(self) -> None:
        value = _token()
        manager = LLMFirewallManager(
            pool_config=_single_worker_config(),
            jwt_token_config=JWTTokenConfig(max_candidates=16),
        ).start()
        try:
            self.assertEqual(manager.sanitize_output(value), "[REDACTED]")
            self.assertEqual(manager.capabilities().jwt_token.max_candidates, 16)
        finally:
            manager.close()

    def test_strict_process_policy_blocks_without_disclosure(self) -> None:
        value = _token(payload={"sub": "UNIQUE_PRIVATE_SUBJECT"})
        firewall = LLMFirewall(
            pool_config=_single_worker_config(),
            policy=STRICT_POLICY,
        )
        with firewall, self.assertRaises(ContentBlockedError) as raised:
            firewall.sanitize_input(value)
        self.assertEqual(raised.exception.findings[0].rule_id, "secrets.jwt_token")
        self.assertNotIn("UNIQUE_PRIVATE_SUBJECT", repr(raised.exception.__dict__))


if __name__ == "__main__":
    unittest.main()
