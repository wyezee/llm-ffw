import asyncio
import time
import unittest

from llm_ffw import (
    AUDIT_POLICY,
    STRICT_POLICY,
    Action,
    AsyncLLMFirewall,
    AuthorizationHeaderConfig,
    AuthorizationHeaderCapability,
    AuthorizationHeaderRule,
    ContentBlockedError,
    Firewall,
    LLMFirewall,
    LLMFirewallManager,
    ProcessScannerPoolConfig,
    ScanScope,
    Scanner,
)


_BEARER = "synthetic_bearer_token_123456"
_BASIC = "dXNlcjpwYXNzd29yZA=="  # synthetic "user:password"


def _scanner(config: AuthorizationHeaderConfig | None = None) -> Scanner:
    return Scanner(rules=(AuthorizationHeaderRule(config),))


def _single_worker_config() -> ProcessScannerPoolConfig:
    return ProcessScannerPoolConfig(
        max_workers=1,
        max_in_flight=1,
        max_tasks_per_child=10,
    )


class AuthorizationHeaderConfigTests(unittest.TestCase):
    def test_rejects_invalid_limits_and_scopes(self) -> None:
        for field_name, values in (
            ("max_candidates", (0, -1, True, 1_025)),
            ("max_credential_chars", (0, -1, True, 65_537)),
        ):
            for value in values:
                with self.subTest(field_name=field_name, value=value), self.assertRaises(
                    (TypeError, ValueError)
                ):
                    AuthorizationHeaderConfig(**{field_name: value})
        for scopes in ((), (ScanScope.TOOL_CALL,), ("input",), "input"):
            with self.subTest(scopes=scopes), self.assertRaises(
                (TypeError, ValueError)
            ):
                AuthorizationHeaderConfig(scopes=scopes)  # type: ignore[arg-type]

    def test_normalizes_text_scopes_deterministically(self) -> None:
        config = AuthorizationHeaderConfig(
            scopes=(ScanScope.OUTPUT, ScanScope.INPUT, ScanScope.OUTPUT)
        )
        self.assertEqual(config.scopes, (ScanScope.INPUT, ScanScope.OUTPUT))

    def test_capability_is_bounded_typed_and_immutable(self) -> None:
        schemes = ["basic", "bearer"]
        capability = AuthorizationHeaderCapability(128, 8_192, schemes)
        schemes.append("digest")
        self.assertEqual(capability.schemes, ("basic", "bearer"))
        for values in ((0, 8_192), (128, 0), (True, 8_192)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                AuthorizationHeaderCapability(*values)
        with self.assertRaises(ValueError):
            AuthorizationHeaderCapability(128, 8_192, ("bearer",))


class AuthorizationHeaderRuleTests(unittest.TestCase):
    def test_is_opt_in_and_scans_input_and_output_by_default(self) -> None:
        text = f"Authorization: Bearer {_BEARER}"
        self.assertEqual(Scanner().scan(text), ())
        self.assertEqual(len(_scanner().scan(text, scope=ScanScope.INPUT)), 1)
        self.assertEqual(len(_scanner().scan(text, scope=ScanScope.OUTPUT)), 1)

    def test_detects_basic_and_bearer_with_exact_credential_spans(self) -> None:
        cases = (
            (f"Authorization: Bearer {_BEARER}", _BEARER, "bearer"),
            (f"authorization:\tBASIC\t{_BASIC}\t", _BASIC, "basic"),
            (f"AUTHORIZATION: bearer {_BEARER}\r\nNext: value", _BEARER, "bearer"),
            (f"Authorization: Bearer {_BEARER}\rNext: value", _BEARER, "bearer"),
        )
        scanner = _scanner()
        for text, credential, scheme in cases:
            with self.subTest(scheme=scheme, text=text[:20]):
                finding = scanner.scan(text)[0]
                self.assertEqual(
                    text[finding.span.start : finding.span.end], credential
                )
                self.assertEqual(finding.metadata["scheme"], scheme)
                self.assertEqual(
                    finding.redacted_preview,
                    "[REDACTED:authorization_credential]",
                )

    def test_rejects_nonheaders_unsupported_schemes_and_malformed_values(self) -> None:
        cases = (
            f"prefix Authorization: Bearer {_BEARER}",
            f" Proxy-Authorization: Bearer {_BEARER}",
            f"Proxy-Authorization: Bearer {_BEARER}",
            f"Authorization : Bearer {_BEARER}",
            "Authorization: Digest abcdef",
            "Authorization: Bearer <token>",
            "Authorization: Bearer your token",
            "Authorization: Bearer abc=def",
            "Authorization: Bearer",
            "Authorization: Basic not-base64",
            "Authorization: Basic dXNlcg==",
            "Authorization: Basic Og=",
            "Authorization: Basic Oh==",
            f"authorization： bearer {_BEARER}",
        )
        scanner = _scanner()
        for text in cases:
            with self.subTest(text=text[:40]):
                self.assertEqual(scanner.scan(text), ())

    def test_multiple_headers_are_ordered_and_redacted_without_disclosure(self) -> None:
        text = (
            f"Authorization: Bearer {_BEARER}\n"
            f"Authorization: Basic {_BASIC}"
        )
        findings = _scanner().scan(text)
        self.assertEqual(len(findings), 2)
        self.assertLess(findings[0].span.start, findings[1].span.start)
        for credential, finding in zip((_BEARER, _BASIC), findings):
            self.assertNotIn(credential, finding.message)
            self.assertNotIn(credential, repr(finding))
        result = Firewall(scanner=_scanner()).process(text)
        self.assertEqual(
            result.processed_text,
            "Authorization: Bearer [REDACTED]\n"
            "Authorization: Basic [REDACTED]",
        )

    def test_candidate_and_credential_limits_fail_closed(self) -> None:
        header = f"Authorization: Bearer {_BEARER}"
        findings = _scanner(
            AuthorizationHeaderConfig(max_candidates=1)
        ).scan(f"{header}\n{header}\ntrailing")
        self.assertEqual(len(findings), 2)
        self.assertIs(findings[-1].action, Action.BLOCK)
        self.assertEqual(
            findings[-1].metadata["reason"], "candidate_limit_exceeded"
        )

        oversized = _scanner(
            AuthorizationHeaderConfig(max_credential_chars=8)
        ).scan(header)
        self.assertEqual(len(oversized), 1)
        self.assertIs(oversized[0].action, Action.BLOCK)
        self.assertEqual(
            oversized[0].metadata["reason"], "credential_limit_exceeded"
        )

    def test_builtin_policies_redact_block_and_review(self) -> None:
        text = f"Authorization: Bearer {_BEARER}"
        self.assertEqual(Firewall(scanner=_scanner()).process(text).decision, Action.REDACT)
        audit = Firewall(scanner=_scanner(), policy=AUDIT_POLICY).process(text)
        self.assertEqual(audit.decision, Action.REVIEW)
        self.assertEqual(audit.processed_text, text)
        self.assertEqual(
            Firewall(scanner=_scanner(), policy=STRICT_POLICY).process(text).decision,
            Action.BLOCK,
        )

    def test_eight_million_character_adversarial_paths_are_bounded(self) -> None:
        scanner = _scanner()
        workloads = (
            "a" * 8_000_000,
            "\n" * 8_000_000,
            "Authorization: Bearer " + "A" * 7_999_978,
            ("Authorization: Bearer <token>\n" * 300_000)[:8_000_000],
        )
        started = time.perf_counter()
        self.assertEqual(scanner.scan(workloads[0]), ())
        self.assertEqual(scanner.scan(workloads[1]), ())
        self.assertEqual(
            scanner.scan(workloads[2])[0].metadata["reason"],
            "credential_limit_exceeded",
        )
        self.assertEqual(
            scanner.scan(workloads[3])[-1].metadata["reason"],
            "candidate_limit_exceeded",
        )
        self.assertLess(time.perf_counter() - started, 4.0)


class AuthorizationHeaderFacadeTests(unittest.TestCase):
    def test_facade_propagates_configuration_and_capabilities(self) -> None:
        config = AuthorizationHeaderConfig(
            max_candidates=7,
            max_credential_chars=512,
        )
        firewall = LLMFirewall(
            pool_config=_single_worker_config(),
            authorization_header_config=config,
        )
        capability = firewall.capabilities().authorization_header
        self.assertIsNotNone(capability)
        self.assertEqual(capability.max_candidates, 7)
        self.assertEqual(capability.max_credential_chars, 512)
        self.assertEqual(capability.schemes, ("basic", "bearer"))
        with firewall:
            self.assertEqual(
                firewall.sanitize_output(
                    f"Authorization: Bearer {_BEARER}"
                ),
                "Authorization: Bearer [REDACTED]",
            )

    def test_manager_and_async_facade_preserve_configuration(self) -> None:
        manager = LLMFirewallManager(
            pool_config=_single_worker_config(),
            authorization_header_config=AuthorizationHeaderConfig(),
        )
        self.assertIsNotNone(manager.capabilities().authorization_header)
        with manager:
            self.assertEqual(
                manager.sanitize_input(f"Authorization: Basic {_BASIC}"),
                "Authorization: Basic [REDACTED]",
            )

        asynchronous = AsyncLLMFirewall(
            pool_config=_single_worker_config(),
            authorization_header_config=AuthorizationHeaderConfig(),
        )

        async def exercise() -> None:
            async with asynchronous:
                self.assertEqual(
                    await asynchronous.sanitize_input(
                        f"Authorization: Bearer {_BEARER}"
                    ),
                    "Authorization: Bearer [REDACTED]",
                )

        asyncio.run(exercise())

    def test_rejects_non_config_value(self) -> None:
        with self.assertRaises(TypeError):
            LLMFirewall(authorization_header_config=object())


if __name__ == "__main__":
    unittest.main()
