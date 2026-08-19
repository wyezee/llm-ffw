import asyncio
import time
import unittest
from unittest.mock import patch

from llm_ffw import (
    AUDIT_POLICY,
    STRICT_POLICY,
    Action,
    AsyncFirewall,
    ConnectionStringCapability,
    ConnectionStringConfig,
    ConnectionStringRule,
    Firewall,
    FirewallConfig,
    FirewallManager,
    ProcessScannerPoolConfig,
    RuleEngine,
    RuleScanner,
    ScanScope,
)


_PASSWORD = "synthetic-db-password-123"
_SCHEMES = (
    "amqp",
    "amqps",
    "mongodb",
    "mongodb+srv",
    "postgres",
    "postgresql",
    "redis",
    "rediss",
    "sqlserver",
)


def _scanner(config: ConnectionStringConfig | None = None) -> RuleScanner:
    return RuleScanner(rules=(ConnectionStringRule(config),))


def _single_worker_config() -> ProcessScannerPoolConfig:
    return ProcessScannerPoolConfig(
        max_workers=1,
        max_in_flight=1,
        max_tasks_per_child=10,
    )


class ConnectionStringConfigTests(unittest.TestCase):
    def test_rejects_invalid_limits_and_scopes(self) -> None:
        for field_name, values in (
            ("max_candidates", (0, -1, True, 1_025)),
            ("max_credential_chars", (0, -1, True, 65_537)),
            ("max_connection_chars", (0, -1, True, 262_145)),
        ):
            for value in values:
                with self.subTest(field_name=field_name, value=value), self.assertRaises(
                    (TypeError, ValueError)
                ):
                    ConnectionStringConfig(**{field_name: value})
        with self.assertRaises(ValueError):
            ConnectionStringConfig(
                max_credential_chars=100,
                max_connection_chars=99,
            )
        for scopes in ((), (ScanScope.TOOL_CALL,), ("input",), "input"):
            with self.subTest(scopes=scopes), self.assertRaises(
                (TypeError, ValueError)
            ):
                ConnectionStringConfig(scopes=scopes)  # type: ignore[arg-type]

    def test_normalizes_scopes_and_capability(self) -> None:
        config = ConnectionStringConfig(
            scopes=(ScanScope.OUTPUT, ScanScope.INPUT, ScanScope.OUTPUT)
        )
        self.assertEqual(config.scopes, (ScanScope.INPUT, ScanScope.OUTPUT))
        capability = ConnectionStringCapability(128, 8_192, 65_536, _SCHEMES)
        self.assertEqual(capability.schemes, _SCHEMES)
        with self.assertRaises(ValueError):
            ConnectionStringCapability(128, 8_192, 65_536, tuple(reversed(_SCHEMES)))


class ConnectionStringRuleTests(unittest.TestCase):
    def test_clean_text_skips_candidate_parsers_without_markers(self) -> None:
        with (
            patch(
                "llm_ffw.rules.connection_string._uri_candidates"
            ) as uri_candidates,
            patch(
                "llm_ffw.rules.connection_string._keyword_candidates"
            ) as keyword_candidates,
        ):
            self.assertEqual(_scanner().scan("plain text with password=value"), ())
        uri_candidates.assert_not_called()
        keyword_candidates.assert_not_called()

    def test_is_opt_in_and_supports_both_text_scopes(self) -> None:
        text = f"postgres://user:{_PASSWORD}@db.example/prod"
        self.assertEqual(RuleScanner().scan(text), ())
        self.assertEqual(len(_scanner().scan(text, scope=ScanScope.INPUT)), 1)
        self.assertEqual(len(_scanner().scan(text, scope=ScanScope.OUTPUT)), 1)

    def test_detects_source_backed_uri_schemes_with_exact_spans(self) -> None:
        scanner = _scanner()
        for scheme in _SCHEMES:
            text = f"{scheme}://user:{_PASSWORD}@db.example/prod"
            with self.subTest(scheme=scheme):
                finding = scanner.scan(text)[0]
                self.assertEqual(
                    text[finding.span.start : finding.span.end],
                    _PASSWORD,
                )
                self.assertEqual(finding.metadata["scheme"], scheme)
                self.assertEqual(
                    finding.metadata["credential_form"],
                    "uri_userinfo",
                )

    def test_detects_encoded_and_redis_password_only_uri_values(self) -> None:
        cases = (
            (
                "sqlserver://sa:p%40ss%3Aword@db.example:1433?database=prod",
                "p%40ss%3Aword",
            ),
            ("redis://:authpass@10.0.0.5:6379/0", "authpass"),
            (
                "mongodb://user:p%23ss%3Fword@db1.example,db2.example/prod",
                "p%23ss%3Fword",
            ),
        )
        scanner = _scanner()
        for text, credential in cases:
            with self.subTest(text=text[:20]):
                finding = scanner.scan(text)[0]
                self.assertEqual(
                    text[finding.span.start : finding.span.end],
                    credential,
                )

    def test_detects_ado_and_odbc_values_with_exact_spans(self) -> None:
        cases = (
            (
                f"Server=db;Database=prod;User Id=sa;Password={_PASSWORD};",
                _PASSWORD,
            ),
            (
                'Data Source=db;Password="p;ass";Initial Catalog=prod',
                "p;ass",
            ),
            (
                "odbc:server=db;pwd={p;ass}}word};database=prod",
                "p;ass}}word",
            ),
            (
                f"Password={_PASSWORD};Server=db;Database=prod",
                _PASSWORD,
            ),
        )
        scanner = _scanner()
        for text, credential in cases:
            with self.subTest(text=text[:25]):
                finding = scanner.scan(text)[0]
                self.assertEqual(
                    text[finding.span.start : finding.span.end],
                    credential,
                )
                self.assertEqual(finding.metadata["scheme"], "keyword")
                self.assertEqual(
                    finding.metadata["credential_form"],
                    "keyword_pair",
                )

    def test_rejects_non_credentials_and_placeholders(self) -> None:
        cases = (
            "postgres://db.example/prod",
            "postgres://user@db.example/prod",
            "https://user:password@example.test/",
            f"mysql://user:{_PASSWORD}@db.example/prod",
            f"prefixpostgres://user:{_PASSWORD}@db.example/prod",
            f"jdbc:postgresql://user:{_PASSWORD}@db.example/prod",
            "Password=ordinary prose",
            "Initial Catalog=prod;Password=value",
            "Server=db, Password=value",
            "Server=db;Password=",
            "Server=db;Password=<password>;Database=prod",
            "Server=db;Password=${PASSWORD};Database=prod",
            "postgres://user:%3Cpassword%3E@db.example/prod",
            "Server=db;PasswordHash=value;Database=prod",
            'Server="text;Password=fake";Data Source=db',
        )
        scanner = _scanner()
        for text in cases:
            with self.subTest(text=text[:35]):
                self.assertEqual(scanner.scan(text), ())

    def test_keyword_markers_inside_recognized_values_are_not_reparsed(self) -> None:
        text = 'Server=db;Password="p;Server=fake";Database=prod'
        findings = _scanner().scan(text)

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            text[findings[0].span.start : findings[0].span.end],
            "p;Server=fake",
        )

    def test_malformed_values_are_redacted_without_disclosure(self) -> None:
        cases = (
            "postgres://user:p%ZZword@db.example/prod",
            'Server=db;Password="unterminated',
            "Server=db;Password={unterminated",
        )
        scanner = _scanner()
        for text in cases:
            with self.subTest(text=text[:25]):
                finding = scanner.scan(text)[0]
                credential = text[finding.span.start : finding.span.end]
                self.assertEqual(
                    finding.metadata["reason"],
                    "malformed_connection_string_credential",
                )
                self.assertIs(finding.action, Action.REDACT)
                self.assertNotIn(credential, finding.message)
                self.assertNotIn(credential, repr(finding))

    def test_candidate_and_credential_limits_fail_closed(self) -> None:
        first = f"postgres://user:{_PASSWORD}@db.example/prod"
        second = f"redis://:{_PASSWORD}@db.example/0"
        findings = _scanner(ConnectionStringConfig(max_candidates=1)).scan(
            first + "\n" + second
        )
        self.assertEqual(len(findings), 2)
        self.assertEqual(
            findings[-1].metadata["reason"],
            "candidate_limit_exceeded",
        )
        self.assertIs(findings[-1].action, Action.BLOCK)

        oversized = _scanner(
            ConnectionStringConfig(
                max_credential_chars=8,
                max_connection_chars=64,
            )
        ).scan(first)[0]
        self.assertEqual(
            oversized.metadata["reason"],
            "credential_limit_exceeded",
        )
        self.assertIs(oversized.action, Action.BLOCK)

        keyword_text = "Server=db;Password=" + "Z" * 64 + ";Database=prod"
        keyword_scanner = _scanner(
            ConnectionStringConfig(
                max_credential_chars=8,
                max_connection_chars=128,
            )
        )
        keyword_finding = keyword_scanner.scan(keyword_text)[0]
        self.assertEqual(
            keyword_finding.metadata["reason"],
            "credential_limit_exceeded",
        )
        sanitized = RuleEngine(scanner=keyword_scanner).process(keyword_text)
        self.assertEqual(sanitized.processed_text, "Server=db;Password=[REDACTED]")
        self.assertNotIn("Z", sanitized.processed_text)

    def test_policies_redact_block_and_review(self) -> None:
        text = f"postgres://user:{_PASSWORD}@db.example/prod"
        scanner = _scanner()
        balanced = RuleEngine(scanner=scanner).process(text)
        self.assertIs(balanced.decision, Action.REDACT)
        self.assertEqual(
            balanced.processed_text,
            "postgres://user:[REDACTED]@db.example/prod",
        )
        self.assertIs(
            RuleEngine(scanner=scanner, policy=STRICT_POLICY).process(text).decision,
            Action.BLOCK,
        )
        audited = RuleEngine(scanner=scanner, policy=AUDIT_POLICY).process(text)
        self.assertIs(audited.decision, Action.REVIEW)
        self.assertEqual(audited.processed_text, text)

    def test_eight_million_character_paths_are_bounded(self) -> None:
        scanner = _scanner()
        oversized_prefix = "postgres://user:"
        oversized_suffix = "@db"
        oversized = (
            oversized_prefix
            + "A"
            * (8_000_000 - len(oversized_prefix) - len(oversized_suffix))
            + oversized_suffix
        )
        workloads = (
            "a" * 8_000_000,
            ("Password=value;" * 500_000)[:8_000_000],
            oversized,
            (
                "postgres://user:%3Cpassword%3E@db.example/x\n" * 180_000
            )[:8_000_000],
        )
        started = time.perf_counter()
        self.assertEqual(scanner.scan(workloads[0]), ())
        self.assertEqual(scanner.scan(workloads[1]), ())
        self.assertEqual(
            scanner.scan(workloads[2])[0].metadata["reason"],
            "credential_limit_exceeded",
        )
        self.assertEqual(scanner.scan(workloads[3]), ())
        self.assertLess(time.perf_counter() - started, len(workloads) * 1.0)


class ConnectionStringFacadeTests(unittest.TestCase):
    def test_facades_propagate_configuration_and_capability(self) -> None:
        config = ConnectionStringConfig(
            max_candidates=7,
            max_credential_chars=512,
            max_connection_chars=1_024,
        )
        firewall = Firewall(
            pool_config=_single_worker_config(),
            connection_string_config=config,
        )
        capability = firewall.capabilities().connection_string
        self.assertIsNotNone(capability)
        self.assertEqual(capability.max_candidates, 7)
        self.assertEqual(capability.schemes, _SCHEMES)
        with firewall:
            self.assertEqual(
                firewall.sanitize_output(
                    f"Server=db;Password={_PASSWORD};Database=prod"
                ),
                "Server=db;Password=[REDACTED];Database=prod",
            )

        manager = FirewallManager(
            pool_config=_single_worker_config(),
            connection_string_config=config,
        )
        with manager:
            self.assertEqual(
                manager.sanitize_input(
                    f"postgres://user:{_PASSWORD}@db.example/prod"
                ),
                "postgres://user:[REDACTED]@db.example/prod",
            )

        asynchronous = AsyncFirewall(
            pool_config=_single_worker_config(),
            connection_string_config=config,
        )

        async def exercise() -> None:
            async with asynchronous:
                self.assertEqual(
                    await asynchronous.sanitize_input(
                        f"redis://:{_PASSWORD}@db.example/0"
                    ),
                    "redis://:[REDACTED]@db.example/0",
                )

        asyncio.run(exercise())

    def test_firewall_config_enables_rule_and_rejects_wrong_type(self) -> None:
        config = FirewallConfig(connection_string_config=ConnectionStringConfig())
        self.assertIsNotNone(
            Firewall.from_config(config).capabilities().connection_string
        )
        with self.assertRaises(TypeError):
            Firewall(connection_string_config=object())


if __name__ == "__main__":
    unittest.main()
