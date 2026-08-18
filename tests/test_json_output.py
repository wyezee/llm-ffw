import unittest

from llm_ffw import (
    AUDIT_POLICY,
    Action,
    BannedSubstring,
    BannedSubstringCatalog,
    BannedSubstringsRule,
    ContentBlockedError,
    RuleEngine,
    JSONOutputConfig,
    JSONOutputRule,
    Firewall,
    FirewallPolicy,
    PolicyOverride,
    ProcessScannerPoolConfig,
    ScanScope,
    RuleScanner,
)


def _scanner(config: JSONOutputConfig | None = None) -> RuleScanner:
    return RuleScanner(rules=(JSONOutputRule(config),))


def _single_worker_config() -> ProcessScannerPoolConfig:
    return ProcessScannerPoolConfig(
        max_workers=1,
        max_in_flight=1,
        max_tasks_per_child=10,
    )


class JSONOutputConfigTests(unittest.TestCase):
    def test_rejects_invalid_limits_and_flags(self) -> None:
        for field_name in (
            "max_document_chars",
            "max_depth",
            "max_structure_tokens",
            "max_number_chars",
        ):
            with self.subTest(field_name=field_name), self.assertRaises(
                (TypeError, ValueError)
            ):
                JSONOutputConfig(**{field_name: 0})
            with self.subTest(field_name=field_name), self.assertRaises(
                TypeError
            ):
                JSONOutputConfig(**{field_name: True})
        with self.assertRaises(TypeError):
            JSONOutputConfig(reject_duplicate_keys=1)  # type: ignore[arg-type]


class JSONOutputRuleTests(unittest.TestCase):
    def test_accepts_complete_standard_json_values(self) -> None:
        values = (
            '{"ok":true,"items":[1,2.5,null,"escaped \\"value\\""]}',
            " [1, 2, 3] \n",
            '"scalar"',
            "1234567890123456789012345678901234567890",
            "1e999999999999999999999999999999999999",
            "true",
            "null",
        )
        scanner = _scanner()
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(
                    scanner.scan(value, scope=ScanScope.OUTPUT),
                    (),
                )

    def test_applies_only_to_output(self) -> None:
        self.assertEqual(_scanner().scan("not json", scope=ScanScope.INPUT), ())

    def test_rejects_empty_trailing_and_incomplete_documents(self) -> None:
        cases = ("", "   ", "{} trailing", '{"open":', "[1,]")
        scanner = _scanner()
        for text in cases:
            with self.subTest(text=text):
                findings = scanner.scan(text, scope=ScanScope.OUTPUT)
                self.assertEqual(len(findings), 1)
                finding = findings[0]
                self.assertEqual(finding.rule_id, "output.json.validity")
                self.assertIs(finding.action, Action.BLOCK)
                self.assertEqual(finding.metadata["reason"], "invalid_syntax")
                self.assertLessEqual(finding.span.end, len(text))

    def test_rejects_nonstandard_non_finite_constants(self) -> None:
        scanner = _scanner()
        for text in ("NaN", "Infinity", "-Infinity", '[1,NaN]'):
            with self.subTest(text=text):
                finding = scanner.scan(text, scope=ScanScope.OUTPUT)[0]
                self.assertEqual(
                    finding.metadata["reason"],
                    "non_finite_number",
                )

    def test_rejects_oversized_number_tokens_without_integer_conversion(self) -> None:
        config = JSONOutputConfig(max_number_chars=8)
        finding = _scanner(config).scan(
            "123456789",
            scope=ScanScope.OUTPUT,
        )[0]
        self.assertEqual(finding.metadata["reason"], "number_too_long")

    def test_rejects_unpaired_unicode_surrogates(self) -> None:
        scanner = _scanner()
        invalid = ('"\\ud800"', '"\\udfff"', '"\ud800"')
        for text in invalid:
            with self.subTest(text=ascii(text)):
                finding = scanner.scan(text, scope=ScanScope.OUTPUT)[0]
                self.assertEqual(
                    finding.metadata["reason"],
                    "unpaired_unicode_surrogate",
                )
        self.assertEqual(
            scanner.scan('"\\ud83d\\ude00"', scope=ScanScope.OUTPUT),
            (),
        )
        self.assertEqual(
            scanner.scan('"\\\\ud800"', scope=ScanScope.OUTPUT),
            (),
        )

    def test_duplicate_object_keys_are_rejected_without_disclosure(self) -> None:
        text = '{"private-name":1,"private-name":2}'
        finding = _scanner().scan(text, scope=ScanScope.OUTPUT)[0]

        self.assertEqual(finding.metadata["reason"], "duplicate_object_key")
        self.assertNotIn("private-name", finding.message)
        self.assertNotIn("private-name", repr(dict(finding.metadata)))

    def test_duplicate_key_policy_can_be_disabled_explicitly(self) -> None:
        config = JSONOutputConfig(reject_duplicate_keys=False)
        findings = _scanner(config).scan(
            '{"same":1,"same":2}',
            scope=ScanScope.OUTPUT,
        )
        self.assertEqual(findings, ())

    def test_depth_limit_is_boundary_checked_outside_strings(self) -> None:
        config = JSONOutputConfig(max_depth=2)
        scanner = _scanner(config)

        self.assertEqual(scanner.scan("[[]]", scope=ScanScope.OUTPUT), ())
        finding = scanner.scan("[[[]]]", scope=ScanScope.OUTPUT)[0]
        self.assertEqual(finding.metadata["reason"], "max_depth_exceeded")
        self.assertEqual(finding.metadata["limit"], "2")
        self.assertEqual((finding.span.start, finding.span.end), (2, 3))
        self.assertEqual(
            scanner.scan(
                '{"text":"[[[[[[[[[["}',
                scope=ScanScope.OUTPUT,
            ),
            (),
        )

    def test_structure_limit_ignores_punctuation_inside_strings(self) -> None:
        config = JSONOutputConfig(max_structure_tokens=2)
        scanner = _scanner(config)

        self.assertEqual(
            scanner.scan('{"text":"{[,:,:]}"}', scope=ScanScope.OUTPUT),
            (),
        )
        finding = scanner.scan(
            '{"a":1,"b":2}',
            scope=ScanScope.OUTPUT,
        )[0]
        self.assertEqual(
            finding.metadata["reason"],
            "max_structure_tokens_exceeded",
        )

    def test_document_size_limit_fails_before_decoding(self) -> None:
        config = JSONOutputConfig(max_document_chars=4)
        finding = _scanner(config).scan('"1234"', scope=ScanScope.OUTPUT)[0]

        self.assertEqual(finding.metadata["reason"], "document_too_large")
        self.assertEqual(finding.metadata["limit"], "4")

    def test_eight_million_character_string_is_bounded_and_valid(self) -> None:
        text = '"' + ("a" * 7_999_998) + '"'
        self.assertEqual(_scanner().scan(text, scope=ScanScope.OUTPUT), ())

    def test_default_policy_blocks_and_audit_policy_reports(self) -> None:
        scanner = _scanner()
        blocked = RuleEngine(scanner=scanner).process(
            "not-json",
            scope=ScanScope.OUTPUT,
        )
        audited = RuleEngine(scanner=scanner, policy=AUDIT_POLICY).process(
            "not-json",
            scope=ScanScope.OUTPUT,
        )

        self.assertTrue(blocked.blocked)
        self.assertIsNone(blocked.processed_text)
        self.assertIs(audited.decision, Action.REVIEW)
        self.assertEqual(audited.processed_text, "not-json")

    def test_rejects_transforming_json_policy_overrides(self) -> None:
        for action in (Action.ALLOW, Action.REMOVE, Action.REDACT):
            policy = FirewallPolicy(
                "test.invalid_json_action",
                "1",
                (
                    PolicyOverride(
                        "output.json.validity",
                        ScanScope.OUTPUT,
                        action,
                    ),
                ),
            )
            with self.subTest(action=action), self.assertRaisesRegex(
                ValueError,
                "BLOCK or REVIEW",
            ):
                RuleEngine(scanner=_scanner(), policy=policy)

    def test_post_policy_validation_blocks_structure_breaking_redaction(self) -> None:
        catalog = BannedSubstringCatalog(
            "test.json.redaction",
            "1",
            (
                BannedSubstring("quoted.value", '"secret"'),
            ),
            scopes=(ScanScope.OUTPUT,),
        )
        firewall = RuleEngine(
            scanner=RuleScanner(
                rules=(JSONOutputRule(), BannedSubstringsRule(catalog)),
            )
        )

        result = firewall.process(
            '{"value":"secret"}',
            scope=ScanScope.OUTPUT,
        )

        self.assertTrue(result.blocked)
        postcondition = tuple(
            finding
            for finding in result.findings
            if finding.rule_id == "output.json.validity"
        )
        self.assertEqual(len(postcondition), 1)
        self.assertEqual(
            postcondition[0].metadata["validation_phase"],
            "post_policy",
        )
        self.assertEqual(
            (postcondition[0].span.start, postcondition[0].span.end),
            (0, 0),
        )

    def test_post_policy_validation_allows_json_preserving_redaction(self) -> None:
        catalog = BannedSubstringCatalog(
            "test.json.redaction",
            "1",
            (BannedSubstring("value", "secret"),),
            scopes=(ScanScope.OUTPUT,),
        )
        firewall = RuleEngine(
            scanner=RuleScanner(
                rules=(JSONOutputRule(), BannedSubstringsRule(catalog)),
            )
        )

        result = firewall.process(
            '{"value":"secret"}',
            scope=ScanScope.OUTPUT,
        )

        self.assertFalse(result.blocked)
        self.assertEqual(result.processed_text, '{"value":"[REDACTED]"}')


class JSONOutputFacadeTests(unittest.TestCase):
    def test_is_opt_in_and_advertised_when_enabled(self) -> None:
        disabled = Firewall(pool_config=_single_worker_config())
        enabled = Firewall(
            pool_config=_single_worker_config(),
            json_output_config=JSONOutputConfig(),
        )

        self.assertNotIn(
            "output.json.validity",
            tuple(rule.rule_id for rule in disabled.capabilities().rules),
        )
        json_capability = tuple(
            rule
            for rule in enabled.capabilities().rules
            if rule.rule_id == "output.json.validity"
        )
        self.assertEqual(len(json_capability), 1)
        self.assertEqual(json_capability[0].scopes, (ScanScope.OUTPUT,))
        self.assertEqual(enabled.capabilities().json_output.max_depth, 64)
        self.assertEqual(
            enabled.capabilities().json_output.max_structure_tokens,
            100_000,
        )
        self.assertEqual(enabled.capabilities().json_output.max_number_chars, 128)
        self.assertTrue(enabled.capabilities().json_output.reject_duplicate_keys)
        disabled.close()
        enabled.close()

    def test_worker_accepts_valid_output_and_blocks_invalid_output(self) -> None:
        firewall = Firewall(
            pool_config=_single_worker_config(),
            json_output_config=JSONOutputConfig(),
        )

        with firewall:
            self.assertEqual(firewall.sanitize_output('{"ok":true}'), '{"ok":true}')
            self.assertEqual(firewall.sanitize_input("ordinary text"), "ordinary text")
            with self.assertRaises(ContentBlockedError) as raised:
                firewall.sanitize_output("ordinary text")

        finding = raised.exception.findings[0]
        self.assertEqual(finding.rule_id, "output.json.validity")
        self.assertNotIn("ordinary text", finding.message)
        self.assertNotIn("ordinary text", repr(dict(finding.metadata)))

    def test_rejects_non_config_value(self) -> None:
        with self.assertRaises(TypeError):
            Firewall(json_output_config=True)  # type: ignore[arg-type]

    def test_worker_blocks_when_redaction_breaks_json_structure(self) -> None:
        catalog = BannedSubstringCatalog(
            "test.json.worker_redaction",
            "1",
            (BannedSubstring("quoted.value", '"secret"'),),
            scopes=(ScanScope.OUTPUT,),
        )
        firewall = Firewall(
            pool_config=_single_worker_config(),
            banned_substring_catalog=catalog,
            json_output_config=JSONOutputConfig(),
        )

        with firewall, self.assertRaises(ContentBlockedError) as raised:
            firewall.sanitize_output('{"value":"secret"}')

        json_findings = tuple(
            finding
            for finding in raised.exception.findings
            if finding.rule_id == "output.json.validity"
        )
        self.assertEqual(len(json_findings), 1)
        self.assertEqual(
            json_findings[0].metadata["validation_phase"],
            "post_policy",
        )


if __name__ == "__main__":
    unittest.main()
