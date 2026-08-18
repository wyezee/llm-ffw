import time
import unittest

from llm_ffw import (
    Action,
    BannedSubstring,
    BannedSubstringCatalog,
    BannedSubstringsRule,
    RuleEngine,
    Firewall,
    FirewallManager,
    LiteralMatchMode,
    ScanScope,
    RuleScanner,
    ProcessScannerPoolConfig,
)


def _catalog(*patterns: BannedSubstring) -> BannedSubstringCatalog:
    return BannedSubstringCatalog(
        "acme.banned_text",
        "1.0.0",
        patterns,
    )


class BannedSubstringsRuleTests(unittest.TestCase):
    def test_redacts_substring_and_reports_only_safe_metadata(self) -> None:
        value = "internal project falcon"
        catalog = _catalog(BannedSubstring("project.falcon", value))
        firewall = RuleEngine(
            scanner=RuleScanner(rules=(BannedSubstringsRule(catalog),))
        )

        result = firewall.process(f"Discuss {value} today")

        self.assertEqual(result.decision, Action.REDACT)
        self.assertEqual(result.processed_text, "Discuss [REDACTED] today")
        finding = result.findings[0]
        self.assertEqual(finding.rule_id, "content.banned_substrings")
        self.assertEqual(finding.metadata["pattern_id"], "project.falcon")
        self.assertNotIn(value, finding.message)
        self.assertNotIn(value, repr(finding.metadata))

    def test_word_case_and_scope_contract(self) -> None:
        catalog = BannedSubstringCatalog(
            "acme.words",
            "1",
            (
                BannedSubstring(
                    "word.alpha",
                    "Alpha",
                    match_mode=LiteralMatchMode.ASCII_WORD,
                ),
            ),
            scopes=(ScanScope.OUTPUT,),
        )
        scanner = RuleScanner(rules=(BannedSubstringsRule(catalog),))

        self.assertEqual(scanner.scan("xalpha", scope=ScanScope.OUTPUT), ())
        self.assertEqual(len(scanner.scan(" ALPHA ", scope=ScanScope.OUTPUT)), 1)
        self.assertEqual(scanner.scan(" ALPHA ", scope=ScanScope.INPUT), ())

    def test_more_than_64_results_returns_one_block_recommendation(self) -> None:
        scanner = RuleScanner(
            rules=(
                BannedSubstringsRule(
                    _catalog(BannedSubstring("repeat", "abc"))
                ),
            )
        )

        findings = scanner.scan("abc " * 65)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].action, Action.BLOCK)
        self.assertEqual(findings[0].metadata["limit"], "64")

    def test_catalog_rejects_regex_unicode_duplicates_and_empty_scopes(self) -> None:
        with self.assertRaisesRegex(ValueError, "printable ASCII"):
            BannedSubstring("bad", "a\nb")
        with self.assertRaisesRegex(ValueError, "unique ignoring ASCII case"):
            _catalog(
                BannedSubstring("one", "Alpha"),
                BannedSubstring("two", "alpha"),
            )
        with self.assertRaisesRegex(ValueError, "scopes"):
            BannedSubstringCatalog(
                "acme.empty",
                "1",
                (BannedSubstring("one", "alpha"),),
                scopes=(),
            )

    def test_long_prefix_adversarial_input_is_fast(self) -> None:
        patterns = tuple(
            BannedSubstring(
                f"pattern.{index}",
                f"shared-prefix-{index:04d}",
                case_sensitive=True,
            )
            for index in range(1_000)
        )
        scanner = RuleScanner(
            rules=(BannedSubstringsRule(_catalog(*patterns)),)
        )
        text = ("shared-prefix-zzzz" * 450_000)[:8_000_000]

        started = time.perf_counter()
        findings = scanner.scan(text)
        elapsed = time.perf_counter() - started

        self.assertEqual(findings, ())
        self.assertLess(elapsed, 2.0)

    def test_facade_propagates_catalog_through_recycled_workers(self) -> None:
        value = "internal project falcon"
        catalog = _catalog(BannedSubstring("project.falcon", value))
        firewall = Firewall(
            banned_substring_catalog=catalog,
            pool_config=ProcessScannerPoolConfig(
                max_workers=1,
                max_in_flight=1,
                max_tasks_per_child=1,
            ),
            request_timeout_seconds=30,
        )

        capabilities = firewall.capabilities()
        self.assertEqual(capabilities.rule_count, 7)
        self.assertEqual(
            capabilities.banned_substring_catalog.pattern_count,
            1,
        )
        self.assertNotIn(value, repr(capabilities))
        with firewall:
            self.assertEqual(
                firewall.sanitize_input(f"Discuss {value}"),
                "Discuss [REDACTED]",
            )
            self.assertEqual(
                firewall.sanitize_output(f"Repeat {value}"),
                "Repeat [REDACTED]",
            )

    def test_manager_created_generation_preserves_literal_catalog(self) -> None:
        value = "internal project falcon"
        manager = FirewallManager(
            banned_substring_catalog=_catalog(
                BannedSubstring("project.falcon", value)
            ),
            pool_config=ProcessScannerPoolConfig(
                max_workers=1,
                max_in_flight=1,
                max_tasks_per_child=2,
            ),
            request_timeout_seconds=30,
        )

        with manager:
            self.assertEqual(
                manager.sanitize_input(value),
                "[REDACTED]",
            )


if __name__ == "__main__":
    unittest.main()
