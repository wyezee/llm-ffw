import string
import time
import unittest
from unittest.mock import patch

from llm_ffw import (
    AUDIT_POLICY,
    BALANCED_POLICY,
    STRICT_POLICY,
    Action,
    Firewall,
    FirewallPolicy,
    InvisibleCharactersRule,
    LLMFirewall,
    PolicyOverride,
    ProcessScannerPoolConfig,
    ScanScope,
    Scanner,
    ScannerConfig,
    SecretCatalog,
    SecretSignature,
)


_ZWSP = "\u200b"


def _enabled_scanner(*, max_input_chars: int = 8_000_000) -> Scanner:
    return Scanner(
        config=ScannerConfig(
            max_input_chars=max_input_chars,
            enable_invisible_characters=True,
        )
    )


class InvisibleCharactersRuleTests(unittest.TestCase):
    def test_matches_contextual_run_with_safe_metadata(self) -> None:
        text = "alpha" + _ZWSP * 2 + "beta"

        finding = Scanner(rules=(InvisibleCharactersRule(),)).scan(text)[0]

        self.assertEqual(finding.rule_id, "unicode.invisible_characters")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(finding.action, Action.REMOVE)
        self.assertEqual((finding.span.start, finding.span.end), (5, 7))
        self.assertEqual(
            finding.redacted_preview,
            "[REMOVED:invisible_character]",
        )
        self.assertEqual(finding.metadata["character_type"], "zero_width_space")
        self.assertNotIn(_ZWSP, finding.message)
        self.assertNotIn(_ZWSP, tuple(finding.metadata.values()))

    def test_ignores_non_contextual_and_legitimate_unicode_controls(self) -> None:
        scanner = Scanner(rules=(InvisibleCharactersRule(),))
        values = (
            "safe ASCII",
            _ZWSP + "prefix",
            "suffix" + _ZWSP,
            "left " + _ZWSP + " right",
            "ก" + _ZWSP + "ข",
            "日" + _ZWSP + "本",
            "က" + _ZWSP + "ခ",
            "ក" + _ZWSP + "ខ",
            "emoji 👩\u200d💻",
            "join\u200cer",
            "bom\ufeffmarker",
            "private\ue000use",
        )

        for value in values:
            with self.subTest(value=ascii(value)):
                self.assertEqual(scanner.scan(value), ())

    def test_excessive_runs_return_one_bounded_block_recommendation(self) -> None:
        text = "a" + (_ZWSP + "a") * 65

        findings = Scanner(rules=(InvisibleCharactersRule(),)).scan(text)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].action, Action.BLOCK)
        self.assertEqual(findings[0].metadata["limit"], "64")

    def test_marker_fast_path_and_adversarial_non_match_are_fast(self) -> None:
        scanner = Scanner(
            rules=(InvisibleCharactersRule(),),
            config=ScannerConfig(max_input_chars=8_000_000),
        )
        ascii_text = "x" * 8_000_000
        hostile_non_match = ("a" + _ZWSP + " ") * 333_333

        started = time.perf_counter()
        self.assertEqual(scanner.scan(ascii_text), ())
        ascii_elapsed = time.perf_counter() - started
        started = time.perf_counter()
        self.assertEqual(scanner.scan(hostile_non_match), ())
        hostile_elapsed = time.perf_counter() - started

        self.assertLess(ascii_elapsed, 2.0)
        self.assertLess(hostile_elapsed, 2.0)


class InvisibleCharacterEnforcementTests(unittest.TestCase):
    def test_builtin_profiles_apply_documented_actions(self) -> None:
        text = "hello" + _ZWSP + "world"

        balanced = Firewall(
            scanner=_enabled_scanner(), policy=BALANCED_POLICY
        ).process(text)
        strict = Firewall(
            scanner=_enabled_scanner(), policy=STRICT_POLICY
        ).process(text)
        audit = Firewall(
            scanner=_enabled_scanner(), policy=AUDIT_POLICY
        ).process(text)

        self.assertEqual(balanced.decision, Action.REMOVE)
        self.assertEqual(balanced.policy_version, "1.2.0")
        self.assertEqual(balanced.processed_text, "helloworld")
        self.assertEqual(strict.decision, Action.BLOCK)
        self.assertIsNone(strict.processed_text)
        self.assertEqual(audit.decision, Action.REVIEW)
        self.assertEqual(audit.processed_text, text)

    def test_balanced_profile_preserves_overflow_block(self) -> None:
        text = "a" + (_ZWSP + "a") * 65

        result = Firewall(scanner=_enabled_scanner()).process(text)

        self.assertEqual(result.decision, Action.BLOCK)
        self.assertIsNone(result.processed_text)

    def test_scanner_redact_applies_remove_without_policy(self) -> None:
        scanner = _enabled_scanner()
        text = "hello" + _ZWSP + "world"

        self.assertEqual(scanner.redact(text), "helloworld")

    def test_rescan_occurs_only_when_removal_is_effective(self) -> None:
        scanner = _enabled_scanner()
        firewall = Firewall(scanner=scanner)

        with patch.object(scanner, "scan", wraps=scanner.scan) as scan:
            self.assertEqual(firewall.process("safe").processed_text, "safe")
            self.assertEqual(scan.call_count, 1)
            self.assertEqual(
                firewall.process("hello" + _ZWSP + "world").processed_text,
                "helloworld",
            )
            self.assertEqual(scan.call_count, 3)

    def test_balanced_policy_removes_then_rescans_secrets(self) -> None:
        firewall = Firewall(scanner=_enabled_scanner())
        secret = "sk-" + "A" * 20
        obfuscated = secret[:3] + _ZWSP + secret[3:]

        result = firewall.process(obfuscated)

        self.assertEqual(result.decision, Action.REDACT)
        self.assertEqual(result.processed_text, "[REDACTED]")
        self.assertEqual(
            frozenset(finding.rule_id for finding in result.findings),
            frozenset(("unicode.invisible_characters", "secrets.detected")),
        )
        invisible_finding = tuple(
            finding
            for finding in result.findings
            if finding.rule_id == "unicode.invisible_characters"
        )[0]
        self.assertEqual(invisible_finding.action, Action.REMOVE)
        secret_finding = tuple(
            finding
            for finding in result.findings
            if finding.rule_id == "secrets.detected"
        )[0]
        self.assertEqual(
            (secret_finding.span.start, secret_finding.span.end),
            (0, len(obfuscated)),
        )
        self.assertNotIn(secret, result.processed_text or "")

    def test_compact_mapping_handles_removals_before_and_inside_match(self) -> None:
        firewall = Firewall(scanner=_enabled_scanner())
        secret = "sk-" + "C" * 20
        text = (
            "a"
            + _ZWSP
            + "b "
            + secret[:3]
            + _ZWSP
            + secret[3:]
            + " tail"
        )

        result = firewall.process(text)

        self.assertEqual(result.processed_text, "ab [REDACTED] tail")
        secret_finding = tuple(
            item for item in result.findings if item.rule_id == "secrets.detected"
        )[0]
        self.assertEqual(
            text[secret_finding.span.start : secret_finding.span.end],
            secret[:3] + _ZWSP + secret[3:],
        )

    def test_remove_is_idempotent_and_output_scope_is_unchanged(self) -> None:
        firewall = Firewall(scanner=_enabled_scanner())
        text = "hello" + _ZWSP + "world"

        first = firewall.process(text)
        second = firewall.process(first.processed_text or "")
        output = firewall.process(text, scope=ScanScope.OUTPUT)

        self.assertEqual(first.decision, Action.REMOVE)
        self.assertEqual(first.processed_text, "helloworld")
        self.assertEqual(second.decision, Action.ALLOW)
        self.assertEqual(second.processed_text, first.processed_text)
        self.assertEqual(output.decision, Action.ALLOW)
        self.assertEqual(output.processed_text, text)

    def test_policy_can_block_instead_of_removing(self) -> None:
        policy = FirewallPolicy(
            "acme.strict_unicode",
            "1",
            (
                PolicyOverride(
                    "unicode.invisible_characters",
                    ScanScope.INPUT,
                    Action.BLOCK,
                ),
            ),
        )
        result = Firewall(scanner=_enabled_scanner(), policy=policy).process(
            "hello" + _ZWSP + "world"
        )

        self.assertTrue(result.blocked)
        self.assertIsNone(result.processed_text)

    def test_process_facade_opt_in_survives_worker_recycling(self) -> None:
        secret = "sk-" + "B" * 20
        obfuscated = secret[:3] + _ZWSP + secret[3:]
        firewall = LLMFirewall(
            scanner_config=ScannerConfig(enable_invisible_characters=True),
            pool_config=ProcessScannerPoolConfig(
                max_workers=1,
                max_in_flight=1,
                max_tasks_per_child=1,
            ),
            request_timeout_seconds=30,
        )

        capabilities = firewall.capabilities()
        self.assertEqual(capabilities.rule_count, 2)
        self.assertEqual(
            tuple(rule.rule_id for rule in capabilities.rules),
            ("secrets.detected", "unicode.invisible_characters"),
        )
        with firewall:
            self.assertEqual(firewall.sanitize_input(obfuscated), "[REDACTED]")
            self.assertEqual(
                firewall.sanitize_input("hello" + _ZWSP + "world"),
                "helloworld",
            )
            self.assertEqual(
                firewall.sanitize_output("hello" + _ZWSP + "world"),
                "hello" + _ZWSP + "world",
            )

    def test_opt_in_rule_is_kept_with_replacement_secret_catalog(self) -> None:
        signature = SecretSignature(
            signature_id="acme.token",
            provider="acme",
            secret_type="token",
            prefixes=("acme_",),
            suffix_chars=string.ascii_letters + string.digits,
            min_suffix_chars=12,
            max_suffix_chars=12,
            boundary_chars=string.ascii_letters + string.digits + "_-",
            source="internal://security/acme-token",
        )
        catalog = SecretCatalog("acme.catalog", "1", (signature,))
        firewall = LLMFirewall(
            scanner_config=ScannerConfig(enable_invisible_characters=True),
            pool_config=ProcessScannerPoolConfig(
                max_workers=1,
                max_in_flight=1,
            ),
            replacement_secret_catalog=catalog,
            request_timeout_seconds=30,
        )

        with firewall:
            self.assertEqual(
                firewall.sanitize_input("acme_" + _ZWSP + "A" * 12),
                "[REDACTED]",
            )


if __name__ == "__main__":
    unittest.main()
