import time
import unittest

from llm_ffw import (
    Action,
    AsyncFirewall,
    Firewall,
    FirewallManager,
    ProcessScannerPoolConfig,
    RepetitionConfig,
    RepetitionRule,
    ScanScope,
    RuleScanner,
)


def _scanner(config: RepetitionConfig | None = None) -> RuleScanner:
    return RuleScanner(rules=(RepetitionRule(config),))


class RepetitionConfigTests(unittest.TestCase):
    def test_rejects_unsafe_thresholds_limits_and_scopes(self) -> None:
        cases = (
            {"character_run_threshold": 7},
            {"token_repeat_threshold": 3},
            {"line_repeat_threshold": 2},
            {"max_findings": 0},
            {"max_findings": 1_025},
            {"character_run_threshold": 4_097},
        )
        for values in cases:
            with self.subTest(values=values), self.assertRaises(ValueError):
                RepetitionConfig(**values)
        with self.assertRaises(TypeError):
            RepetitionConfig(max_findings=True)
        for scopes in ((), ("input",), "input"):
            with self.subTest(scopes=scopes), self.assertRaises(
                (TypeError, ValueError)
            ):
                RepetitionConfig(scopes=scopes)  # type: ignore[arg-type]

    def test_normalizes_scopes_deterministically(self) -> None:
        config = RepetitionConfig(
            scopes=(ScanScope.OUTPUT, ScanScope.INPUT, ScanScope.OUTPUT)
        )
        self.assertEqual(config.scopes, (ScanScope.INPUT, ScanScope.OUTPUT))


class RepetitionRuleTests(unittest.TestCase):
    def test_is_opt_in_and_supports_both_scopes(self) -> None:
        text = "x" * 256
        self.assertEqual(RuleScanner().scan(text), ())
        scanner = _scanner()
        self.assertEqual(len(scanner.scan(text, scope=ScanScope.INPUT)), 1)
        self.assertEqual(len(scanner.scan(text, scope=ScanScope.OUTPUT)), 1)

    def test_detects_exact_character_token_and_nonempty_line_runs(self) -> None:
        cases = (
            ("prefix " + ("x" * 256), "character_run", 256),
            ("go " * 64, "token_run", 64),
            ("same line\n" * 32, "line_run", 32),
            (("windows line\r\n" * 31) + "windows line", "line_run", 32),
        )
        scanner = _scanner()
        for text, reason, count in cases:
            with self.subTest(reason=reason):
                findings = scanner.scan(text)
                matching = [
                    item for item in findings if item.metadata["reason"] == reason
                ]
                self.assertEqual(len(matching), 1)
                finding = matching[0]
                self.assertIs(finding.action, Action.REVIEW)
                self.assertEqual(finding.metadata["repeat_count"], str(count))
                self.assertEqual(finding.redacted_preview, None)
                self.assertNotIn(text[finding.span.start : finding.span.end], repr(finding))

    def test_ignores_normal_prose_code_logs_base64_separators_and_multilingual(self) -> None:
        samples = (
            "This is ordinary prose with no excessive exact repetition.",
            "\n".join("    value = value + 1" for _ in range(31)),
            "\n".join(f"INFO request={index} status=ok" for index in range(100)),
            "VGhpcyBpcyBhIGJvdW5kZWQgYmFzZTY0LWxpa2Ugc2FtcGxlLg==",
            ("- " * 200) + ("= " * 200),
            "नमस्ते दुनिया こんにちは世界 مرحبا بالعالم",
            ("word " * 63) + "done",
        )
        scanner = _scanner()
        for text in samples:
            with self.subTest(text=text[:40]):
                self.assertEqual(scanner.scan(text), ())

    def test_token_alphanumeric_check_preserves_edges_and_middle(self) -> None:
        scanner = _scanner()
        for token in ("a___", "___a", "__a__", "__9__"):
            with self.subTest(token=token):
                finding = scanner.scan((token + " ") * 64)[0]
                self.assertEqual(finding.metadata["reason"], "token_run")
                self.assertEqual(finding.metadata["repeat_count"], "64")
        self.assertEqual(scanner.scan(("___ " * 64)), ())

    def test_finding_limit_fails_closed_over_uninspected_remainder(self) -> None:
        scanner = _scanner(
            RepetitionConfig(
                character_run_threshold=8,
                token_repeat_threshold=4,
                line_repeat_threshold=3,
                max_findings=1,
            )
        )
        text = ("a" * 8) + " gap " + ("b" * 8) + " private remainder"
        findings = scanner.scan(text)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[-1].metadata["reason"], "finding_limit_exceeded")
        self.assertIs(findings[-1].action, Action.BLOCK)
        self.assertEqual(findings[-1].span.end, len(text))

    def test_eight_million_character_adversarial_paths_are_bounded(self) -> None:
        scanner = _scanner()
        workloads = (
            "x" * 8_000_000,
            ("ab" * 4_000_000),
            ("- " * 4_000_000),
            ("aa " * 2_666_667)[:8_000_000],
            (("a" * 255) + "b") * 31_250,
        )
        started = time.perf_counter()
        self.assertEqual(
            scanner.scan(workloads[0])[0].metadata["reason"],
            "character_run",
        )
        self.assertEqual(scanner.scan(workloads[1]), ())
        self.assertEqual(scanner.scan(workloads[2]), ())
        self.assertEqual(
            scanner.scan(workloads[3])[0].metadata["reason"], "token_run"
        )
        self.assertEqual(scanner.scan(workloads[4]), ())
        self.assertLess(time.perf_counter() - started, 8.0)


class RepetitionFacadeTests(unittest.TestCase):
    def test_facade_propagates_configuration_and_capabilities(self) -> None:
        config = RepetitionConfig(
            character_run_threshold=300,
            token_repeat_threshold=70,
            line_repeat_threshold=40,
            max_findings=12,
        )
        firewall = Firewall(
            pool_config=ProcessScannerPoolConfig(
                max_workers=1, max_in_flight=1, max_tasks_per_child=10
            ),
            repetition_config=config,
        )
        capability = firewall.capabilities().repetition
        self.assertIsNotNone(capability)
        assert capability is not None
        self.assertEqual(capability.character_run_threshold, 300)
        self.assertEqual(capability.token_repeat_threshold, 70)
        self.assertEqual(capability.line_repeat_threshold, 40)
        self.assertEqual(capability.max_findings, 12)
        with firewall:
            result = firewall.sanitize_input_result("z" * 300)
        self.assertIs(result.decision, Action.REVIEW)
        self.assertEqual(result.text, "z" * 300)

    def test_rejects_invalid_facade_configuration(self) -> None:
        with self.assertRaises(TypeError):
            Firewall(repetition_config=object())  # type: ignore[arg-type]

    def test_manager_and_async_facade_preserve_configuration(self) -> None:
        config = RepetitionConfig(max_findings=7)
        manager = FirewallManager(repetition_config=config)
        asynchronous = AsyncFirewall(repetition_config=config)
        self.assertEqual(manager.capabilities().repetition.max_findings, 7)  # type: ignore[union-attr]
        self.assertEqual(
            asynchronous.capabilities().repetition.max_findings, 7  # type: ignore[union-attr]
        )


if __name__ == "__main__":
    unittest.main()
