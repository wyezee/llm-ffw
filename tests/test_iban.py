import time
import asyncio
import unittest

from llm_ffw import (
    AUDIT_POLICY,
    STRICT_POLICY,
    Action,
    AsyncFirewall,
    ContentBlockedError,
    RuleEngine,
    IBANConfig,
    IBANRule,
    Firewall,
    FirewallManager,
    ProcessScannerPoolConfig,
    ScanScope,
    RuleScanner,
)
from llm_ffw.iban import (
    IBAN_LENGTHS,
    IBAN_REGISTRY_ISSUED,
    IBAN_REGISTRY_RELEASE,
)


def _scanner(config: IBANConfig | None = None) -> RuleScanner:
    return RuleScanner(rules=(IBANRule(config),))


def _single_worker_config() -> ProcessScannerPoolConfig:
    return ProcessScannerPoolConfig(
        max_workers=1,
        max_in_flight=1,
        max_tasks_per_child=10,
    )


def _check_digits(country: str, bban: str) -> str:
    rearranged = bban + country + "00"
    remainder = 0
    for character in rearranged:
        if character.isdigit():
            remainder = (remainder * 10 + int(character)) % 97
        else:
            remainder = (remainder * 100 + ord(character) - ord("A") + 10) % 97
    return f"{98 - remainder:02d}"


def _synthetic_iban(country: str, length: int) -> str:
    bban = "0" * (length - 4)
    return country + _check_digits(country, bban) + bban


class IBANConfigTests(unittest.TestCase):
    def test_rejects_invalid_limits_and_scopes(self) -> None:
        for value in (0, -1, 1_025):
            with self.subTest(value=value), self.assertRaises(ValueError):
                IBANConfig(max_candidates=value)
        with self.assertRaises(TypeError):
            IBANConfig(max_candidates=True)
        for scopes in ((), (ScanScope.TOOL_CALL,), ("input",), "input"):
            with self.subTest(scopes=scopes), self.assertRaises(
                (TypeError, ValueError)
            ):
                IBANConfig(scopes=scopes)  # type: ignore[arg-type]

    def test_normalizes_text_scopes_deterministically(self) -> None:
        config = IBANConfig(
            scopes=(ScanScope.OUTPUT, ScanScope.INPUT, ScanScope.OUTPUT)
        )
        self.assertEqual(config.scopes, (ScanScope.INPUT, ScanScope.OUTPUT))


class IBANRuleTests(unittest.TestCase):
    def test_registry_is_pinned_to_swift_release_102(self) -> None:
        self.assertEqual(IBAN_REGISTRY_RELEASE, "102")
        self.assertEqual(IBAN_REGISTRY_ISSUED, "2026-06")
        self.assertEqual(len(IBAN_LENGTHS), 89)
        self.assertEqual(
            (min(IBAN_LENGTHS.values()), max(IBAN_LENGTHS.values())),
            (15, 33),
        )

    def test_detects_official_electronic_examples_with_exact_spans(self) -> None:
        examples = (
            "AD1200012030200359100100",
            "DE89370400440532013000",
            "GB29NWBK60161331926819",
            "LC55HEMM000100010012001200023015",
            "OM810180000001299123456",
            "SC18SSCB11010000000000001497USD",
            "VA59001123000012345678",
        )
        scanner = _scanner()
        for iban in examples:
            text = f"Account ({iban})."
            with self.subTest(country=iban[:2]):
                finding = scanner.scan(text)[0]
                self.assertEqual(text[finding.span.start : finding.span.end], iban)
                self.assertEqual(finding.metadata["country_code"], iban[:2])
                self.assertEqual(finding.metadata["format"], "electronic")

    def test_detects_canonical_print_format(self) -> None:
        iban = "GB29 NWBK 6016 1331 9268 19"
        finding = _scanner().scan(f"Pay {iban} today")[0]
        self.assertEqual(finding.metadata["format"], "print")
        self.assertEqual(finding.span.end - finding.span.start, len(iban))

    def test_detects_ascii_case_variants_without_changing_spans(self) -> None:
        variants = (
            "de89370400440532013000",
            "De89370400440532013000",
            "gb29 nwbk 6016 1331 9268 19",
        )
        scanner = _scanner()
        for iban in variants:
            text = f"Account ({iban})."
            with self.subTest(iban=iban):
                finding = scanner.scan(text)[0]
                self.assertEqual(text[finding.span.start : finding.span.end], iban)
                self.assertEqual(
                    finding.metadata["country_code"], iban[:2].upper()
                )

    def test_every_registered_country_length_can_pass_mod97(self) -> None:
        scanner = _scanner()
        for country, length in IBAN_LENGTHS.items():
            iban = _synthetic_iban(country, length)
            with self.subTest(country=country):
                findings = scanner.scan(iban)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].metadata["country_code"], country)

    def test_rejects_bad_checksums_lengths_formatting_and_boundaries(self) -> None:
        cases = (
            "DE00370400440532013000",
            "DE8937040044053201300",
            "DE893704004405320130000",
            "US89370400440532013000",
            "DE89-3704-0044-0532-0130-00",
            "DE89  3704 0044 0532 0130 00",
            "DE893704 0044 0532 0130 00",
            "DE89 37040044 0532 0130 00",
            "prefixDE89370400440532013000",
            "DE89370400440532013000suffix",
            "éDE89370400440532013000",
            "DE89370400440532013000é",
            "550E8400E29B41D4A716446655440000",
        )
        scanner = _scanner()
        for text in cases:
            with self.subTest(text=text):
                self.assertEqual(scanner.scan(text), ())

    def test_finding_and_redaction_do_not_disclose_iban(self) -> None:
        iban = "DE89370400440532013000"
        finding = _scanner().scan(iban)[0]
        self.assertIs(finding.action, Action.REDACT)
        self.assertEqual(finding.redacted_preview, "[REDACTED:iban]")
        self.assertNotIn(iban, finding.message)
        self.assertNotIn(iban, repr(finding))
        result = RuleEngine(scanner=_scanner()).process(iban)
        self.assertEqual(result.processed_text, "[REDACTED]")

    def test_builtin_policies_redact_block_and_review(self) -> None:
        iban = "DE89370400440532013000"
        self.assertEqual(
            RuleEngine(scanner=_scanner()).process(iban).decision,
            Action.REDACT,
        )
        self.assertEqual(
            RuleEngine(scanner=_scanner(), policy=AUDIT_POLICY)
            .process(iban)
            .decision,
            Action.REVIEW,
        )
        self.assertEqual(
            RuleEngine(scanner=_scanner(), policy=STRICT_POLICY)
            .process(iban)
            .decision,
            Action.BLOCK,
        )

    def test_candidate_limit_fails_closed(self) -> None:
        scanner = _scanner(IBANConfig(max_candidates=1))
        invalid = "DE00370400440532013000"
        text = f"{invalid} then {invalid} trailing"
        finding = scanner.scan(text)[0]
        self.assertIs(finding.action, Action.BLOCK)
        self.assertEqual(finding.metadata["reason"], "candidate_limit_exceeded")
        self.assertEqual(finding.span.end, len(text))

    def test_rule_is_opt_in_and_input_only_by_default(self) -> None:
        iban = "DE89370400440532013000"
        self.assertEqual(RuleScanner().scan(iban), ())
        self.assertEqual(len(_scanner().scan(iban, scope=ScanScope.INPUT)), 1)
        self.assertEqual(_scanner().scan(iban, scope=ScanScope.OUTPUT), ())

    def test_eight_million_character_adversarial_paths_are_bounded(self) -> None:
        scanner = _scanner()
        workloads = (
            "a" * 8_000_000,
            "A" * 8_000_000,
            "a" * 7_999_977 + " " + "de89370400440532013000",
            (("DE00" + "0" * 18 + " ") * 400_000)[:8_000_000],
            ("DE00 " * 1_600_000)[:8_000_000],
        )
        started = time.perf_counter()
        self.assertEqual(scanner.scan(workloads[0]), ())
        self.assertEqual(scanner.scan(workloads[1]), ())
        self.assertEqual(len(scanner.scan(workloads[2])), 1)
        for text in workloads[3:]:
            findings = scanner.scan(text)
            self.assertTrue(findings)
            self.assertIs(findings[-1].action, Action.BLOCK)
        self.assertLess(time.perf_counter() - started, 4.0)


class IBANFacadeTests(unittest.TestCase):
    def test_facade_propagates_configuration_and_capabilities(self) -> None:
        config = IBANConfig(
            max_candidates=7,
            scopes=(ScanScope.INPUT, ScanScope.OUTPUT),
        )
        firewall = Firewall(
            pool_config=_single_worker_config(),
            iban_config=config,
        )
        capabilities = firewall.capabilities()
        self.assertIsNotNone(capabilities.iban)
        self.assertEqual(capabilities.iban.max_candidates, 7)
        self.assertEqual(capabilities.iban.registry_release, "102")
        self.assertIn(
            IBANRule.RULE_ID,
            tuple(rule.rule_id for rule in capabilities.rules),
        )
        with firewall:
            self.assertEqual(
                firewall.sanitize_output("DE89370400440532013000"),
                "[REDACTED]",
            )

    def test_manager_and_async_facade_preserve_configuration(self) -> None:
        manager = FirewallManager(
            pool_config=_single_worker_config(),
            iban_config=IBANConfig(),
        )
        self.assertIsNotNone(manager.capabilities().iban)
        with manager:
            self.assertEqual(
                manager.sanitize_input("DE89370400440532013000"),
                "[REDACTED]",
            )

        asynchronous = AsyncFirewall(
            pool_config=_single_worker_config(),
            iban_config=IBANConfig(),
        )

        async def exercise() -> None:
            async with asynchronous:
                self.assertEqual(
                    await asynchronous.sanitize_input(
                        "DE89370400440532013000"
                    ),
                    "[REDACTED]",
                )

        asyncio.run(exercise())

    def test_strict_facade_blocks_and_invalid_config_type_is_rejected(self) -> None:
        with Firewall(
            pool_config=_single_worker_config(),
            iban_config=IBANConfig(),
            policy=STRICT_POLICY,
        ) as firewall, self.assertRaises(ContentBlockedError):
            firewall.sanitize_input("DE89370400440532013000")
        with self.assertRaises(TypeError):
            Firewall(iban_config=object())


if __name__ == "__main__":
    unittest.main()
