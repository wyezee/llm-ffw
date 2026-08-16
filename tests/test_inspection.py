from dataclasses import FrozenInstanceError
import time
import unittest
from unittest.mock import patch

from llm_ffw import (
    Action,
    Inspection,
    InspectionFeature,
    InspectionFeatureUnavailableError,
    ScanScope,
    Scanner,
    ScannerConfig,
    Severity,
    Span,
)
from llm_ffw.inspection import build_inspection
from llm_ffw.rules import Rule, RuleMatch


class _ProbeRule(Rule):
    def __init__(
        self,
        rule_id: str,
        *,
        scopes: frozenset[ScanScope],
        features: frozenset[InspectionFeature] = frozenset(),
        required_prompt: str | None = None,
    ) -> None:
        self._rule_id = rule_id
        self._scopes = scopes
        self._features = features
        self._required_prompt = required_prompt

    @property
    def rule_id(self) -> str:
        return self._rule_id

    @property
    def purpose(self) -> str:
        return "Exercise the shared inspection contract in tests."

    @property
    def scopes(self) -> frozenset[ScanScope]:
        return self._scopes

    @property
    def inspection_features(self) -> frozenset[InspectionFeature]:
        return self._features

    def scan(self, inspection: Inspection) -> tuple[RuleMatch, ...]:
        if InspectionFeature.ASCII in self._features and not inspection.is_ascii:
            return ()
        if (
            InspectionFeature.PROMPT_CONTEXT in self._features
            and inspection.prompt_text != self._required_prompt
        ):
            return ()
        if not inspection.text:
            return ()
        return (
            RuleMatch(
                span=Span(0, 1),
                severity=Severity.LOW,
                action=Action.ALLOW,
                message="Inspection probe matched.",
                metadata={"scope": inspection.scope.value},
            ),
        )


class InspectionTests(unittest.TestCase):
    def test_inspection_is_immutable_and_guards_unplanned_features(self) -> None:
        inspection = build_inspection(
            "safe",
            scope=ScanScope.INPUT,
            features=frozenset(),
            prompt_context=None,
        )

        with self.assertRaises(FrozenInstanceError):
            inspection.scope = ScanScope.OUTPUT  # type: ignore[misc]
        with self.assertRaises(InspectionFeatureUnavailableError):
            _ = inspection.is_ascii
        with self.assertRaises(InspectionFeatureUnavailableError):
            _ = inspection.prompt_text
        with self.assertRaises(InspectionFeatureUnavailableError):
            _ = inspection.unicode_security

    def test_identity_normalization_does_not_copy_large_ascii_text(self) -> None:
        text = "x" * 8_000_000

        inspection = build_inspection(
            text,
            scope=ScanScope.INPUT,
            features=frozenset((InspectionFeature.ASCII,)),
            prompt_context=None,
        )

        self.assertIs(inspection.text, text)
        self.assertTrue(inspection.is_ascii)

    def test_scope_dispatch_runs_only_applicable_rules(self) -> None:
        scanner = Scanner(
            rules=(
                _ProbeRule("probe.input", scopes=frozenset((ScanScope.INPUT,))),
                _ProbeRule("probe.output", scopes=frozenset((ScanScope.OUTPUT,))),
            )
        )

        input_findings = scanner.scan("x", scope=ScanScope.INPUT)
        output_findings = scanner.scan("x", scope=ScanScope.OUTPUT)

        self.assertEqual(tuple(item.rule_id for item in input_findings), ("probe.input",))
        self.assertEqual(
            tuple(item.rule_id for item in output_findings),
            ("probe.output",),
        )

    def test_ascii_feature_is_computed_once_for_all_active_rules(self) -> None:
        ascii_feature = frozenset((InspectionFeature.ASCII,))
        scanner = Scanner(
            rules=(
                _ProbeRule(
                    "probe.ascii.first",
                    scopes=frozenset((ScanScope.INPUT,)),
                    features=ascii_feature,
                ),
                _ProbeRule(
                    "probe.ascii.second",
                    scopes=frozenset((ScanScope.INPUT,)),
                    features=ascii_feature,
                ),
            )
        )

        with patch(
            "llm_ffw.inspection._compute_ascii",
            wraps=str.isascii,
        ) as compute_ascii:
            findings = scanner.scan("plain ASCII")

        self.assertEqual(len(findings), 2)
        compute_ascii.assert_called_once_with("plain ASCII")

    def test_features_for_inapplicable_rules_are_not_computed(self) -> None:
        scanner = Scanner(
            rules=(
                _ProbeRule(
                    "probe.input.ascii",
                    scopes=frozenset((ScanScope.INPUT,)),
                    features=frozenset((InspectionFeature.ASCII,)),
                ),
            )
        )

        with patch("llm_ffw.inspection._compute_ascii") as compute_ascii:
            self.assertEqual(scanner.scan("output", scope=ScanScope.OUTPUT), ())

        compute_ascii.assert_not_called()

    def test_prompt_context_is_normalized_only_for_output_rule_requesting_it(self) -> None:
        scanner = Scanner(
            rules=(
                _ProbeRule(
                    "probe.output.context",
                    scopes=frozenset((ScanScope.OUTPUT,)),
                    features=frozenset((InspectionFeature.PROMPT_CONTEXT,)),
                    required_prompt="first\nsecond",
                ),
            )
        )

        findings = scanner.scan(
            "x",
            scope=ScanScope.OUTPUT,
            prompt_context="first\r\nsecond",
        )

        self.assertEqual(len(findings), 1)
        self.assertNotIn("first", findings[0].message)
        self.assertNotIn("first", tuple(findings[0].metadata.values()))

    def test_rejects_invalid_scope_and_prompt_context(self) -> None:
        scanner = Scanner(config=ScannerConfig(max_input_chars=5))

        with self.assertRaises(TypeError):
            scanner.scan("safe", scope="input")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            scanner.scan("safe", prompt_context="x")
        with self.assertRaises(TypeError):
            scanner.scan(
                "safe",
                scope=ScanScope.OUTPUT,
                prompt_context=1,  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(ValueError, "prompt_context"):
            scanner.scan(
                "safe",
                scope=ScanScope.OUTPUT,
                prompt_context="123456",
            )

    def test_rejects_empty_scope_contract(self) -> None:
        with self.assertRaisesRegex(ValueError, "scopes"):
            Scanner(rules=(_ProbeRule("probe.invalid", scopes=frozenset()),))

    def test_rejects_unknown_inspection_feature_contract(self) -> None:
        rule = _ProbeRule(
            "probe.invalid.feature",
            scopes=frozenset((ScanScope.INPUT,)),
            features=frozenset(("ascii",)),  # type: ignore[arg-type]
        )

        with self.assertRaisesRegex(ValueError, "inspection_features"):
            Scanner(rules=(rule,))

    def test_shared_ascii_feature_is_fast_on_eight_million_characters(self) -> None:
        scanner = Scanner(
            rules=(
                _ProbeRule(
                    "probe.long.first",
                    scopes=frozenset((ScanScope.INPUT,)),
                    features=frozenset((InspectionFeature.ASCII,)),
                ),
                _ProbeRule(
                    "probe.long.second",
                    scopes=frozenset((ScanScope.INPUT,)),
                    features=frozenset((InspectionFeature.ASCII,)),
                ),
            )
        )
        text = "x" * 8_000_000

        started = time.perf_counter()
        findings = scanner.scan(text)
        elapsed = time.perf_counter() - started

        self.assertEqual(len(findings), 2)
        self.assertLess(elapsed, 2.0)


if __name__ == "__main__":
    unittest.main()
