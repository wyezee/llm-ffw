import unittest

from llm_ffw import Action, Finding, Severity, Span


class SpanTests(unittest.TestCase):
    def test_allows_empty_diagnostic_span_and_rejects_invalid_span(self) -> None:
        self.assertEqual(Span(0, 0), Span(0, 0))
        for start, end in ((2, 1), (-1, 2)):
            with self.subTest(start=start, end=end), self.assertRaises(ValueError):
                Span(start, end)


class FindingTests(unittest.TestCase):
    def test_schema_serializes_without_matched_text(self) -> None:
        finding = Finding(
            rule_id="secrets.detected",
            severity=Severity.HIGH,
            action=Action.REDACT,
            span=Span(4, 12),
            message="Potential credential detected.",
            redacted_preview="[REDACTED:test]",
            metadata={"secret_type": "test"},
        )

        self.assertEqual(
            finding.to_dict(),
            {
                "rule_id": "secrets.detected",
                "severity": "high",
                "action": "redact",
                "span": {"start": 4, "end": 12},
                "message": "Potential credential detected.",
                "redacted_preview": "[REDACTED:test]",
                "metadata": {"secret_type": "test"},
            },
        )

    def test_metadata_is_immutable_copy(self) -> None:
        source = {"secret_type": "test"}
        finding = Finding(
            rule_id="secrets.detected",
            severity=Severity.HIGH,
            action=Action.REDACT,
            span=Span(0, 1),
            message="Detected.",
            metadata=source,
        )
        source["secret_type"] = "changed"

        self.assertEqual(finding.metadata["secret_type"], "test")
        with self.assertRaises(TypeError):
            finding.metadata["new"] = "value"  # type: ignore[index]

    def test_rejects_invalid_metadata(self) -> None:
        with self.assertRaises(TypeError):
            Finding(
                rule_id="secrets.detected",
                severity=Severity.HIGH,
                action=Action.REDACT,
                span=Span(0, 1),
                message="Detected.",
                metadata={"count": 1},  # type: ignore[dict-item]
            )
