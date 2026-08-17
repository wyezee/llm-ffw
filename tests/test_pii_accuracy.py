import ast
import contextlib
import io
import ipaddress
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from benchmarks.pii_accuracy import (
    ExpectedPIIFinding,
    PIIAccuracyCorpus,
    PIIAccuracyScenario,
    build_corpus,
    evaluate_corpus,
    write_corpus,
)
from llm_ffw import EmailAddressRule, IPAddressRule, Scanner
from tools import pii_accuracy_gate


EXPECTED_DIGEST = (
    "315c53c4730ea81c391fcf9995503d5538da8337fa2f1cb85b7f859171da31d7"
)


class PIIAccuracyCorpusTests(unittest.TestCase):
    def test_corpus_is_deterministic_and_matches_manifest(self) -> None:
        first = build_corpus()
        second = build_corpus()

        self.assertEqual(first, second)
        self.assertEqual(first.sha256, EXPECTED_DIGEST)
        self.assertEqual(len(first.scenarios), 364)
        self.assertFalse(first.uses_llm)
        self.assertFalse(first.uses_network)
        self.assertTrue(first.synthetic_examples_only)

    def test_positive_values_use_only_synthetic_examples(self) -> None:
        synthetic_networks = (
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
            ipaddress.ip_network("2001:db8::/32"),
            ipaddress.ip_network("0.0.0.0/32"),
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("169.254.0.0/16"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("255.255.255.255/32"),
            ipaddress.ip_network("::/128"),
            ipaddress.ip_network("::1/128"),
            ipaddress.ip_network("fe80::/10"),
        )

        for scenario in build_corpus().scenarios:
            for finding in scenario.expected:
                value = scenario.text[finding.start : finding.end]
                if finding.rule_id == EmailAddressRule.RULE_ID:
                    domain = value.rsplit("@", 1)[1].lower()
                    reserved_domains = {
                        "example.com",
                        "example.org",
                        "example.net",
                        "example.test",
                        "example.invalid",
                    }
                    self.assertTrue(
                        domain in reserved_domains
                        or domain.endswith(
                            tuple(f".{item}" for item in reserved_domains)
                            + (".example",)
                        )
                    )
                elif finding.rule_id == IPAddressRule.RULE_ID:
                    address = ipaddress.ip_address(value)
                    self.assertTrue(
                        any(address in network for network in synthetic_networks)
                    )
                else:
                    self.fail(f"unexpected rule_id: {finding.rule_id}")

    def test_manifest_digest_drift_fails_closed(self) -> None:
        source = Path("benchmarks/pii_accuracy_manifest.json")
        manifest = json.loads(source.read_text(encoding="utf-8"))
        manifest["seed"] += 1
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "digest"):
                build_corpus(path)

    def test_generated_manifest_does_not_retain_scenario_text(self) -> None:
        corpus = build_corpus()
        with tempfile.TemporaryDirectory() as directory:
            corpus_path, manifest_path = write_corpus(corpus, Path(directory))
            lines = corpus_path.read_text(encoding="utf-8").splitlines()
            generated_manifest = json.loads(
                manifest_path.read_text(encoding="utf-8")
            )

        self.assertEqual(len(lines), 364)
        self.assertEqual(generated_manifest["sha256"], EXPECTED_DIGEST)
        self.assertTrue(generated_manifest["synthetic_examples_only"])
        self.assertEqual(
            generated_manifest["category_counts"],
            {
                "curated_email_positive": 20,
                "curated_ip_positive": 24,
                "curated_negative": 64,
                "email_positive": 64,
                "ip_positive": 64,
                "mixed_positive": 32,
                "negative": 96,
            },
        )
        self.assertNotIn("text", generated_manifest)
        self.assertNotIn("expected", generated_manifest)
        self.assertNotIn("example.com", json.dumps(generated_manifest))

    def test_corpus_tools_import_only_standard_library_and_local_modules(
        self,
    ) -> None:
        allowed = {
            "argparse",
            "benchmarks",
            "collections",
            "dataclasses",
            "hashlib",
            "json",
            "llm_ffw",
            "math",
            "pathlib",
            "random",
            "sys",
        }
        root = Path(__file__).resolve().parents[1]
        for relative_path in (
            "benchmarks/generate_pii_accuracy_dataset.py",
            "benchmarks/pii_accuracy.py",
            "tools/pii_accuracy_gate.py",
        ):
            with self.subTest(path=relative_path):
                tree = ast.parse(
                    (root / relative_path).read_text(encoding="utf-8")
                )
                imported_roots: set[str] = set()
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        imported_roots.update(
                            alias.name.split(".")[0] for alias in node.names
                        )
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        imported_roots.add(node.module.split(".")[0])
                self.assertLessEqual(imported_roots, allowed)


class PIIAccuracyEvaluationTests(unittest.TestCase):
    def test_current_rules_pass_exact_accuracy_and_redaction(self) -> None:
        report = evaluate_corpus(build_corpus())

        self.assertEqual(report.expected_findings, 236)
        self.assertEqual(report.actual_findings, 236)
        self.assertEqual(report.true_positives, 236)
        self.assertEqual(report.true_negative_scenarios, 160)
        self.assertEqual(report.false_positives, 0)
        self.assertEqual(report.false_negatives, 0)
        self.assertEqual(report.redaction_failures, 0)
        self.assertEqual(report.precision, 1.0)
        self.assertEqual(report.recall, 1.0)
        self.assertEqual(report.exact_span_rate, 1.0)
        self.assertEqual(
            {
                item.rule_id: (
                    item.expected_findings,
                    item.true_positives,
                    item.false_positives,
                    item.false_negatives,
                )
                for item in report.rules
            },
            {
                EmailAddressRule.RULE_ID: (116, 116, 0, 0),
                IPAddressRule.RULE_ID: (120, 120, 0, 0),
            },
        )
        self.assertEqual(
            {
                item.category: (
                    item.scenario_count,
                    item.false_positives,
                    item.false_negatives,
                    item.redaction_failures,
                )
                for item in report.categories
            },
            {
                "curated_email_positive": (20, 0, 0, 0),
                "curated_ip_positive": (24, 0, 0, 0),
                "curated_negative": (64, 0, 0, 0),
                "email_positive": (64, 0, 0, 0),
                "ip_positive": (64, 0, 0, 0),
                "mixed_positive": (32, 0, 0, 0),
                "negative": (96, 0, 0, 0),
            },
        )

    def test_false_positive_is_counted_without_exposing_text(self) -> None:
        corpus = _corpus(
            PIIAccuracyScenario(
                "false-positive",
                "negative",
                "synthetic@example.com",
                (),
            )
        )

        report = evaluate_corpus(corpus)

        self.assertEqual(report.false_positives, 1)
        self.assertEqual(report.false_negatives, 0)
        self.assertFalse(hasattr(report, "text"))
        self.assertNotIn("synthetic@example.com", repr(report))

    def test_false_negative_and_redaction_failure_are_counted(self) -> None:
        text = "owner=synthetic@example.com"
        corpus = _corpus(
            PIIAccuracyScenario(
                "false-negative",
                "email_positive",
                text,
                (
                    ExpectedPIIFinding(
                        EmailAddressRule.RULE_ID,
                        text.index("synthetic@example.com"),
                        len(text),
                    ),
                ),
            )
        )

        report = evaluate_corpus(corpus, scanner=Scanner(rules=()))

        self.assertEqual(report.false_positives, 0)
        self.assertEqual(report.false_negatives, 1)
        self.assertEqual(report.redaction_failures, 1)

    def test_wrong_span_counts_as_false_positive_and_false_negative(self) -> None:
        text = "owner=synthetic@example.com"
        actual_start = text.index("synthetic@example.com")
        corpus = _corpus(
            PIIAccuracyScenario(
                "wrong-span",
                "email_positive",
                text,
                (
                    ExpectedPIIFinding(
                        EmailAddressRule.RULE_ID,
                        actual_start + 1,
                        len(text),
                    ),
                ),
            )
        )

        report = evaluate_corpus(corpus)

        self.assertEqual(report.true_positives, 0)
        self.assertEqual(report.false_positives, 1)
        self.assertEqual(report.false_negatives, 1)
        self.assertEqual(report.redaction_failures, 1)


class PIIAccuracyGateTests(unittest.TestCase):
    def test_gate_passes_and_cli_prints_only_aggregate_evidence(self) -> None:
        output = io.StringIO()
        with mock.patch("sys.argv", ["pii_accuracy_gate.py"]):
            with contextlib.redirect_stdout(output):
                pii_accuracy_gate.main()

        rendered = output.getvalue()
        self.assertIn("pii_accuracy_gate=passed", rendered)
        self.assertIn(f"corpus_sha256={EXPECTED_DIGEST}", rendered)
        self.assertIn("category_curated_negative_scenarios=64", rendered)
        self.assertNotIn("synthetic@example.com", rendered)
        self.assertNotIn("2001:db8", rendered)

    def test_gate_rejects_invalid_thresholds(self) -> None:
        for value in (-0.01, 1.01, float("inf"), float("nan"), True):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    pii_accuracy_gate.run_gate(min_precision=value)
        with self.assertRaises(ValueError):
            pii_accuracy_gate.run_gate(max_redaction_failures=-1)


def _corpus(scenario: PIIAccuracyScenario) -> PIIAccuracyCorpus:
    return PIIAccuracyCorpus(
        dataset_id="test.pii_accuracy",
        seed=0,
        uses_llm=False,
        uses_network=False,
        synthetic_examples_only=True,
        scenarios=(scenario,),
    )


if __name__ == "__main__":
    unittest.main()
