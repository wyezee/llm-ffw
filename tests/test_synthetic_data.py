import ast
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from benchmarks.bench_concurrent_scan import benchmark_concurrency
from benchmarks.generate_synthetic_dataset import write_dataset
from benchmarks.synthetic_data import build_dataset
from llm_ffw import Scanner, ScannerConfig


class SyntheticDataTests(unittest.TestCase):
    def test_dataset_is_deterministic_exact_size_and_source_independent(self) -> None:
        first = build_dataset(100_000)
        second = build_dataset(100_000)

        self.assertEqual(first.text, second.text)
        self.assertEqual(first.expected_findings, second.expected_findings)
        self.assertEqual(len(first.text), 100_000)
        self.assertEqual(
            first.sha256,
            hashlib.sha256(first.text.encode("utf-8")).hexdigest(),
        )

    def test_scanner_results_equal_independent_expected_spans(self) -> None:
        dataset = build_dataset(100_000)
        scanner = Scanner(config=ScannerConfig(max_input_chars=len(dataset.text)))

        actual = scanner.scan(dataset.text)

        self.assertEqual(len(actual), len(dataset.expected_findings))
        for expected, finding in zip(dataset.expected_findings, actual, strict=True):
            self.assertEqual(finding.metadata["signature_id"], expected.signature_id)
            self.assertEqual(finding.metadata["provider"], expected.provider)
            self.assertEqual(
                (finding.span.start, finding.span.end),
                (expected.start, expected.end),
            )

    def test_generator_writes_manifest_without_corpus_values(self) -> None:
        dataset = build_dataset(100_000)
        with tempfile.TemporaryDirectory() as temporary_directory:
            corpus_path, manifest_path = write_dataset(
                dataset, Path(temporary_directory)
            )

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(corpus_path.read_text(encoding="utf-8"), dataset.text)
            self.assertFalse(manifest["uses_llm"])
            self.assertFalse(manifest["uses_network"])
            self.assertEqual(manifest["sha256"], dataset.sha256)
            self.assertNotIn("text", manifest)
            self.assertNotIn(
                dataset.text[
                    dataset.expected_findings[0].start : dataset.expected_findings[0].end
                ],
                manifest_path.read_text(encoding="utf-8"),
            )

    def test_generator_imports_only_standard_library_and_local_modules(self) -> None:
        source_path = (
            Path(__file__).resolve().parents[1]
            / "benchmarks"
            / "generate_synthetic_dataset.py"
        )
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imported_roots: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".")[0])

        self.assertLessEqual(
            imported_roots,
            {"argparse", "json", "pathlib", "sys", "benchmarks"},
        )

    def test_thread_concurrency_harness_validates_results(self) -> None:
        dataset = build_dataset(100_000)

        result = benchmark_concurrency(
            "thread",
            dataset.text,
            expected_findings=len(dataset.expected_findings),
            workers=2,
            requests=4,
        )

        self.assertEqual(result.executor, "thread")
        self.assertEqual(result.workers, 2)
        self.assertEqual(result.requests, 4)
        self.assertGreater(result.requests_per_second, 0)


if __name__ == "__main__":
    unittest.main()
