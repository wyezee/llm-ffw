import ast
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from benchmarks.all_rules_data import (
    ALL_TEXT_RULE_IDS,
    BANNED_MARKER,
    build_structured_scenarios,
    build_text_scenarios,
    manifest,
)
from benchmarks.bench_all_rules import (
    environment_metadata,
    run_benchmark,
    summarize_results,
)
from benchmarks.generate_all_rules_dataset import write_dataset
from llm_ffw import ToolCallRule, ToolResultRule


class AllRulesDatasetTests(unittest.TestCase):
    def test_text_profiles_are_deterministic_exact_size_and_complete(self) -> None:
        first = build_text_scenarios(32_768)
        second = build_text_scenarios(32_768)

        self.assertEqual(first, second)
        self.assertTrue(all(len(item.text) == 32_768 for item in first))
        self.assertEqual(
            {item.scenario_id for item in first},
            {
                "clean-input",
                "clean-code-log-input",
                "clean-output-json",
                "invalid-output-json",
                "sparse-input",
                "dense-input",
                "adversarial-near-miss-input",
            },
        )
        expected_rule_ids = {
            finding.rule_id for scenario in first for finding in scenario.expected
        }
        self.assertEqual(expected_rule_ids, ALL_TEXT_RULE_IDS)

    def test_manifest_is_disclosure_safe_and_corpora_are_ignored_outputs(self) -> None:
        scenarios = build_text_scenarios(32_768)
        rendered = json.dumps(manifest(scenarios), sort_keys=True)
        self.assertNotIn("text", manifest(scenarios)["scenarios"][0])
        self.assertNotIn(BANNED_MARKER, rendered)
        self.assertNotIn("4242424242424242", rendered)
        self.assertIn('"uses_llm": false', rendered)
        self.assertIn('"uses_network": false', rendered)
        self.assertIn('"action": "remove"', rendered)

        with tempfile.TemporaryDirectory() as directory:
            paths = write_dataset(32_768, Path(directory))
            self.assertEqual(len(paths), len(scenarios) + 1)
            generated = json.loads(paths[-1].read_text(encoding="utf-8"))
            self.assertEqual(generated, manifest(scenarios))

    def test_structured_scenarios_cover_valid_and_invalid_cases(self) -> None:
        scenarios = build_structured_scenarios()
        call_rule = ToolCallRule((scenarios.definition,))
        result_rule = ToolResultRule()

        self.assertEqual(call_rule.validate(scenarios.valid_call), ())
        self.assertEqual(result_rule.validate(scenarios.valid_result), ())
        self.assertEqual(
            call_rule.validate(scenarios.invalid_call)[0].rule_id,
            "tools.call.validity",
        )
        self.assertEqual(
            result_rule.validate(scenarios.invalid_result)[0].rule_id,
            "tools.result.validity",
        )

    def test_new_tools_use_only_standard_library_and_local_modules(self) -> None:
        allowed = {
            "argparse",
            "benchmarks",
            "collections",
            "concurrent",
            "dataclasses",
            "hashlib",
            "json",
            "llm_ffw",
            "os",
            "pathlib",
            "platform",
            "statistics",
            "subprocess",
            "sys",
            "threading",
            "time",
        }
        root = Path(__file__).resolve().parents[1]
        for relative in (
            "benchmarks/all_rules_data.py",
            "benchmarks/generate_all_rules_dataset.py",
            "benchmarks/bench_all_rules.py",
        ):
            tree = ast.parse((root / relative).read_text(encoding="utf-8"))
            imported: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module.split(".")[0])
            self.assertLessEqual(imported, allowed, relative)


class AllRulesBenchmarkTests(unittest.TestCase):
    def test_process_harness_verifies_sparse_expectations_and_metrics(self) -> None:
        sparse = next(
            item
            for item in build_text_scenarios(32_768)
            if item.scenario_id == "sparse-input"
        )
        result = run_benchmark(
            sparse,
            workers=1,
            concurrency=1,
            requests=1,
            max_tasks_per_child=10,
            request_timeout=30,
        )

        self.assertEqual(result.enabled_text_rules, 17)
        self.assertEqual(result.completed, 1)
        self.assertEqual(result.rejected + result.timed_out + result.failed, 0)
        self.assertEqual(set(result.finding_counts), {item.rule_id for item in sparse.expected})
        self.assertGreater(result.requests_per_second, 0)
        self.assertGreater(result.peak_tree_rss_mib, 0)

    def test_default_rule_set_filters_opt_in_expectations(self) -> None:
        sparse = next(
            item
            for item in build_text_scenarios(8_192)
            if item.scenario_id == "sparse-input"
        )
        result = run_benchmark(
            sparse,
            workers=1,
            concurrency=1,
            requests=1,
            max_tasks_per_child=10,
            request_timeout=30,
            rule_set="default",
        )

        self.assertEqual(result.enabled_text_rules, 6)
        self.assertEqual(
            set(result.finding_counts),
            {
                "secrets.detected",
                "unicode.invisible_characters",
                "unicode.tag_smuggling",
                "pii.payment_card",
                "secrets.private_key",
                "secrets.jwt_token",
            },
        )

    def test_repeated_rounds_produce_disclosure_safe_summary(self) -> None:
        scenario = next(
            item
            for item in build_text_scenarios(8_192)
            if item.scenario_id == "clean-input"
        )
        first = run_benchmark(
            scenario,
            workers=1,
            concurrency=1,
            requests=1,
            max_tasks_per_child=10,
            request_timeout=30,
        )
        second = replace(
            first,
            round_index=2,
            requests_per_second=first.requests_per_second * 2,
        )

        summary = summarize_results([first, second])[0]

        self.assertEqual(summary.rounds, 2)
        self.assertEqual(summary.measured_requests, 2)
        self.assertEqual(
            summary.median_requests_per_second,
            first.requests_per_second * 1.5,
        )
        self.assertGreater(summary.latency_p95_ms, 0)
        self.assertFalse(hasattr(summary, "text"))

    def test_environment_metadata_omits_host_and_user_identity(self) -> None:
        metadata = environment_metadata()

        self.assertEqual(metadata["python"], "3.14.7")
        self.assertIn("commit", metadata)
        self.assertNotIn("hostname", metadata)
        self.assertNotIn("username", metadata)

    def test_process_harness_verifies_json_block_expectation(self) -> None:
        invalid = next(
            item
            for item in build_text_scenarios(8_192)
            if item.scenario_id == "invalid-output-json"
        )
        result = run_benchmark(
            invalid,
            workers=1,
            concurrency=1,
            requests=1,
            max_tasks_per_child=10,
            request_timeout=30,
        )

        self.assertEqual(result.finding_counts, {"output.json.validity": 1})
        self.assertEqual(result.completed, 1)


if __name__ == "__main__":
    unittest.main()
