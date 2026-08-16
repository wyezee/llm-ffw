import io
from contextlib import redirect_stdout
import unittest
from unittest.mock import patch

from tools.rc_acceptance import (
    _default_scenarios,
    _percentile,
    main,
    run_acceptance,
)


class RCAcceptanceTests(unittest.TestCase):
    def test_scenarios_cover_false_positives_and_every_default_rule(self) -> None:
        scenarios = _default_scenarios()

        self.assertEqual(len(scenarios), 15)
        self.assertEqual(sum(not item.protected for item in scenarios), 9)
        self.assertEqual(sum(item.protected for item in scenarios), 6)
        self.assertEqual(
            {item.scenario_id for item in scenarios if item.protected},
            {
                "protect-provider-secret",
                "protect-invisible-character",
                "protect-unicode-tag-smuggling",
                "protect-payment-card",
                "protect-private-key",
                "protect-jwt",
            },
        )

    def test_percentile_uses_nearest_rank(self) -> None:
        self.assertEqual(_percentile([4.0, 1.0, 3.0, 2.0], 50), 2.0)
        self.assertEqual(_percentile([4.0, 1.0, 3.0, 2.0], 99), 4.0)
        with self.assertRaises(ValueError):
            _percentile([], 99)

    def test_consumer_acceptance_recycles_workers_and_closes(self) -> None:
        result = run_acceptance(
            workers=1,
            concurrency=2,
            rounds=1,
            max_tasks_per_child=2,
            max_p99_latency_ms=10_000,
        )

        self.assertEqual(result.scenario_count, 15)
        self.assertEqual(result.safe_scenario_count, 9)
        self.assertEqual(result.protected_scenario_count, 6)
        self.assertEqual(result.sequential_requests, 15)
        self.assertEqual(result.concurrent_requests, 15)
        self.assertGreater(result.p95_latency_ms, 0)
        self.assertGreaterEqual(result.p99_latency_ms, result.p95_latency_ms)
        self.assertEqual(result.final_state, "closed")

    def test_report_contains_aggregates_without_scenario_text(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            with patch(
                "sys.argv",
                [
                    "rc_acceptance.py",
                    "--workers",
                    "1",
                    "--concurrency",
                    "1",
                    "--rounds",
                    "1",
                    "--max-tasks-per-child",
                    "4",
                    "--max-p99-latency-ms",
                    "10000",
                ],
            ):
                main()

        report = output.getvalue()
        self.assertIn("rc_acceptance=passed", report)
        self.assertIn("safe_scenarios=9", report)
        for scenario in _default_scenarios():
            self.assertNotIn(scenario.text, report)

    def test_rejects_invalid_resource_controls(self) -> None:
        for arguments in (
            {"workers": 0},
            {"workers": 2, "concurrency": 1},
            {"rounds": 0},
            {"max_tasks_per_child": 0},
            {"max_p99_latency_ms": float("inf")},
        ):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                run_acceptance(**arguments)


if __name__ == "__main__":
    unittest.main()
