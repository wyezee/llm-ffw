from concurrent.futures.process import BrokenProcessPool
import os
from threading import Thread
import time
import unittest

from llm_ffw import (
    BUILTIN_SECRET_CATALOG,
    STRICT_POLICY,
    Action,
    RuleEngine,
    ProcessPoolNotRunningError,
    ProcessPoolSaturatedError,
    ProcessPoolState,
    ProcessScannerPool,
    ProcessScannerPoolConfig,
    ScanScope,
    RuleScanner,
    RuleScannerConfig,
)


def _terminate_current_test_worker() -> None:
    os._exit(23)


def _sleep_in_test_worker(seconds: float) -> None:
    time.sleep(seconds)


class ProcessScannerPoolConfigTests(unittest.TestCase):
    def test_default_workers_respect_process_cpu_availability(self) -> None:
        available = os.process_cpu_count() or 1

        self.assertEqual(
            ProcessScannerPoolConfig().max_workers,
            min(4, available),
        )

    def test_defaults_bound_queue_and_recycle_workers(self) -> None:
        config = ProcessScannerPoolConfig(max_workers=2)

        self.assertEqual(config.max_in_flight, 4)
        self.assertEqual(config.max_tasks_per_child, 1_000)
        self.assertEqual(config.admission_timeout_seconds, 0.0)

    def test_rejects_unsafe_resource_values(self) -> None:
        invalid_builders = (
            lambda: ProcessScannerPoolConfig(max_workers=0),
            lambda: ProcessScannerPoolConfig(max_workers=True),
            lambda: ProcessScannerPoolConfig(max_workers=2, max_in_flight=1),
            lambda: ProcessScannerPoolConfig(max_tasks_per_child=0),
            lambda: ProcessScannerPoolConfig(admission_timeout_seconds=-1),
        )
        for builder in invalid_builders:
            with self.subTest(builder=builder), self.assertRaises(
                (TypeError, ValueError)
            ):
                builder()


class ProcessScannerPoolTests(unittest.TestCase):
    def test_default_catalog_is_exposed_as_immutable_configuration(self) -> None:
        pool = ProcessScannerPool(pool_config=ProcessScannerPoolConfig(max_workers=1))

        self.assertIs(pool.secret_catalog, BUILTIN_SECRET_CATALOG)
        pool.shutdown()

    def test_context_starts_scans_and_closes_workers(self) -> None:
        text = "credential=sk-" + "A" * 20
        pool = ProcessScannerPool(
            pool_config=ProcessScannerPoolConfig(
                max_workers=1,
                max_in_flight=1,
                max_tasks_per_child=10,
            )
        )

        self.assertEqual(pool.state, ProcessPoolState.NEW)
        with self.assertRaises(ProcessPoolNotRunningError):
            pool.submit(text)

        with pool:
            self.assertEqual(pool.state, ProcessPoolState.RUNNING)
            findings = pool.scan(text, timeout=10)
            self.assertEqual(findings, RuleScanner().scan(text))
            self.assertNotIn(text, findings[0].message)
            self.assertNotIn(text, tuple(findings[0].metadata.values()))

        self.assertEqual(pool.state, ProcessPoolState.CLOSED)
        pool.shutdown()
        with self.assertRaises(ProcessPoolNotRunningError):
            pool.submit(text)

    def test_bounded_admission_timeout_and_parent_input_limit(self) -> None:
        scanner_config = RuleScannerConfig(max_input_chars=8_000_000)
        pool = ProcessScannerPool(
            scanner_config=scanner_config,
            pool_config=ProcessScannerPoolConfig(
                max_workers=1,
                max_in_flight=1,
                max_tasks_per_child=10,
            ),
        )
        slow_text = "x" * scanner_config.max_input_chars

        with pool:
            with self.assertRaises(TypeError):
                pool.submit("safe", scope="input")  # type: ignore[arg-type]
            with self.assertRaises(ValueError):
                pool.submit("safe", prompt_context="not valid for input")
            with self.assertRaisesRegex(ValueError, "prompt_context"):
                pool.submit(
                    "safe",
                    scope=ScanScope.OUTPUT,
                    prompt_context="x" * (scanner_config.max_input_chars + 1),
                )
            first = pool.submit(slow_text)
            with self.assertRaises(ProcessPoolSaturatedError):
                pool.submit("safe")
            self.assertEqual(first.result(timeout=10), ())

            with self.assertRaises(TimeoutError):
                pool.scan(slow_text, timeout=0)
            self.assertEqual(pool.state, ProcessPoolState.BROKEN)
            with self.assertRaises(ProcessPoolNotRunningError):
                pool.submit("safe")
            with self.assertRaisesRegex(ValueError, "max_input_chars"):
                pool.submit(slow_text + "x")

        self.assertEqual(pool.state, ProcessPoolState.CLOSED)

    def test_output_scope_and_prompt_context_cross_process_boundary(self) -> None:
        value = "sk-" + "P" * 20
        pool = ProcessScannerPool(
            pool_config=ProcessScannerPoolConfig(max_workers=1)
        )

        with pool:
            findings = pool.scan(
                value,
                scope=ScanScope.OUTPUT,
                prompt_context="user prompt",
                timeout=10,
            )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "secrets.detected")
        self.assertNotIn("user prompt", findings[0].message)
        self.assertNotIn("user prompt", tuple(findings[0].metadata.values()))

    def test_default_process_policy_redacts_secrets(self) -> None:
        value = "sk-" + "R" * 20
        pool = ProcessScannerPool(
            pool_config=ProcessScannerPoolConfig(max_workers=1)
        )

        with pool:
            result = pool.process(value, timeout=10)

        self.assertEqual(result.decision, Action.REDACT)
        self.assertEqual(result.processed_text, "[REDACTED]")
        self.assertNotIn(value, result.processed_text or "")

    def test_process_canonicalization_matches_direct_findings_and_spans(self) -> None:
        text = "prefix sk-\u200b" + "H" * 20 + " suffix"
        expected = RuleEngine().process(text)
        pool = ProcessScannerPool(
            pool_config=ProcessScannerPoolConfig(
                max_workers=1,
                max_tasks_per_child=1,
            )
        )

        with pool:
            actual = pool.process(text, timeout=20)

        self.assertEqual(actual, expected)
        self.assertEqual(
            tuple(finding.rule_id for finding in actual.findings),
            ("secrets.detected", "unicode.invisible_characters"),
        )

    def test_strict_block_does_not_stop_process_pool(self) -> None:
        value = "sk-" + "B" * 20
        pool = ProcessScannerPool(
            pool_config=ProcessScannerPoolConfig(max_workers=1),
            policy=STRICT_POLICY,
        )

        with pool:
            blocked = pool.process(value, timeout=10)
            following_request = pool.process("safe", timeout=10)
            self.assertEqual(pool.state, ProcessPoolState.RUNNING)

        self.assertTrue(blocked.blocked)
        self.assertIsNone(blocked.processed_text)
        self.assertEqual(following_request.decision, Action.ALLOW)
        self.assertEqual(following_request.processed_text, "safe")

    def test_abrupt_worker_exit_marks_pool_broken_and_shutdown_recovers(self) -> None:
        pool = ProcessScannerPool(
            pool_config=ProcessScannerPoolConfig(
                max_workers=1,
                max_in_flight=1,
                max_tasks_per_child=10,
            )
        )

        with pool:
            executor = pool._executor
            self.assertIsNotNone(executor)
            if executor is None:  # Satisfy static narrowing after the assertion.
                self.fail("running pool did not have an executor")
            terminated = executor.submit(_terminate_current_test_worker)
            with self.assertRaises(BrokenProcessPool):
                terminated.result(timeout=10)
            with self.assertRaises(BrokenProcessPool):
                pool.submit("safe")
            self.assertEqual(pool.state, ProcessPoolState.BROKEN)

        self.assertEqual(pool.state, ProcessPoolState.CLOSED)

    def test_worker_recycling_preserves_scanning(self) -> None:
        pool = ProcessScannerPool(
            pool_config=ProcessScannerPoolConfig(
                max_workers=1,
                max_in_flight=1,
                max_tasks_per_child=1,
            )
        )

        with pool:
            self.assertEqual(pool.scan("safe", timeout=10), ())
            findings = pool.scan("sk-" + "A" * 20, timeout=10)
            self.assertEqual(len(findings), 1)

        self.assertEqual(pool.state, ProcessPoolState.CLOSED)

    def test_terminate_immediately_closes_workers(self) -> None:
        pool = ProcessScannerPool(
            pool_config=ProcessScannerPoolConfig(max_workers=1)
        ).start()

        pool.terminate()

        self.assertEqual(pool.state, ProcessPoolState.CLOSED)
        pool.terminate()
        with self.assertRaises(ProcessPoolNotRunningError):
            pool.submit("safe")

    def test_kill_immediately_closes_workers(self) -> None:
        pool = ProcessScannerPool(
            pool_config=ProcessScannerPoolConfig(max_workers=1)
        ).start()

        pool.kill()

        self.assertEqual(pool.state, ProcessPoolState.CLOSED)
        pool.kill()
        with self.assertRaises(ProcessPoolNotRunningError):
            pool.submit("safe")

    def test_graceful_shutdown_can_be_escalated_to_terminate(self) -> None:
        pool = ProcessScannerPool(
            pool_config=ProcessScannerPoolConfig(max_workers=1)
        ).start()
        executor = pool._executor
        self.assertIsNotNone(executor)
        if executor is None:
            self.fail("running pool did not have an executor")
        executor.submit(_sleep_in_test_worker, 30.0)
        shutdown_errors: list[BaseException] = []

        def shut_down() -> None:
            try:
                pool.shutdown(cancel_pending=True)
            except BaseException as exc:
                shutdown_errors.append(exc)

        shutdown_thread = Thread(target=shut_down)
        shutdown_thread.start()
        deadline = time.monotonic() + 5.0
        while pool.state is not ProcessPoolState.SHUTTING_DOWN:
            if time.monotonic() >= deadline:
                self.fail("graceful shutdown did not start")
            time.sleep(0.01)

        pool.terminate()
        shutdown_thread.join(timeout=5.0)

        self.assertFalse(shutdown_thread.is_alive())
        self.assertEqual(shutdown_errors, [])
        self.assertEqual(pool.state, ProcessPoolState.CLOSED)


if __name__ == "__main__":
    unittest.main()
