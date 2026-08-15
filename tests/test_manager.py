import string
from threading import Event, Thread
import time
import unittest

from benchmarks.bench_manager_reload import run_manager_reload_gate
from llm_ffw import (
    FirewallManagerState,
    FirewallReloadError,
    FirewallUnavailableError,
    LLMFirewallManager,
    ProcessScannerPoolConfig,
    SecretCatalog,
    SecretSignature,
)


def _pool_config() -> ProcessScannerPoolConfig:
    return ProcessScannerPoolConfig(
        max_workers=1,
        max_in_flight=1,
        max_tasks_per_child=2,
    )


def _additional_catalog() -> SecretCatalog:
    return SecretCatalog(
        catalog_id="acme.secrets.with_llm_ffw_builtins",
        version="3.0.0+acme.2",
        signatures=(
            SecretSignature(
                signature_id="acme.token.service",
                provider="acme",
                secret_type="service_token",
                prefixes=("acme_live_",),
                suffix_chars=string.ascii_letters + string.digits,
                min_suffix_chars=12,
                max_suffix_chars=12,
                boundary_chars=string.ascii_letters + string.digits + "_",
                source="internal://security/acme-service-token",
            ),
        ),
    )


class LLMFirewallManagerTests(unittest.TestCase):
    def test_small_reload_stress_gate_accounts_for_every_result(self) -> None:
        result = run_manager_reload_gate(
            size=100_000,
            workers=1,
            concurrency=2,
            reloads=2,
            min_requests=4,
            max_tasks_per_child=4,
            timeout=60,
            sample_interval_seconds=0.005,
        )

        self.assertGreaterEqual(result.traffic_requests, 4)
        self.assertEqual(result.reload_probe_requests, 2)
        self.assertEqual(
            result.builtin_generation_requests
            + result.extended_generation_requests,
            result.traffic_requests + result.reload_probe_requests,
        )
        self.assertTrue(result.rollback_preserved)
        self.assertTrue(result.shutdown_during_reload)
        self.assertGreater(result.peak_tree_rss_mib, 0)

    def test_context_manages_initial_generation(self) -> None:
        manager = LLMFirewallManager(pool_config=_pool_config())
        value = "sk-" + "A" * 20

        self.assertEqual(manager.state, FirewallManagerState.NEW)
        self.assertEqual(manager.capabilities().secret_catalog.version, "3.0.0")
        with self.assertRaises(FirewallUnavailableError):
            manager.sanitize_input(value)

        with manager:
            self.assertEqual(manager.state, FirewallManagerState.RUNNING)
            self.assertEqual(manager.sanitize_input(value), "[REDACTED]")

        self.assertEqual(manager.state, FirewallManagerState.CLOSED)

    def test_reload_extension_and_return_to_builtins(self) -> None:
        custom = "acme_live_" + "A" * 12
        builtin = "sk-" + "A" * 20
        manager = LLMFirewallManager(pool_config=_pool_config()).start()
        try:
            capabilities = manager.reload(
                additional_secret_catalog=_additional_catalog()
            )

            self.assertEqual(capabilities.secret_catalog.signature_count, 29)
            self.assertEqual(manager.sanitize_input(custom), "[REDACTED]")
            self.assertEqual(manager.sanitize_output(builtin), "[REDACTED]")

            with self.assertRaises(FirewallReloadError) as unchanged:
                manager.reload(
                    additional_secret_catalog=_additional_catalog()
                )
            self.assertEqual(
                unchanged.exception.cause_type,
                "CatalogCoordinateUnchangedError",
            )

            restored = manager.reload_builtin_catalog()
            self.assertEqual(restored.secret_catalog.signature_count, 28)
            self.assertEqual(manager.sanitize_input(custom), custom)
            self.assertEqual(manager.sanitize_input(builtin), "[REDACTED]")
        finally:
            manager.close()

    def test_explicit_replacement_removes_builtins(self) -> None:
        custom = "acme_live_" + "A" * 12
        builtin = "sk-" + "A" * 20
        manager = LLMFirewallManager(pool_config=_pool_config()).start()
        try:
            capabilities = manager.reload(
                replacement_secret_catalog=_additional_catalog()
            )

            self.assertEqual(capabilities.secret_catalog.signature_count, 1)
            self.assertEqual(manager.sanitize_input(custom), "[REDACTED]")
            self.assertEqual(manager.sanitize_input(builtin), builtin)
        finally:
            manager.close()

    def test_invalid_candidate_preserves_active_generation(self) -> None:
        nested = SecretCatalog(
            catalog_id="acme.invalid",
            version="1",
            signatures=(
                SecretSignature(
                    signature_id="acme.token.nested",
                    provider="acme",
                    secret_type="service_token",
                    prefixes=("sk-acme-",),
                    suffix_chars=string.ascii_letters + string.digits,
                    min_suffix_chars=12,
                    max_suffix_chars=12,
                    boundary_chars=string.ascii_letters + string.digits + "_-",
                    source="internal://security/nested-token",
                ),
            ),
        )
        builtin = "sk-" + "A" * 20
        manager = LLMFirewallManager(pool_config=_pool_config()).start()
        try:
            with self.assertRaises(FirewallReloadError) as raised:
                manager.reload(additional_secret_catalog=nested)

            error = raised.exception
            self.assertFalse(error.activated)
            self.assertEqual(error.cause_type, "ValueError")
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)
            self.assertEqual(manager.state, FirewallManagerState.RUNNING)
            self.assertEqual(manager.sanitize_input(builtin), "[REDACTED]")
        finally:
            manager.close()

    def test_reload_requires_snapshot_and_running_manager(self) -> None:
        manager = LLMFirewallManager(pool_config=_pool_config())
        with self.assertRaises(ValueError):
            manager.reload()
        with self.assertRaises(FirewallReloadError) as raised:
            manager.reload(additional_secret_catalog=_additional_catalog())
        self.assertFalse(raised.exception.activated)
        self.assertEqual(
            raised.exception.cause_type,
            "FirewallManagerNotRunningError",
        )
        manager.close()

    def test_cleanup_failure_reports_activation_and_blocks_reload(self) -> None:
        manager = LLMFirewallManager(pool_config=_pool_config()).start()
        previous = manager._active.firewall
        original_close = previous.close

        def fail_close() -> None:
            raise FirewallUnavailableError("SyntheticCleanupError")

        previous.close = fail_close  # type: ignore[method-assign]
        try:
            with self.assertRaises(FirewallReloadError) as raised:
                manager.reload(
                    additional_secret_catalog=_additional_catalog()
                )

            error = raised.exception
            self.assertTrue(error.activated)
            self.assertEqual(error.cause_type, "SyntheticCleanupError")
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)
            self.assertEqual(manager.state, FirewallManagerState.RUNNING)

            with self.assertRaises(FirewallReloadError) as pending:
                manager.reload(
                    replacement_secret_catalog=_additional_catalog()
                )
            self.assertFalse(pending.exception.activated)
            self.assertEqual(
                pending.exception.cause_type,
                "RetiredGenerationCleanupPendingError",
            )
        finally:
            previous.close = original_close  # type: ignore[method-assign]
            manager.close()

    def test_reload_switches_new_requests_before_draining_old(self) -> None:
        manager = LLMFirewallManager(pool_config=_pool_config()).start()
        previous = manager._active.firewall
        entered = Event()
        release = Event()
        old_results: list[str] = []
        thread_errors: list[BaseException] = []

        def blocking_sanitize(text: str) -> str:
            entered.set()
            if not release.wait(10):
                raise TimeoutError("test did not release old generation")
            return f"old:{text}"

        previous.sanitize_input = blocking_sanitize  # type: ignore[method-assign]

        def run_old_request() -> None:
            try:
                old_results.append(manager.sanitize_input("request"))
            except BaseException as exc:
                thread_errors.append(exc)

        reload_results: list[object] = []

        def run_reload() -> None:
            try:
                reload_results.append(
                    manager.reload(
                        additional_secret_catalog=_additional_catalog()
                    )
                )
            except BaseException as exc:
                thread_errors.append(exc)

        request_thread = Thread(target=run_old_request)
        reload_thread = Thread(target=run_reload)
        try:
            request_thread.start()
            self.assertTrue(entered.wait(5))
            reload_thread.start()

            deadline = time.monotonic() + 10
            while (
                manager.capabilities().secret_catalog.signature_count != 29
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)

            self.assertEqual(
                manager.capabilities().secret_catalog.signature_count,
                29,
            )
            self.assertTrue(reload_thread.is_alive())
            self.assertEqual(
                manager.sanitize_input("acme_live_" + "A" * 12),
                "[REDACTED]",
            )
        finally:
            release.set()
            request_thread.join(10)
            reload_thread.join(10)
            manager.close()

        self.assertFalse(request_thread.is_alive())
        self.assertFalse(reload_thread.is_alive())
        self.assertEqual(thread_errors, [])
        self.assertEqual(old_results, ["old:request"])
        self.assertEqual(len(reload_results), 1)


if __name__ == "__main__":
    unittest.main()
