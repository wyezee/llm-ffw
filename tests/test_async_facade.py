import asyncio
import string
from threading import Event
import unittest

from llm_ffw import (
    Action,
    AsyncFirewall,
    AsyncFirewallManager,
    ContentBlockedError,
    FirewallManagerState,
    FirewallUnavailableError,
    ProcessPoolState,
    ProcessScannerPoolConfig,
    STRICT_POLICY,
    SecretCatalog,
    SecretSignature,
)


def _pool_config(
    *,
    max_in_flight: int = 2,
    admission_timeout_seconds: float | None = 0,
) -> ProcessScannerPoolConfig:
    return ProcessScannerPoolConfig(
        max_workers=1,
        max_in_flight=max_in_flight,
        max_tasks_per_child=10,
        admission_timeout_seconds=admission_timeout_seconds,
    )


def _additional_catalog() -> SecretCatalog:
    signature = SecretSignature(
        signature_id="acme.async_token",
        provider="acme",
        secret_type="async_token",
        prefixes=("acme_async_",),
        suffix_chars=string.ascii_letters + string.digits,
        min_suffix_chars=16,
        max_suffix_chars=16,
        boundary_chars=string.ascii_letters + string.digits + "_",
        source="internal://security/async-token-format",
    )
    return SecretCatalog(
        catalog_id="acme.async.with_builtins",
        version="3.0.0+async.1",
        signatures=(signature,),
    )


class AsyncLLMFirewallTests(unittest.IsolatedAsyncioTestCase):
    async def test_context_sanitizes_with_structured_sync_parity(self) -> None:
        secret = "sk-" + "A" * 20
        firewall = AsyncFirewall(pool_config=_pool_config())

        self.assertEqual(firewall.state, ProcessPoolState.NEW)
        async with firewall:
            self.assertEqual(firewall.state, ProcessPoolState.RUNNING)
            result = await firewall.sanitize_input_result(
                f"credential={secret}"
            )
            output = await firewall.sanitize_output(
                f"credential={secret}",
                prompt_context="Return a status message.",
            )

            self.assertEqual(result.decision, Action.REDACT)
            self.assertEqual(result.text, "credential=[REDACTED]")
            self.assertEqual(output, "credential=[REDACTED]")
            self.assertNotIn(secret, repr(result))
            self.assertEqual(result.findings[0].rule_id, "secrets.detected")

        self.assertEqual(firewall.state, ProcessPoolState.CLOSED)
        self.assertTrue(firewall._requests._closed)

    async def test_strict_block_does_not_stop_async_firewall(self) -> None:
        secret = "sk-" + "B" * 20
        async with AsyncFirewall(
            pool_config=_pool_config(),
            policy=STRICT_POLICY,
        ) as firewall:
            with self.assertRaises(ContentBlockedError) as caught:
                await firewall.sanitize_input(secret)
            following = await firewall.sanitize_input("safe")

            self.assertEqual(caught.exception.findings[0].action, Action.BLOCK)
            self.assertNotIn(secret, repr(caught.exception))
            self.assertEqual(following, "safe")
            self.assertEqual(firewall.state, ProcessPoolState.RUNNING)

    async def test_cancellation_keeps_capacity_until_running_call_finishes(
        self,
    ) -> None:
        started = Event()
        release = Event()
        firewall = AsyncFirewall(
            pool_config=_pool_config(max_in_flight=1),
        )

        def blocking_sanitize(text: str) -> str:
            started.set()
            if not release.wait(timeout=5):
                raise TimeoutError("test release was not signaled")
            return text

        firewall._firewall.sanitize_input = blocking_sanitize  # type: ignore[method-assign]
        request = asyncio.create_task(firewall.sanitize_input("first"))
        self.assertTrue(await asyncio.to_thread(started.wait, 2))
        request.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await request

        with self.assertRaises(FirewallUnavailableError) as saturated:
            await firewall.sanitize_input("second")
        self.assertEqual(
            saturated.exception.cause_type,
            "ProcessPoolSaturatedError",
        )

        release.set()
        await firewall._requests.drain()
        self.assertEqual(await firewall.sanitize_input("third"), "third")
        await firewall.close()

    async def test_positive_admission_timeout_is_non_blocking(self) -> None:
        started = Event()
        release = Event()
        firewall = AsyncFirewall(
            pool_config=_pool_config(
                max_in_flight=1,
                admission_timeout_seconds=0.02,
            ),
        )

        def blocking_sanitize(text: str) -> str:
            started.set()
            if not release.wait(timeout=5):
                raise TimeoutError("test release was not signaled")
            return text

        firewall._firewall.sanitize_input = blocking_sanitize  # type: ignore[method-assign]
        request = asyncio.create_task(firewall.sanitize_input("first"))
        self.assertTrue(await asyncio.to_thread(started.wait, 2))

        with self.assertRaises(FirewallUnavailableError) as saturated:
            await firewall.sanitize_input("second")
        self.assertEqual(
            saturated.exception.cause_type,
            "ProcessPoolSaturatedError",
        )

        release.set()
        self.assertEqual(await request, "first")
        await firewall.close()

    async def test_start_completes_transition_before_propagating_cancellation(
        self,
    ) -> None:
        started = Event()
        release = Event()
        completed = Event()
        firewall = AsyncFirewall(pool_config=_pool_config())

        def blocking_start() -> object:
            started.set()
            if not release.wait(timeout=5):
                raise TimeoutError("test release was not signaled")
            completed.set()
            return firewall._firewall

        firewall._firewall.start = blocking_start  # type: ignore[method-assign]
        start = asyncio.create_task(firewall.start())
        self.assertTrue(await asyncio.to_thread(started.wait, 2))
        start.cancel()
        await asyncio.sleep(0)
        self.assertFalse(start.done())

        release.set()
        with self.assertRaises(asyncio.CancelledError):
            await start
        self.assertTrue(completed.is_set())
        await firewall.close()

    async def test_cancellation_is_preserved_when_lifecycle_operation_fails(
        self,
    ) -> None:
        started = Event()
        release = Event()
        firewall = AsyncFirewall(pool_config=_pool_config())

        def failing_start() -> object:
            started.set()
            if not release.wait(timeout=5):
                raise TimeoutError("test release was not signaled")
            raise RuntimeError("synthetic lifecycle failure")

        firewall._firewall.start = failing_start  # type: ignore[method-assign]
        starting = asyncio.create_task(firewall.start())
        self.assertTrue(await asyncio.to_thread(started.wait, 2))
        starting.cancel()
        release.set()
        with self.assertRaises(asyncio.CancelledError):
            await starting
        await firewall.close()

    async def test_close_stops_admission_and_drains_running_requests(self) -> None:
        started = Event()
        release = Event()
        firewall = AsyncFirewall(
            pool_config=_pool_config(max_in_flight=1),
        )

        def blocking_sanitize(text: str) -> str:
            started.set()
            if not release.wait(timeout=5):
                raise TimeoutError("test release was not signaled")
            return text

        firewall._firewall.sanitize_input = blocking_sanitize  # type: ignore[method-assign]
        request = asyncio.create_task(firewall.sanitize_input("first"))
        self.assertTrue(await asyncio.to_thread(started.wait, 2))
        closing = asyncio.create_task(firewall.close())
        await asyncio.sleep(0)
        self.assertFalse(closing.done())
        with self.assertRaises(FirewallUnavailableError):
            await firewall.sanitize_input("second")

        release.set()
        self.assertEqual(await request, "first")
        await closing
        self.assertTrue(firewall._requests._closed)

    async def test_rejects_zero_request_timeout_before_startup(self) -> None:
        with self.assertRaisesRegex(ValueError, "positive"):
            AsyncFirewall(
                pool_config=_pool_config(),
                request_timeout_seconds=0,
            )

    async def test_rejects_cross_event_loop_reuse(self) -> None:
        firewall = AsyncFirewall(pool_config=_pool_config())
        self.assertEqual(
            await firewall._requests.run(lambda: "ok"),
            "ok",
        )

        def use_from_new_loop() -> None:
            async def invoke() -> None:
                await firewall.sanitize_input("safe")

            asyncio.run(invoke())

        with self.assertRaisesRegex(RuntimeError, "one event loop"):
            await asyncio.to_thread(use_from_new_loop)
        await firewall.close()

    async def test_close_from_new_loop_still_releases_resources(self) -> None:
        firewall = AsyncFirewall(pool_config=_pool_config())

        def bind_on_temporary_loop() -> None:
            asyncio.run(firewall._requests.run(lambda: None))

        await asyncio.to_thread(bind_on_temporary_loop)
        await firewall.close()
        self.assertTrue(firewall._closed)
        self.assertTrue(firewall._requests._closed)

    async def test_cancelled_close_preserves_cancellation_after_failure(
        self,
    ) -> None:
        started = Event()
        release = Event()
        firewall = AsyncFirewall(pool_config=_pool_config())

        def failing_close() -> None:
            started.set()
            if not release.wait(timeout=5):
                raise TimeoutError("test release was not signaled")
            raise RuntimeError("synthetic close failure")

        firewall._firewall.close = failing_close  # type: ignore[method-assign]
        closing = asyncio.create_task(firewall.close())
        self.assertTrue(await asyncio.to_thread(started.wait, 2))
        closing.cancel()
        release.set()
        with self.assertRaises(asyncio.CancelledError):
            await closing
        self.assertTrue(firewall._closed)
        self.assertTrue(firewall._requests._closed)


class AsyncLLMFirewallManagerTests(unittest.IsolatedAsyncioTestCase):
    async def test_structured_results_match_async_facade_contract(self) -> None:
        secret = "sk-" + "D" * 20
        manager = AsyncFirewallManager(pool_config=_pool_config())

        async with manager:
            input_result = await manager.sanitize_input_result(secret)
            output_result = await manager.sanitize_output_result(
                secret,
                prompt_context="Return a status message.",
            )

            self.assertEqual(input_result.text, "[REDACTED]")
            self.assertEqual(output_result.text, "[REDACTED]")
            self.assertNotIn(secret, repr(input_result))

    async def test_reload_and_restart_preserve_async_service(self) -> None:
        custom = "acme_async_" + "C" * 16
        manager = AsyncFirewallManager(pool_config=_pool_config())

        async with manager:
            self.assertEqual(manager.state, FirewallManagerState.RUNNING)
            capabilities = await manager.reload(
                additional_secret_catalog=_additional_catalog()
            )
            sanitized = await manager.sanitize_input(custom)
            restarted = await manager.restart()

            self.assertEqual(capabilities.secret_catalog.signature_count, 29)
            self.assertEqual(sanitized, "[REDACTED]")
            self.assertEqual(restarted.secret_catalog.signature_count, 29)
            self.assertEqual(manager.state, FirewallManagerState.RUNNING)

        self.assertEqual(manager.state, FirewallManagerState.CLOSED)
        self.assertTrue(manager._requests._closed)

    async def test_close_from_new_loop_still_releases_resources(self) -> None:
        manager = AsyncFirewallManager(pool_config=_pool_config())

        def bind_on_temporary_loop() -> None:
            asyncio.run(manager._requests.run(lambda: None))

        await asyncio.to_thread(bind_on_temporary_loop)
        await manager.close()
        self.assertTrue(manager._closed)
        self.assertTrue(manager._requests._closed)


if __name__ == "__main__":
    unittest.main()
