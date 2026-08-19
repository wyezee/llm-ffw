"""First-class asyncio facades over the bounded process firewall core."""

import asyncio
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import cast, TypeVar

from .banned_substring_catalog import BannedSubstringCatalog
from .capabilities import FirewallCapabilities
from .config import RuleScannerConfig
from .facade import (
    Firewall,
    FirewallUnavailableError,
    SanitizationResult,
)
from .ip_address import IPAddressConfig
from .mac_address import MACAddressConfig
from .iban import IBANConfig
from .authorization_header import AuthorizationHeaderConfig
from .connection_string import ConnectionStringConfig
from .email_address import EmailAddressConfig
from .external_resource import ExternalResourceConfig
from .phone_number import PhoneNumberConfig
from .facade_config import FirewallConfig
from .json_output import JSONOutputConfig
from .jwt_token import JWTTokenConfig
from .repetition import RepetitionConfig
from .manager import (
    FirewallManager,
    FirewallManagerState,
)
from .payment_card import PaymentCardConfig
from .policy import BALANCED_POLICY, FirewallPolicy
from .private_key import PrivateKeyConfig
from .process_pool import ProcessPoolState, ProcessScannerPoolConfig
from .secret_catalog import SecretCatalog
from .unsafe_url import UnsafeURLConfig


_T = TypeVar("_T")


async def _await_without_cancelling(
    operation: asyncio.Future[_T],
) -> _T:
    """Await one future without propagating caller cancellation into it."""

    await asyncio.wait((operation,))
    return operation.result()


async def _finish_after_cancellation(
    operation: asyncio.Future[_T],
) -> None:
    """Finish and consume one shielded operation after caller cancellation."""

    while not operation.done():
        try:
            await asyncio.wait((operation,))
        except asyncio.CancelledError:
            continue
        except BaseException:
            break
    try:
        operation.result()
    except BaseException:
        pass


async def _run_blocking(
    function: Callable[..., _T],
    /,
    *args: object,
    **kwargs: object,
) -> _T:
    """Complete one lifecycle transition before propagating cancellation."""

    operation = asyncio.create_task(
        asyncio.to_thread(function, *args, **kwargs)
    )
    try:
        return await _await_without_cancelling(operation)
    except asyncio.CancelledError:
        await _finish_after_cancellation(operation)
        raise


class _AsyncRequestRunner:
    """Run synchronous facade requests without blocking one event loop."""

    def __init__(self, pool_config: ProcessScannerPoolConfig) -> None:
        max_in_flight = pool_config.max_in_flight
        if max_in_flight is None:
            raise RuntimeError("max_in_flight was not initialized")
        self._max_in_flight = max_in_flight
        self._admission_timeout = pool_config.admission_timeout_seconds
        self._executor = ThreadPoolExecutor(
            max_workers=pool_config.max_workers,
            thread_name_prefix="llm-ffw-async",
        )
        self._loop: asyncio.AbstractEventLoop | None = None
        self._capacity: asyncio.BoundedSemaphore | None = None
        self._pending: set[asyncio.Future[object]] = set()
        self._accepting = True
        self._closed = False

    def _bind(self) -> tuple[asyncio.AbstractEventLoop, asyncio.BoundedSemaphore]:
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
            self._capacity = asyncio.BoundedSemaphore(self._max_in_flight)
        elif self._loop is not loop:
            raise RuntimeError("async firewall must remain on one event loop")
        capacity = self._capacity
        if capacity is None:
            raise RuntimeError("async request capacity was not initialized")
        return loop, capacity

    async def _acquire(self, capacity: asyncio.BoundedSemaphore) -> None:
        timeout = self._admission_timeout
        if timeout == 0:
            if capacity.locked():
                raise FirewallUnavailableError("ProcessPoolSaturatedError")
            await capacity.acquire()
            return
        try:
            async with asyncio.timeout(timeout):
                await capacity.acquire()
        except TimeoutError:
            raise FirewallUnavailableError(
                "ProcessPoolSaturatedError"
            ) from None

    async def run(
        self,
        function: Callable[..., _T],
        /,
        *args: object,
        **kwargs: object,
    ) -> _T:
        loop, capacity = self._bind()
        if not self._accepting or self._closed:
            raise FirewallUnavailableError("AsyncFirewallNotAcceptingError")
        await self._acquire(capacity)
        if not self._accepting or self._closed:
            capacity.release()
            raise FirewallUnavailableError("AsyncFirewallNotAcceptingError")
        try:
            future = loop.run_in_executor(
                self._executor,
                partial(function, *args, **kwargs),
            )
        except BaseException:
            capacity.release()
            raise
        tracked = cast(
            asyncio.Future[object], future
        )  # Preserve one invariant for callbacks and draining.
        self._pending.add(tracked)

        def completed(value: asyncio.Future[object]) -> None:
            self._pending.discard(value)
            capacity.release()
            if not value.cancelled():
                value.exception()  # Consume errors after a caller cancellation.

        tracked.add_done_callback(completed)
        return await _await_without_cancelling(future)

    def stop_accepting(self) -> None:
        self._accepting = False

    async def drain(self) -> None:
        if not self._pending:
            return
        self._bind()
        while self._pending:
            pending = tuple(self._pending)
            await asyncio.wait(pending)

    async def shutdown(self) -> None:
        if self._closed:
            return
        self.stop_accepting()
        try:
            await self.drain()
        finally:
            self._closed = True
            await asyncio.to_thread(
                self._executor.shutdown,
                wait=True,
                cancel_futures=True,
            )


class AsyncFirewall:
    """Asyncio facade with bounded admission and synchronous API parity."""

    def __init__(
        self,
        *,
        scanner_config: RuleScannerConfig | None = None,
        pool_config: ProcessScannerPoolConfig | None = None,
        additional_secret_catalog: SecretCatalog | None = None,
        replacement_secret_catalog: SecretCatalog | None = None,
        banned_substring_catalog: BannedSubstringCatalog | None = None,
        json_output_config: JSONOutputConfig | None = None,
        unsafe_url_config: UnsafeURLConfig | None = None,
        external_resource_config: ExternalResourceConfig | None = None,
        ip_address_config: IPAddressConfig | None = None,
        mac_address_config: MACAddressConfig | None = None,
        iban_config: IBANConfig | None = None,
        authorization_header_config: AuthorizationHeaderConfig | None = None,
        connection_string_config: ConnectionStringConfig | None = None,
        email_address_config: EmailAddressConfig | None = None,
        phone_number_config: PhoneNumberConfig | None = None,
        payment_card_config: PaymentCardConfig | None = None,
        private_key_config: PrivateKeyConfig | None = None,
        jwt_token_config: JWTTokenConfig | None = None,
        repetition_config: RepetitionConfig | None = None,
        policy: FirewallPolicy = BALANCED_POLICY,
        request_timeout_seconds: float = 30.0,
    ) -> None:
        resolved_pool_config = (
            pool_config
            if pool_config is not None
            else ProcessScannerPoolConfig()
        )
        self._firewall = Firewall(
            scanner_config=scanner_config,
            pool_config=resolved_pool_config,
            additional_secret_catalog=additional_secret_catalog,
            replacement_secret_catalog=replacement_secret_catalog,
            banned_substring_catalog=banned_substring_catalog,
            json_output_config=json_output_config,
            unsafe_url_config=unsafe_url_config,
            external_resource_config=external_resource_config,
            ip_address_config=ip_address_config,
            mac_address_config=mac_address_config,
            iban_config=iban_config,
            authorization_header_config=authorization_header_config,
            connection_string_config=connection_string_config,
            email_address_config=email_address_config,
            phone_number_config=phone_number_config,
            payment_card_config=payment_card_config,
            private_key_config=private_key_config,
            jwt_token_config=jwt_token_config,
            repetition_config=repetition_config,
            policy=policy,
            request_timeout_seconds=request_timeout_seconds,
        )
        self._requests = _AsyncRequestRunner(resolved_pool_config)
        self._lifecycle_lock = asyncio.Lock()
        self._closed = False

    @classmethod
    def from_config(cls, config: FirewallConfig) -> "AsyncFirewall":
        """Build the async facade from one immutable configuration."""

        if not isinstance(config, FirewallConfig):
            raise TypeError("config must be a FirewallConfig")
        return cls(**config._facade_kwargs())

    @property
    def state(self) -> ProcessPoolState:
        return self._firewall.state

    def capabilities(self) -> FirewallCapabilities:
        """Return immutable capabilities without event-loop work."""

        return self._firewall.capabilities()

    async def start(self) -> "AsyncFirewall":
        """Start and verify worker processes without blocking the event loop."""

        async with self._lifecycle_lock:
            if self._closed:
                raise FirewallUnavailableError("AsyncFirewallNotStartableError")
            await _run_blocking(self._firewall.start)
        return self

    async def sanitize_input(self, text: str) -> str:
        return await self._requests.run(self._firewall.sanitize_input, text)

    async def sanitize_input_result(self, text: str) -> SanitizationResult:
        return await self._requests.run(
            self._firewall.sanitize_input_result,
            text,
        )

    async def sanitize_output(
        self,
        text: str,
        *,
        prompt_context: str | None = None,
    ) -> str:
        return await self._requests.run(
            self._firewall.sanitize_output,
            text,
            prompt_context=prompt_context,
        )

    async def sanitize_output_result(
        self,
        text: str,
        *,
        prompt_context: str | None = None,
    ) -> SanitizationResult:
        return await self._requests.run(
            self._firewall.sanitize_output_result,
            text,
            prompt_context=prompt_context,
        )

    async def _close_impl(
        self,
        operation: Callable[[], None],
        *,
        drain_first: bool,
    ) -> None:
        self._requests.stop_accepting()
        try:
            if drain_first:
                await self._requests.drain()
        finally:
            try:
                await _run_blocking(operation)
            finally:
                await self._requests.shutdown()
                self._closed = True

    async def _finish_lifecycle(
        self,
        operation: Callable[[], None],
        *,
        drain_first: bool,
    ) -> None:
        async with self._lifecycle_lock:
            if self._closed:
                return
            cleanup = asyncio.create_task(
                self._close_impl(operation, drain_first=drain_first)
            )
            try:
                await _await_without_cancelling(cleanup)
            except asyncio.CancelledError:
                await _finish_after_cancellation(cleanup)
                raise

    async def close(self) -> None:
        """Stop admission, drain requests, and close worker processes."""

        await self._finish_lifecycle(
            self._firewall.close,
            drain_first=True,
        )

    async def terminate(self) -> None:
        """Terminate worker processes at a graceful-shutdown deadline."""

        await self._finish_lifecycle(
            self._firewall.terminate,
            drain_first=False,
        )

    async def kill(self) -> None:
        """Kill worker processes at a final hard-stop deadline."""

        await self._finish_lifecycle(
            self._firewall.kill,
            drain_first=False,
        )

    async def __aenter__(self) -> "AsyncFirewall":
        return await self.start()

    async def __aexit__(
        self,
        exc_type: object,
        exc: object,
        traceback: object,
    ) -> None:
        try:
            await self.close()
        except FirewallUnavailableError:
            if exc_type is None:
                raise


class AsyncFirewallManager:
    """Asyncio facade for atomic catalog reloads and draining generations."""

    def __init__(
        self,
        *,
        scanner_config: RuleScannerConfig | None = None,
        pool_config: ProcessScannerPoolConfig | None = None,
        additional_secret_catalog: SecretCatalog | None = None,
        replacement_secret_catalog: SecretCatalog | None = None,
        banned_substring_catalog: BannedSubstringCatalog | None = None,
        json_output_config: JSONOutputConfig | None = None,
        unsafe_url_config: UnsafeURLConfig | None = None,
        external_resource_config: ExternalResourceConfig | None = None,
        ip_address_config: IPAddressConfig | None = None,
        mac_address_config: MACAddressConfig | None = None,
        iban_config: IBANConfig | None = None,
        authorization_header_config: AuthorizationHeaderConfig | None = None,
        connection_string_config: ConnectionStringConfig | None = None,
        email_address_config: EmailAddressConfig | None = None,
        phone_number_config: PhoneNumberConfig | None = None,
        payment_card_config: PaymentCardConfig | None = None,
        private_key_config: PrivateKeyConfig | None = None,
        jwt_token_config: JWTTokenConfig | None = None,
        repetition_config: RepetitionConfig | None = None,
        policy: FirewallPolicy = BALANCED_POLICY,
        request_timeout_seconds: float = 30.0,
    ) -> None:
        resolved_pool_config = (
            pool_config
            if pool_config is not None
            else ProcessScannerPoolConfig()
        )
        self._manager = FirewallManager(
            scanner_config=scanner_config,
            pool_config=resolved_pool_config,
            additional_secret_catalog=additional_secret_catalog,
            replacement_secret_catalog=replacement_secret_catalog,
            banned_substring_catalog=banned_substring_catalog,
            json_output_config=json_output_config,
            unsafe_url_config=unsafe_url_config,
            external_resource_config=external_resource_config,
            ip_address_config=ip_address_config,
            mac_address_config=mac_address_config,
            iban_config=iban_config,
            authorization_header_config=authorization_header_config,
            connection_string_config=connection_string_config,
            email_address_config=email_address_config,
            phone_number_config=phone_number_config,
            payment_card_config=payment_card_config,
            private_key_config=private_key_config,
            jwt_token_config=jwt_token_config,
            repetition_config=repetition_config,
            policy=policy,
            request_timeout_seconds=request_timeout_seconds,
        )
        self._requests = _AsyncRequestRunner(resolved_pool_config)
        self._lifecycle_lock = asyncio.Lock()
        self._closed = False

    @classmethod
    def from_config(
        cls,
        config: FirewallConfig,
    ) -> "AsyncFirewallManager":
        """Build the async manager from one immutable configuration."""

        if not isinstance(config, FirewallConfig):
            raise TypeError("config must be a FirewallConfig")
        return cls(**config._facade_kwargs())

    @property
    def state(self) -> FirewallManagerState:
        return self._manager.state

    def capabilities(self) -> FirewallCapabilities:
        return self._manager.capabilities()

    async def start(self) -> "AsyncFirewallManager":
        async with self._lifecycle_lock:
            if self._closed:
                raise FirewallUnavailableError(
                    "AsyncFirewallManagerNotStartableError"
                )
            await _run_blocking(self._manager.start)
        return self

    async def sanitize_input(self, text: str) -> str:
        return await self._requests.run(self._manager.sanitize_input, text)

    async def sanitize_input_result(self, text: str) -> SanitizationResult:
        return await self._requests.run(
            self._manager.sanitize_input_result,
            text,
        )

    async def sanitize_output(
        self,
        text: str,
        *,
        prompt_context: str | None = None,
    ) -> str:
        return await self._requests.run(
            self._manager.sanitize_output,
            text,
            prompt_context=prompt_context,
        )

    async def sanitize_output_result(
        self,
        text: str,
        *,
        prompt_context: str | None = None,
    ) -> SanitizationResult:
        return await self._requests.run(
            self._manager.sanitize_output_result,
            text,
            prompt_context=prompt_context,
        )

    async def reload(
        self,
        *,
        additional_secret_catalog: SecretCatalog | None = None,
        replacement_secret_catalog: SecretCatalog | None = None,
    ) -> FirewallCapabilities:
        async with self._lifecycle_lock:
            if self._closed:
                raise FirewallUnavailableError(
                    "AsyncFirewallManagerNotReloadableError"
                )
            return await _run_blocking(
                self._manager.reload,
                additional_secret_catalog=additional_secret_catalog,
                replacement_secret_catalog=replacement_secret_catalog,
            )

    async def reload_builtin_catalog(self) -> FirewallCapabilities:
        async with self._lifecycle_lock:
            if self._closed:
                raise FirewallUnavailableError(
                    "AsyncFirewallManagerNotReloadableError"
                )
            return await _run_blocking(
                self._manager.reload_builtin_catalog
            )

    async def restart(self) -> FirewallCapabilities:
        async with self._lifecycle_lock:
            if self._closed:
                raise FirewallUnavailableError(
                    "AsyncFirewallManagerNotReloadableError"
                )
            return await _run_blocking(self._manager.restart)

    async def _close_impl(self) -> None:
        self._requests.stop_accepting()
        try:
            await self._requests.drain()
        finally:
            try:
                await _run_blocking(self._manager.close)
            finally:
                await self._requests.shutdown()
                self._closed = True

    async def close(self) -> None:
        """Stop admission, drain requests, and close every generation."""

        async with self._lifecycle_lock:
            if self._closed:
                return
            cleanup = asyncio.create_task(self._close_impl())
            try:
                await _await_without_cancelling(cleanup)
            except asyncio.CancelledError:
                await _finish_after_cancellation(cleanup)
                raise

    async def __aenter__(self) -> "AsyncFirewallManager":
        return await self.start()

    async def __aexit__(
        self,
        exc_type: object,
        exc: object,
        traceback: object,
    ) -> None:
        try:
            await self.close()
        except FirewallUnavailableError:
            if exc_type is None:
                raise


__all__ = [
    "AsyncFirewall",
    "AsyncFirewallManager",
]
