"""Atomic, draining generations for runtime firewall catalog updates."""

from dataclasses import dataclass
from enum import Enum
from threading import Condition, Lock

from .capabilities import FirewallCapabilities
from .banned_substring_catalog import BannedSubstringCatalog
from .config import ScannerConfig
from .facade import FirewallUnavailableError, LLMFirewall
from .json_output import JSONOutputConfig
from .unsafe_url import UnsafeURLConfig
from .payment_card import PaymentCardConfig
from .private_key import PrivateKeyConfig
from .policy import BALANCED_POLICY, FirewallPolicy
from .process_pool import ProcessScannerPoolConfig
from .secret_catalog import BUILTIN_SECRET_CATALOG, SecretCatalog


class FirewallManagerState(str, Enum):
    """Observable lifecycle states for a managed firewall generation."""

    NEW = "new"
    STARTING = "starting"
    RUNNING = "running"
    RELOADING = "reloading"
    CLOSING = "closing"
    CLOSED = "closed"
    BROKEN = "broken"


class FirewallReloadError(RuntimeError):
    """Report a safe reload failure and whether the new generation is active."""

    def __init__(self, *, activated: bool, cause_type: str) -> None:
        super().__init__(
            "firewall generation activated but cleanup failed"
            if activated
            else "firewall generation was not activated"
        )
        self.activated = activated
        self.cause_type = cause_type


@dataclass(slots=True)
class _Generation:
    firewall: LLMFirewall
    in_flight: int = 0


class LLMFirewallManager:
    """Hot-swap immutable firewall generations and drain previous requests."""

    def __init__(
        self,
        *,
        scanner_config: ScannerConfig | None = None,
        pool_config: ProcessScannerPoolConfig | None = None,
        additional_secret_catalog: SecretCatalog | None = None,
        replacement_secret_catalog: SecretCatalog | None = None,
        banned_substring_catalog: BannedSubstringCatalog | None = None,
        json_output_config: JSONOutputConfig | None = None,
        unsafe_url_config: UnsafeURLConfig | None = None,
        payment_card_config: PaymentCardConfig | None = None,
        private_key_config: PrivateKeyConfig | None = None,
        policy: FirewallPolicy = BALANCED_POLICY,
        request_timeout_seconds: float | None = 5.0,
    ) -> None:
        self._scanner_config = scanner_config
        self._pool_config = pool_config
        self._policy = policy
        self._request_timeout_seconds = request_timeout_seconds
        self._banned_substring_catalog = banned_substring_catalog
        self._json_output_config = json_output_config
        self._unsafe_url_config = unsafe_url_config
        self._payment_card_config = payment_card_config
        self._private_key_config = private_key_config
        initial = self._build_firewall(
            additional_secret_catalog=additional_secret_catalog,
            replacement_secret_catalog=replacement_secret_catalog,
        )
        self._condition = Condition(Lock())
        self._lifecycle_lock = Lock()
        self._reload_lock = Lock()
        self._state = FirewallManagerState.NEW
        self._active = _Generation(initial)
        self._retired: list[_Generation] = []

    def _build_firewall(
        self,
        *,
        additional_secret_catalog: SecretCatalog | None,
        replacement_secret_catalog: SecretCatalog | None,
    ) -> LLMFirewall:
        return LLMFirewall(
            scanner_config=self._scanner_config,
            pool_config=self._pool_config,
            additional_secret_catalog=additional_secret_catalog,
            replacement_secret_catalog=replacement_secret_catalog,
            banned_substring_catalog=self._banned_substring_catalog,
            json_output_config=self._json_output_config,
            unsafe_url_config=self._unsafe_url_config,
            payment_card_config=self._payment_card_config,
            private_key_config=self._private_key_config,
            policy=self._policy,
            request_timeout_seconds=self._request_timeout_seconds,
        )

    @property
    def state(self) -> FirewallManagerState:
        with self._condition:
            return self._state

    def capabilities(self) -> FirewallCapabilities:
        """Return the active generation's immutable capability summary."""

        with self._condition:
            return self._active.firewall.capabilities()

    def start(self) -> "LLMFirewallManager":
        """Start the initial generation during application startup."""

        with self._lifecycle_lock:
            with self._condition:
                if self._state in (
                    FirewallManagerState.RUNNING,
                    FirewallManagerState.RELOADING,
                ):
                    return self
                if self._state is not FirewallManagerState.NEW:
                    raise FirewallUnavailableError(
                        "FirewallManagerNotStartableError"
                    )
                self._state = FirewallManagerState.STARTING
                generation = self._active
            try:
                generation.firewall.start()
            except FirewallUnavailableError:
                with self._condition:
                    self._state = FirewallManagerState.BROKEN
                    self._condition.notify_all()
                raise
            with self._condition:
                self._state = FirewallManagerState.RUNNING
                self._condition.notify_all()
        return self

    def reload(
        self,
        *,
        additional_secret_catalog: SecretCatalog | None = None,
        replacement_secret_catalog: SecretCatalog | None = None,
    ) -> FirewallCapabilities:
        """Activate one complete catalog snapshot, then drain the old generation."""

        if (
            additional_secret_catalog is None
            and replacement_secret_catalog is None
        ):
            raise ValueError(
                "reload requires an additional or replacement secret catalog"
            )
        with self._reload_lock:
            return self._reload_locked(
                additional_secret_catalog=additional_secret_catalog,
                replacement_secret_catalog=replacement_secret_catalog,
            )

    def reload_builtin_catalog(self) -> FirewallCapabilities:
        """Return to the package's built-in catalog as a new generation."""

        with self._reload_lock:
            return self._reload_locked(
                additional_secret_catalog=None,
                replacement_secret_catalog=None,
            )

    def _reload_locked(
        self,
        *,
        additional_secret_catalog: SecretCatalog | None,
        replacement_secret_catalog: SecretCatalog | None,
    ) -> FirewallCapabilities:
        with self._condition:
            if self._state is not FirewallManagerState.RUNNING:
                raise FirewallReloadError(
                    activated=False,
                    cause_type="FirewallManagerNotRunningError",
                )
            if self._retired:
                raise FirewallReloadError(
                    activated=False,
                    cause_type="RetiredGenerationCleanupPendingError",
                )
            requested = (
                replacement_secret_catalog
                or additional_secret_catalog
                or BUILTIN_SECRET_CATALOG
            )
            active_catalog = self._active.firewall.capabilities().secret_catalog
            if (
                requested.catalog_id == active_catalog.catalog_id
                and requested.version == active_catalog.version
            ):
                raise FirewallReloadError(
                    activated=False,
                    cause_type="CatalogCoordinateUnchangedError",
                )
            self._state = FirewallManagerState.RELOADING
        candidate: LLMFirewall | None = None
        cause_type: str | None = None
        try:
            candidate = self._build_firewall(
                additional_secret_catalog=additional_secret_catalog,
                replacement_secret_catalog=replacement_secret_catalog,
            )
            candidate.start()
        except Exception as exc:
            cause_type = self._safe_cause_type(exc)
        if cause_type is not None:
            if candidate is not None:
                self._discard_candidate(candidate)
            with self._condition:
                if self._state is FirewallManagerState.RELOADING:
                    self._state = FirewallManagerState.RUNNING
                self._condition.notify_all()
            raise FirewallReloadError(
                activated=False,
                cause_type=cause_type,
            )
        if candidate is None:
            raise FirewallReloadError(
                activated=False,
                cause_type="InternalReloadError",
            )
        return self._activate_and_drain(candidate)

    def _activate_and_drain(
        self,
        candidate: LLMFirewall,
    ) -> FirewallCapabilities:
        closing = False
        with self._condition:
            if self._state is not FirewallManagerState.RELOADING:
                closing = True
            else:
                previous = self._active
                current = _Generation(candidate)
                self._active = current
                self._retired.append(previous)
                self._state = FirewallManagerState.RUNNING
                self._condition.notify_all()
                while (
                    previous.in_flight
                    and self._state is FirewallManagerState.RUNNING
                ):
                    self._condition.wait()
        if closing:
            self._discard_candidate(candidate)
            raise FirewallReloadError(
                activated=False,
                cause_type="FirewallManagerClosingError",
            )
        cleanup_error: FirewallUnavailableError | None = None
        with self._condition:
            manager_running = self._state is FirewallManagerState.RUNNING
        if manager_running:
            try:
                previous.firewall.close()
            except FirewallUnavailableError as exc:
                cleanup_error = exc
            else:
                with self._condition:
                    if previous in self._retired:
                        self._retired.remove(previous)
        if cleanup_error is not None:
            raise FirewallReloadError(
                activated=True,
                cause_type=cleanup_error.cause_type,
            ) from None
        return current.firewall.capabilities()

    def sanitize_input(self, text: str) -> str:
        """Sanitize input using one leased immutable generation."""

        generation = self._acquire_generation()
        try:
            return generation.firewall.sanitize_input(text)
        finally:
            self._release_generation(generation)

    def sanitize_output(
        self,
        text: str,
        *,
        prompt_context: str | None = None,
    ) -> str:
        """Sanitize output using one leased immutable generation."""

        generation = self._acquire_generation()
        try:
            return generation.firewall.sanitize_output(
                text,
                prompt_context=prompt_context,
            )
        finally:
            self._release_generation(generation)

    def _acquire_generation(self) -> _Generation:
        with self._condition:
            if self._state not in (
                FirewallManagerState.RUNNING,
                FirewallManagerState.RELOADING,
            ):
                raise FirewallUnavailableError(
                    "FirewallManagerNotRunningError"
                )
            generation = self._active
            generation.in_flight += 1
            return generation

    def _release_generation(self, generation: _Generation) -> None:
        with self._condition:
            generation.in_flight -= 1
            if generation.in_flight < 0:
                self._state = FirewallManagerState.BROKEN
                raise RuntimeError("firewall generation lease underflow")
            self._condition.notify_all()

    def close(self) -> None:
        """Stop admission, drain requests, and close every known generation."""

        with self._reload_lock:
            with self._lifecycle_lock:
                with self._condition:
                    if self._state is FirewallManagerState.CLOSED:
                        return
                    self._state = FirewallManagerState.CLOSING
                    generations = self._all_generations()
                    while any(
                        generation.in_flight for generation in generations
                    ):
                        self._condition.wait()

                failure: FirewallUnavailableError | None = None
                for generation in generations:
                    try:
                        generation.firewall.close()
                    except FirewallUnavailableError as exc:
                        if failure is None:
                            failure = exc
                with self._condition:
                    if failure is None:
                        self._retired.clear()
                        self._state = FirewallManagerState.CLOSED
                    else:
                        self._state = FirewallManagerState.BROKEN
                    self._condition.notify_all()
                if failure is not None:
                    raise failure

    def _all_generations(self) -> tuple[_Generation, ...]:
        values = (self._active, *self._retired)
        unique: list[_Generation] = []
        for generation in values:
            if all(existing is not generation for existing in unique):
                unique.append(generation)
        return tuple(unique)

    @staticmethod
    def _safe_cause_type(exc: Exception) -> str:
        if isinstance(exc, FirewallUnavailableError):
            return exc.cause_type
        if isinstance(exc, (TypeError, ValueError)):
            return type(exc).__name__
        return "InternalReloadError"

    @staticmethod
    def _discard_candidate(candidate: LLMFirewall) -> None:
        try:
            candidate.close()
        except FirewallUnavailableError:
            try:
                candidate.kill()
            except FirewallUnavailableError:
                pass

    def __enter__(self) -> "LLMFirewallManager":
        return self.start()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        try:
            self.close()
        except FirewallUnavailableError:
            if exc_type is None:
                raise


__all__ = [
    "FirewallManagerState",
    "FirewallReloadError",
    "LLMFirewallManager",
]
