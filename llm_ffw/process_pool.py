"""Lifecycle-managed process concurrency for production scanning."""

from concurrent.futures import Future, InvalidStateError, ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
import math
import multiprocessing
import os
from threading import BoundedSemaphore, Lock
import time
from typing import TypeAlias

from ._rule_registry import (
    ConfiguredRuleConfigs,
    REGISTERED_RULE_IDS,
    build_registered_rules,
    normalize_rule_configs,
    registered_rule_capabilities,
    registered_rule_ids,
)
from .config import RuleScannerConfig
from .capabilities import RuleCapability
from .banned_substring_catalog import BannedSubstringCatalog
from .engine import RuleScanner
from .findings import Action, Finding, Severity, Span
from .inspection import ScanScope
from .json_output import JSONOutputConfig
from .ip_address import IPAddressConfig
from .mac_address import MACAddressConfig
from .iban import IBANConfig
from .authorization_header import AuthorizationHeaderConfig
from .connection_string import ConnectionStringConfig
from .email_address import EmailAddressConfig
from .external_resource import ExternalResourceConfig
from .phone_number import PhoneNumberConfig
from .unsafe_url import UnsafeURLConfig
from .payment_card import PaymentCardConfig
from .private_key import PrivateKeyConfig
from .jwt_token import JWTTokenConfig
from .repetition import RepetitionConfig
from .policy import BALANCED_POLICY, FirewallPolicy, FirewallResult, PolicyOverride
from .rules.secrets import SecretsRule
from .rules.base import Rule
from .rules.bidi_control import BidiControlRule
from .rules.invisible_characters import InvisibleCharactersRule
from .rules.unicode_tag_smuggling import UnicodeTagSmugglingRule
from .rules.json_output import JSONOutputRule
from .secret_catalog import BUILTIN_SECRET_CATALOG, SecretCatalog


class ProcessPoolState(str, Enum):
    """Observable lifecycle state of a process scanner pool."""

    NEW = "new"
    STARTING = "starting"
    RUNNING = "running"
    SHUTTING_DOWN = "shutting_down"
    CLOSED = "closed"
    BROKEN = "broken"


class ProcessPoolNotRunningError(RuntimeError):
    """Raised when work is submitted outside the running lifecycle."""


class ProcessPoolSaturatedError(RuntimeError):
    """Raised when the bounded in-flight capacity cannot admit a request."""


def _available_cpu_count() -> int:
    """Return CPUs available to this process, including quota restrictions."""

    return os.process_cpu_count() or 1


def _validate_timeout(value: object, field_name: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{field_name} must be numeric or None")
    if value < 0 or not math.isfinite(value):
        raise ValueError(f"{field_name} must be finite and not negative")
    return float(value)


def _validate_admission_timeout(value: object, field_name: str) -> float:
    timeout = _validate_timeout(value, field_name)
    if timeout is None:
        raise TypeError(f"{field_name} must be numeric")
    return timeout


@dataclass(frozen=True, slots=True)
class ProcessScannerPoolConfig:
    """Resource, recycling, and admission controls for worker processes."""

    max_workers: int = min(4, _available_cpu_count())
    max_in_flight: int | None = None
    max_tasks_per_child: int | None = 1_000
    admission_timeout_seconds: float = 0.0

    def __post_init__(self) -> None:
        if isinstance(self.max_workers, bool) or not isinstance(self.max_workers, int):
            raise TypeError("max_workers must be an integer")
        if self.max_workers <= 0:
            raise ValueError("max_workers must be positive")
        if os.name == "nt" and self.max_workers > 61:
            raise ValueError("max_workers must not exceed 61 on Windows")

        max_in_flight = self.max_in_flight
        if max_in_flight is None:
            max_in_flight = self.max_workers * 2
            object.__setattr__(self, "max_in_flight", max_in_flight)
        if isinstance(max_in_flight, bool) or not isinstance(max_in_flight, int):
            raise TypeError("max_in_flight must be an integer or None")
        if max_in_flight < self.max_workers:
            raise ValueError("max_in_flight must be at least max_workers")

        tasks = self.max_tasks_per_child
        if tasks is not None:
            if isinstance(tasks, bool) or not isinstance(tasks, int):
                raise TypeError("max_tasks_per_child must be an integer or None")
            if tasks <= 0:
                raise ValueError("max_tasks_per_child must be positive")

        object.__setattr__(
            self,
            "admission_timeout_seconds",
            _validate_admission_timeout(
                self.admission_timeout_seconds,
                "admission_timeout_seconds",
            ),
        )


_SerializedMetadata: TypeAlias = tuple[tuple[str, str], ...]
_SerializedFinding: TypeAlias = tuple[
    str,
    str,
    str,
    int,
    int,
    str,
    str | None,
    _SerializedMetadata,
]

_WORKER_SCANNER: RuleScanner | None = None
_WORKER_POLICY: FirewallPolicy | None = None


def _initialize_worker(
    scanner_config: RuleScannerConfig,
    secret_catalog: SecretCatalog | None,
    configured_rule_configs: ConfiguredRuleConfigs,
    policy_id: str,
    policy_version: str,
    policy_overrides: tuple[PolicyOverride, ...],
) -> None:
    global _WORKER_POLICY, _WORKER_SCANNER
    _WORKER_POLICY = FirewallPolicy(policy_id, policy_version, policy_overrides)
    if secret_catalog is None and not configured_rule_configs:
        _WORKER_SCANNER = RuleScanner(config=scanner_config)
    else:
        rules: list[Rule] = [
            SecretsRule(secret_catalog or BUILTIN_SECRET_CATALOG)
        ]
        if scanner_config.enable_bidi_controls:
            rules.append(BidiControlRule())
        if scanner_config.enable_invisible_characters:
            rules.append(InvisibleCharactersRule())
        if scanner_config.enable_unicode_tag_smuggling:
            rules.append(UnicodeTagSmugglingRule())
        rules.extend(build_registered_rules(configured_rule_configs))
        _WORKER_SCANNER = RuleScanner(
            rules=rules,
            config=scanner_config,
        )


def _worker_ready(_: int) -> bool:
    return _WORKER_SCANNER is not None


def _scan_in_worker(
    text: str,
    scope: ScanScope,
    prompt_context: str | None,
) -> tuple[_SerializedFinding, ...]:
    if _WORKER_SCANNER is None:
        raise RuntimeError("scanner worker was not initialized")
    return _serialize_findings(
        _WORKER_SCANNER.scan(
            text,
            scope=scope,
            prompt_context=prompt_context,
        )
    )


def _serialize_findings(
    findings: tuple[Finding, ...],
) -> tuple[_SerializedFinding, ...]:
    return tuple(
        (
            finding.rule_id,
            finding.severity.value,
            finding.action.value,
            finding.span.start,
            finding.span.end,
            finding.message,
            finding.redacted_preview,
            tuple(finding.metadata.items()),
        )
        for finding in findings
    )


def _scan_for_policy_in_worker(
    text: str,
    scope: ScanScope,
    prompt_context: str | None,
) -> tuple[_SerializedFinding, ...]:
    if _WORKER_SCANNER is None or _WORKER_POLICY is None:
        raise RuntimeError("scanner worker was not initialized")
    if not _WORKER_SCANNER._supports_staged_canonicalization:
        return _serialize_findings(
            _WORKER_SCANNER.scan(
                text,
                scope=scope,
                prompt_context=prompt_context,
            )
        )
    canonical = _WORKER_SCANNER._scan_canonicalizers(
        text,
        scope=scope,
        prompt_context=prompt_context,
    )
    actions = tuple(
        _WORKER_POLICY.action_for(finding, scope) for finding in canonical
    )
    if Action.BLOCK not in actions and Action.REMOVE in actions:
        findings = canonical
    else:
        findings = tuple(
            sorted(
                (
                    *canonical,
                    *_WORKER_SCANNER._scan_remaining(
                        text,
                        scope=scope,
                        prompt_context=prompt_context,
                    ),
                ),
                key=lambda finding: (
                    finding.span.start,
                    finding.span.end,
                    finding.rule_id,
                    tuple(sorted(finding.metadata.items())),
                ),
            )
        )
    return _serialize_findings(findings)


def _deserialize_findings(
    values: tuple[_SerializedFinding, ...],
) -> tuple[Finding, ...]:
    return tuple(
        Finding(
            rule_id=rule_id,
            severity=Severity(severity),
            action=Action(action),
            span=Span(start, end),
            message=message,
            redacted_preview=redacted_preview,
            metadata=dict(metadata),
        )
        for (
            rule_id,
            severity,
            action,
            start,
            end,
            message,
            redacted_preview,
            metadata,
        ) in values
    )


class ProcessScannerPool:
    """Bounded, reusable process pool with explicit startup and shutdown."""

    def __init__(
        self,
        *,
        scanner_config: RuleScannerConfig | None = None,
        pool_config: ProcessScannerPoolConfig | None = None,
        secret_catalog: SecretCatalog | None = None,
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
    ) -> None:
        if scanner_config is not None and not isinstance(scanner_config, RuleScannerConfig):
            raise TypeError("scanner_config must be a RuleScannerConfig or None")
        if pool_config is not None and not isinstance(
            pool_config, ProcessScannerPoolConfig
        ):
            raise TypeError(
                "pool_config must be a ProcessScannerPoolConfig or None"
            )
        if secret_catalog is not None and not isinstance(
            secret_catalog, SecretCatalog
        ):
            raise TypeError("secret_catalog must be a SecretCatalog or None")
        normalize_rule_configs(
            (
                ("banned_substring_catalog", banned_substring_catalog),
                ("json_output_config", json_output_config),
                ("unsafe_url_config", unsafe_url_config),
                ("external_resource_config", external_resource_config),
                ("ip_address_config", ip_address_config),
                ("mac_address_config", mac_address_config),
                ("iban_config", iban_config),
                ("authorization_header_config", authorization_header_config),
                ("connection_string_config", connection_string_config),
                ("email_address_config", email_address_config),
                ("phone_number_config", phone_number_config),
                ("payment_card_config", payment_card_config),
                ("private_key_config", private_key_config),
                ("jwt_token_config", jwt_token_config),
                ("repetition_config", repetition_config),
            )
        )
        if not isinstance(policy, FirewallPolicy):
            raise TypeError("policy must be a FirewallPolicy")
        resolved_scanner_config = scanner_config or RuleScannerConfig()
        if (
            not resolved_scanner_config.enable_payment_cards
            and payment_card_config is not None
        ):
            raise ValueError(
                "payment_card_config requires enable_payment_cards=True"
            )
        resolved_payment_card_config = (
            (payment_card_config or PaymentCardConfig())
            if resolved_scanner_config.enable_payment_cards
            else None
        )
        if (
            not resolved_scanner_config.enable_private_keys
            and private_key_config is not None
        ):
            raise ValueError(
                "private_key_config requires enable_private_keys=True"
            )
        resolved_private_key_config = (
            (private_key_config or PrivateKeyConfig())
            if resolved_scanner_config.enable_private_keys
            else None
        )
        if (
            not resolved_scanner_config.enable_jwt_tokens
            and jwt_token_config is not None
        ):
            raise ValueError(
                "jwt_token_config requires enable_jwt_tokens=True"
            )
        resolved_jwt_token_config = (
            (jwt_token_config or JWTTokenConfig())
            if resolved_scanner_config.enable_jwt_tokens
            else None
        )
        configured_rule_configs = normalize_rule_configs(
            (
                ("banned_substring_catalog", banned_substring_catalog),
                ("json_output_config", json_output_config),
                ("unsafe_url_config", unsafe_url_config),
                ("external_resource_config", external_resource_config),
                ("ip_address_config", ip_address_config),
                ("mac_address_config", mac_address_config),
                ("iban_config", iban_config),
                ("authorization_header_config", authorization_header_config),
                ("connection_string_config", connection_string_config),
                ("email_address_config", email_address_config),
                ("phone_number_config", phone_number_config),
                ("payment_card_config", resolved_payment_card_config),
                ("private_key_config", resolved_private_key_config),
                ("jwt_token_config", resolved_jwt_token_config),
                ("repetition_config", repetition_config),
            )
        )
        active_rule_ids = {"secrets.detected"}
        if resolved_scanner_config.enable_bidi_controls:
            active_rule_ids.add("unicode.bidi_controls")
        if resolved_scanner_config.enable_invisible_characters:
            active_rule_ids.add("unicode.invisible_characters")
        if resolved_scanner_config.enable_unicode_tag_smuggling:
            active_rule_ids.add("unicode.tag_smuggling")
        active_rule_ids.update(registered_rule_ids(configured_rule_configs))
        policy.validate_rule_ids(
            frozenset(active_rule_ids),
            supported_rule_ids=REGISTERED_RULE_IDS
            | frozenset(
                {
                    "secrets.detected",
                    "unicode.bidi_controls",
                    "unicode.invisible_characters",
                    "unicode.tag_smuggling",
                }
            ),
        )
        self._scanner_config = resolved_scanner_config
        self._pool_config = pool_config or ProcessScannerPoolConfig()
        self._configured_secret_catalog = secret_catalog
        self._secret_catalog = secret_catalog or BUILTIN_SECRET_CATALOG
        self._banned_substring_catalog = banned_substring_catalog
        self._json_output_config = json_output_config
        self._unsafe_url_config = unsafe_url_config
        self._external_resource_config = external_resource_config
        self._ip_address_config = ip_address_config
        self._mac_address_config = mac_address_config
        self._iban_config = iban_config
        self._authorization_header_config = authorization_header_config
        self._connection_string_config = connection_string_config
        self._email_address_config = email_address_config
        self._phone_number_config = phone_number_config
        self._payment_card_config = resolved_payment_card_config
        self._private_key_config = resolved_private_key_config
        self._jwt_token_config = resolved_jwt_token_config
        self._repetition_config = repetition_config
        self._configured_rule_configs = configured_rule_configs
        self._json_output_rule = (
            JSONOutputRule(json_output_config)
            if json_output_config is not None
            else None
        )
        self._policy = policy
        self._state = ProcessPoolState.NEW
        self._state_lock = Lock()
        self._lifecycle_lock = Lock()
        max_in_flight = self._pool_config.max_in_flight
        if max_in_flight is None:
            raise RuntimeError("max_in_flight was not initialized")
        self._capacity = BoundedSemaphore(max_in_flight)
        self._executor: ProcessPoolExecutor | None = None

    @property
    def state(self) -> ProcessPoolState:
        with self._state_lock:
            return self._state

    @property
    def pool_config(self) -> ProcessScannerPoolConfig:
        return self._pool_config

    @property
    def scanner_config(self) -> RuleScannerConfig:
        return self._scanner_config

    @property
    def policy(self) -> FirewallPolicy:
        return self._policy

    @property
    def secret_catalog(self) -> SecretCatalog:
        return self._secret_catalog

    @property
    def banned_substring_catalog(self) -> BannedSubstringCatalog | None:
        return self._banned_substring_catalog

    @property
    def json_output_config(self) -> JSONOutputConfig | None:
        return self._json_output_config

    @property
    def unsafe_url_config(self) -> UnsafeURLConfig | None:
        return self._unsafe_url_config

    @property
    def external_resource_config(self) -> ExternalResourceConfig | None:
        return self._external_resource_config

    @property
    def ip_address_config(self) -> IPAddressConfig | None:
        return self._ip_address_config

    @property
    def mac_address_config(self) -> MACAddressConfig | None:
        return self._mac_address_config

    @property
    def iban_config(self) -> IBANConfig | None:
        return self._iban_config

    @property
    def authorization_header_config(
        self,
    ) -> AuthorizationHeaderConfig | None:
        return self._authorization_header_config

    @property
    def connection_string_config(
        self,
    ) -> ConnectionStringConfig | None:
        return self._connection_string_config

    @property
    def email_address_config(self) -> EmailAddressConfig | None:
        return self._email_address_config

    @property
    def phone_number_config(self) -> PhoneNumberConfig | None:
        return self._phone_number_config

    @property
    def payment_card_config(self) -> PaymentCardConfig | None:
        return self._payment_card_config

    @property
    def private_key_config(self) -> PrivateKeyConfig | None:
        return self._private_key_config

    @property
    def jwt_token_config(self) -> JWTTokenConfig | None:
        return self._jwt_token_config

    @property
    def repetition_config(self) -> RepetitionConfig | None:
        return self._repetition_config

    def _registered_rule_capabilities(self) -> tuple[RuleCapability, ...]:
        """Return safe generic capabilities for internal facade assembly."""

        return registered_rule_capabilities(self._configured_rule_configs)

    def start(self) -> "ProcessScannerPool":
        """Start workers and validate process execution before accepting traffic."""

        executor: ProcessPoolExecutor | None = None
        with self._lifecycle_lock:
            with self._state_lock:
                if self._state is not ProcessPoolState.NEW:
                    raise ProcessPoolNotRunningError(
                        f"pool cannot start from state {self._state.value}"
                    )
                self._state = ProcessPoolState.STARTING
            try:
                executor = ProcessPoolExecutor(
                    max_workers=self._pool_config.max_workers,
                    mp_context=multiprocessing.get_context("spawn"),
                    initializer=_initialize_worker,
                    initargs=(
                        self._scanner_config,
                        self._configured_secret_catalog,
                        self._configured_rule_configs,
                        self._policy.policy_id,
                        self._policy.version,
                        self._policy.overrides,
                    ),
                    max_tasks_per_child=self._pool_config.max_tasks_per_child,
                )
                with self._state_lock:
                    self._executor = executor
                readiness = tuple(
                    executor.map(
                        _worker_ready,
                        range(self._pool_config.max_workers),
                        chunksize=1,
                    )
                )
                if not all(readiness):
                    raise RuntimeError("one or more scanner workers failed readiness")
                with self._state_lock:
                    self._state = ProcessPoolState.RUNNING
            except BaseException:
                with self._state_lock:
                    self._state = ProcessPoolState.BROKEN
                if executor is not None:
                    executor.shutdown(wait=True, cancel_futures=True)
                with self._state_lock:
                    if self._executor is executor:
                        self._executor = None
                raise
        return self

    def submit(
        self,
        text: str,
        *,
        scope: ScanScope = ScanScope.INPUT,
        prompt_context: str | None = None,
        admission_timeout: float | None = None,
    ) -> Future[tuple[Finding, ...]]:
        """Admit one bounded request and return a future containing safe findings."""

        return self._submit(
            text,
            scope=scope,
            prompt_context=prompt_context,
            admission_timeout=admission_timeout,
            worker_function=_scan_in_worker,
        )

    def _submit(
        self,
        text: str,
        *,
        scope: ScanScope,
        prompt_context: str | None,
        admission_timeout: float | None,
        worker_function: Callable[
            [str, ScanScope, str | None], tuple[_SerializedFinding, ...]
        ],
    ) -> Future[tuple[Finding, ...]]:
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        if len(text) > self._scanner_config.max_input_chars:
            raise ValueError(
                f"input exceeds max_input_chars={self._scanner_config.max_input_chars}"
            )
        if not isinstance(scope, ScanScope):
            raise TypeError("scope must be a ScanScope")
        if prompt_context is not None and not isinstance(prompt_context, str):
            raise TypeError("prompt_context must be a string or None")
        if scope is ScanScope.INPUT and prompt_context is not None:
            raise ValueError("prompt_context is only valid for output scans")
        if (
            isinstance(prompt_context, str)
            and len(prompt_context) > self._scanner_config.max_input_chars
        ):
            raise ValueError(
                "prompt_context exceeds "
                f"max_input_chars={self._scanner_config.max_input_chars}"
            )
        with self._state_lock:
            if self._state is not ProcessPoolState.RUNNING:
                raise ProcessPoolNotRunningError(
                    f"pool is not accepting work in state {self._state.value}"
                )
        timeout = _validate_admission_timeout(
            self._pool_config.admission_timeout_seconds
            if admission_timeout is None
            else admission_timeout,
            "admission_timeout",
        )
        if not self._capacity.acquire(timeout=timeout):
            raise ProcessPoolSaturatedError("process scanner pool is saturated")

        try:
            with self._state_lock:
                if self._state is not ProcessPoolState.RUNNING:
                    raise ProcessPoolNotRunningError(
                        f"pool is not accepting work in state {self._state.value}"
                    )
                if self._executor is None:
                    raise RuntimeError("running pool has no executor")
                raw_future = self._executor.submit(
                    worker_function,
                    text,
                    scope,
                    prompt_context,
                )
        except BaseException as exc:
            if isinstance(exc, BrokenProcessPool):
                with self._state_lock:
                    if self._state is ProcessPoolState.RUNNING:
                        self._state = ProcessPoolState.BROKEN
            self._capacity.release()
            raise

        result_future: Future[tuple[Finding, ...]] = Future()

        def complete(completed: Future[tuple[_SerializedFinding, ...]]) -> None:
            values: tuple[Finding, ...] | None = None
            exception: BaseException | None = None
            cancelled = completed.cancelled()
            try:
                if not cancelled:
                    values = _deserialize_findings(completed.result())
            except BaseException as exc:
                exception = exc
                if isinstance(exc, BrokenProcessPool):
                    with self._state_lock:
                        if self._state is ProcessPoolState.RUNNING:
                            self._state = ProcessPoolState.BROKEN
            finally:
                self._capacity.release()
            if cancelled:
                result_future.cancel()
            elif not result_future.cancelled():
                try:
                    if exception is not None:
                        result_future.set_exception(exception)
                    elif values is not None:
                        result_future.set_result(values)
                except InvalidStateError:
                    pass  # A caller cancelled between the state check and publish.

        def propagate_cancellation(completed: Future[tuple[Finding, ...]]) -> None:
            if completed.cancelled():
                raw_future.cancel()

        raw_future.add_done_callback(complete)
        result_future.add_done_callback(propagate_cancellation)
        return result_future

    def scan(
        self,
        text: str,
        *,
        scope: ScanScope = ScanScope.INPUT,
        prompt_context: str | None = None,
        timeout: float | None = None,
        admission_timeout: float | None = None,
    ) -> tuple[Finding, ...]:
        """Submit and synchronously await one scan request."""

        validated_timeout = _validate_timeout(timeout, "timeout")
        future = self.submit(
            text,
            scope=scope,
            prompt_context=prompt_context,
            admission_timeout=admission_timeout,
        )
        try:
            return future.result(timeout=validated_timeout)
        except TimeoutError:
            future.cancel()
            self._break_timed_out_generation()
            raise

    def _scan_for_policy(
        self,
        text: str,
        *,
        scope: ScanScope,
        prompt_context: str | None,
        timeout: float | None,
        admission_timeout: float | None,
    ) -> tuple[Finding, ...]:
        future = self._submit(
            text,
            scope=scope,
            prompt_context=prompt_context,
            admission_timeout=admission_timeout,
            worker_function=_scan_for_policy_in_worker,
        )
        try:
            return future.result(timeout=timeout)
        except TimeoutError:
            future.cancel()
            self._break_timed_out_generation()
            raise

    def _break_timed_out_generation(self) -> None:
        """Stop all work in a generation that missed its request deadline."""

        executor: ProcessPoolExecutor | None = None
        with self._lifecycle_lock:
            with self._state_lock:
                if self._state is not ProcessPoolState.RUNNING:
                    return
                executor = self._executor
                self._executor = None
                self._state = ProcessPoolState.BROKEN
            if executor is not None:
                # Python 3.14 force-shutdown is non-blocking: it cancels queued
                # work and signals every live worker. Completion callbacks then
                # release their admission slots.
                try:
                    executor.terminate_workers()
                except BaseException:
                    # The pool is already quarantined as BROKEN. Preserve the
                    # request's TimeoutError rather than exposing cleanup detail.
                    pass

    def process(
        self,
        text: str,
        *,
        scope: ScanScope = ScanScope.INPUT,
        prompt_context: str | None = None,
        timeout: float | None = None,
        admission_timeout: float | None = None,
    ) -> FirewallResult:
        """Scan in a worker and enforce parent-side policy on the request."""

        validated_timeout = _validate_timeout(timeout, "timeout")
        started = time.monotonic()
        findings = self._scan_for_policy(
            text,
            scope=scope,
            prompt_context=prompt_context,
            timeout=validated_timeout,
            admission_timeout=admission_timeout,
        )

        def rescan(cleaned: str) -> tuple[Finding, ...]:
            remaining = (
                None
                if validated_timeout is None
                else max(
                    0.0,
                    validated_timeout - (time.monotonic() - started),
                )
            )
            return self.scan(
                cleaned,
                scope=scope,
                prompt_context=prompt_context,
                timeout=remaining,
                admission_timeout=admission_timeout,
            )

        result = self._policy.apply_with_rescan(
            text,
            findings,
            scope=scope,
            redaction_text=self._scanner_config.redaction_text,
            rescan=rescan,
        )
        return self._policy.enforce_json_postcondition(
            text,
            result,
            validator=self._json_output_rule,
            redaction_text=self._scanner_config.redaction_text,
        )

    def shutdown(
        self,
        *,
        cancel_pending: bool = False,
    ) -> None:
        """Stop admission, optionally cancel queued work, and release workers."""

        with self._lifecycle_lock:
            with self._state_lock:
                if self._state is ProcessPoolState.CLOSED:
                    return
                if self._state is ProcessPoolState.NEW:
                    self._state = ProcessPoolState.CLOSED
                    return
                executor = self._executor
                self._state = ProcessPoolState.SHUTTING_DOWN
        if executor is not None:
            try:
                executor.shutdown(wait=True, cancel_futures=cancel_pending)
            except BaseException:
                with self._state_lock:
                    if self._state is not ProcessPoolState.CLOSED:
                        self._state = ProcessPoolState.BROKEN
                raise
        with self._lifecycle_lock:
            with self._state_lock:
                if self._executor is executor:
                    self._executor = None
                if self._state is not ProcessPoolState.BROKEN:
                    self._state = ProcessPoolState.CLOSED

    def terminate(self) -> None:
        """Terminate workers immediately and permanently close the pool."""

        self._force_shutdown(kill=False)

    def kill(self) -> None:
        """Kill workers immediately and permanently close the pool."""

        self._force_shutdown(kill=True)

    def _force_shutdown(self, *, kill: bool) -> None:
        with self._lifecycle_lock:
            with self._state_lock:
                if self._state is ProcessPoolState.CLOSED:
                    return
                if self._state is ProcessPoolState.NEW:
                    self._state = ProcessPoolState.CLOSED
                    return
                executor = self._executor
                if executor is None:
                    raise RuntimeError("active pool has no executor")
                self._executor = None
                self._state = ProcessPoolState.SHUTTING_DOWN
            try:
                if kill:
                    executor.kill_workers()
                else:
                    executor.terminate_workers()
            except BaseException:
                with self._state_lock:
                    self._state = ProcessPoolState.BROKEN
                raise
            with self._state_lock:
                self._state = ProcessPoolState.CLOSED

    def __enter__(self) -> "ProcessScannerPool":
        return self.start()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.shutdown(cancel_pending=exc_type is not None)


__all__ = [
    "ProcessPoolNotRunningError",
    "ProcessPoolSaturatedError",
    "ProcessPoolState",
    "ProcessScannerPool",
    "ProcessScannerPoolConfig",
]
