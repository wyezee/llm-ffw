"""High-level production facade for sanitized input and output text."""

from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass, field
import math
from threading import Lock
from typing import cast

from .capabilities import (
    BannedSubstringCatalogCapability,
    FirewallCapabilities,
    JSONOutputCapability,
    IPAddressCapability,
    MACAddressCapability,
    IBANCapability,
    EmailAddressCapability,
    RuleCapability,
    SecretCatalogCapability,
    UnsafeURLCapability,
    PaymentCardCapability,
    PrivateKeyCapability,
    JWTTokenCapability,
)
from .banned_substring_catalog import BannedSubstringCatalog
from .config import ScannerConfig
from .findings import Action, Finding
from .inspection import ScanScope
from .json_output import JSONOutputConfig
from .ip_address import IPAddressConfig
from .mac_address import MACAddressConfig
from .iban import (
    IBANConfig,
    IBAN_REGISTRY_ISSUED,
    IBAN_REGISTRY_RELEASE,
)
from .email_address import EmailAddressConfig
from .unsafe_url import UnsafeURLConfig
from .payment_card import PaymentCardConfig
from .private_key import PrivateKeyConfig
from .jwt_token import JWTTokenConfig
from .policy import BALANCED_POLICY, FirewallPolicy, FirewallResult
from .process_pool import (
    ProcessPoolNotRunningError,
    ProcessPoolSaturatedError,
    ProcessPoolState,
    ProcessScannerPool,
    ProcessScannerPoolConfig,
)
from .rules.secrets import SecretsRule
from .rules.banned_substrings import BannedSubstringsRule
from .rules.invisible_characters import InvisibleCharactersRule
from .rules.unicode_tag_smuggling import UnicodeTagSmugglingRule
from .rules.json_output import JSONOutputRule
from .rules.ip_address import IPAddressRule
from .rules.mac_address import MACAddressRule
from .rules.iban import IBANRule
from .rules.email_address import EmailAddressRule
from .rules.unsafe_url import UnsafeURLRule
from .rules.payment_card import PaymentCardRule
from .rules.private_key import PrivateKeyRule
from .rules.jwt_token import JWTTokenRule
from .secret_catalog import (
    BUILTIN_SECRET_CATALOG,
    SecretCatalog,
    _resolve_secret_catalog,
)


class ContentBlockedError(RuntimeError):
    """Raised when policy blocks content without retaining the original text."""

    def __init__(self, result: FirewallResult) -> None:
        if not isinstance(result, FirewallResult) or not result.blocked:
            raise ValueError("result must be a blocked FirewallResult")
        super().__init__("content blocked by firewall policy")
        self.policy_id = result.policy_id
        self.policy_version = result.policy_version
        self.scope = result.scope
        self.findings: tuple[Finding, ...] = result.findings


class FirewallUnavailableError(RuntimeError):
    """Raised when content cannot be safely inspected."""

    def __init__(self, cause_type: str) -> None:
        super().__init__("content inspection unavailable")
        self.cause_type = cause_type


@dataclass(frozen=True, slots=True)
class SanitizationResult:
    """Forwardable sanitized text and disclosure-safe enforcement details."""

    text: str = field(repr=False)
    policy_id: str
    policy_version: str
    scope: ScanScope
    decision: Action
    findings: tuple[Finding, ...]

    def __post_init__(self) -> None:
        validated = FirewallResult(
            policy_id=self.policy_id,
            policy_version=self.policy_version,
            scope=self.scope,
            decision=self.decision,
            processed_text=self.text,
            findings=self.findings,
        )
        object.__setattr__(self, "findings", validated.findings)


def _validate_request_timeout(value: object) -> float:
    if value is None:
        raise TypeError("request_timeout_seconds must be numeric")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("request_timeout_seconds must be numeric")
    if value < 0 or not math.isfinite(value):
        raise ValueError(
            "request_timeout_seconds must be finite and not negative"
        )
    return float(value)


class LLMFirewall:
    """Sanitize text through one lifecycle-managed process scanner pool."""

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
        ip_address_config: IPAddressConfig | None = None,
        mac_address_config: MACAddressConfig | None = None,
        iban_config: IBANConfig | None = None,
        email_address_config: EmailAddressConfig | None = None,
        payment_card_config: PaymentCardConfig | None = None,
        private_key_config: PrivateKeyConfig | None = None,
        jwt_token_config: JWTTokenConfig | None = None,
        policy: FirewallPolicy = BALANCED_POLICY,
        request_timeout_seconds: float = 5.0,
    ) -> None:
        self._request_timeout_seconds = _validate_request_timeout(
            request_timeout_seconds
        )
        self._lifecycle_lock = Lock()
        catalog = _resolve_secret_catalog(
            additional_secret_catalog,
            replacement_secret_catalog,
        )
        self._pool = ProcessScannerPool(
            scanner_config=scanner_config,
            pool_config=pool_config,
            secret_catalog=(
                None if catalog is BUILTIN_SECRET_CATALOG else catalog
            ),
            banned_substring_catalog=banned_substring_catalog,
            json_output_config=json_output_config,
            unsafe_url_config=unsafe_url_config,
            ip_address_config=ip_address_config,
            mac_address_config=mac_address_config,
            iban_config=iban_config,
            email_address_config=email_address_config,
            payment_card_config=payment_card_config,
            private_key_config=private_key_config,
            jwt_token_config=jwt_token_config,
            policy=policy,
        )
        catalog = self._pool.secret_catalog
        rule_capabilities = [
            RuleCapability(
                rule_id=SecretsRule.RULE_ID,
                purpose=SecretsRule.PURPOSE,
                scopes=tuple(SecretsRule.SCOPES),
            )
        ]
        if self._pool.scanner_config.enable_invisible_characters:
            rule_capabilities.append(
                RuleCapability(
                    rule_id=InvisibleCharactersRule.RULE_ID,
                    purpose=InvisibleCharactersRule.PURPOSE,
                    scopes=tuple(InvisibleCharactersRule.SCOPES),
                )
            )
        if self._pool.scanner_config.enable_unicode_tag_smuggling:
            rule_capabilities.append(
                RuleCapability(
                    rule_id=UnicodeTagSmugglingRule.RULE_ID,
                    purpose=UnicodeTagSmugglingRule.PURPOSE,
                    scopes=tuple(UnicodeTagSmugglingRule.SCOPES),
                )
            )
        literal_catalog = self._pool.banned_substring_catalog
        if literal_catalog is not None:
            rule_capabilities.append(
                RuleCapability(
                    rule_id=BannedSubstringsRule.RULE_ID,
                    purpose=BannedSubstringsRule.PURPOSE,
                    scopes=tuple(literal_catalog.scopes),
                )
            )
        if self._pool.json_output_config is not None:
            rule_capabilities.append(
                RuleCapability(
                    rule_id=JSONOutputRule.RULE_ID,
                    purpose=JSONOutputRule.PURPOSE,
                    scopes=tuple(JSONOutputRule.SCOPES),
                )
            )
        if self._pool.unsafe_url_config is not None:
            rule_capabilities.append(
                RuleCapability(
                    rule_id=UnsafeURLRule.RULE_ID,
                    purpose=UnsafeURLRule.PURPOSE,
                    scopes=tuple(self._pool.unsafe_url_config.scopes),
                )
            )
        if self._pool.ip_address_config is not None:
            rule_capabilities.append(
                RuleCapability(
                    rule_id=IPAddressRule.RULE_ID,
                    purpose=IPAddressRule.PURPOSE,
                    scopes=tuple(self._pool.ip_address_config.scopes),
                )
            )
        if self._pool.mac_address_config is not None:
            rule_capabilities.append(
                RuleCapability(
                    rule_id=MACAddressRule.RULE_ID,
                    purpose=MACAddressRule.PURPOSE,
                    scopes=tuple(self._pool.mac_address_config.scopes),
                )
            )
        if self._pool.iban_config is not None:
            rule_capabilities.append(
                RuleCapability(
                    rule_id=IBANRule.RULE_ID,
                    purpose=IBANRule.PURPOSE,
                    scopes=tuple(self._pool.iban_config.scopes),
                )
            )
        if self._pool.email_address_config is not None:
            rule_capabilities.append(
                RuleCapability(
                    rule_id=EmailAddressRule.RULE_ID,
                    purpose=EmailAddressRule.PURPOSE,
                    scopes=tuple(self._pool.email_address_config.scopes),
                )
            )
        if self._pool.payment_card_config is not None:
            rule_capabilities.append(
                RuleCapability(
                    rule_id=PaymentCardRule.RULE_ID,
                    purpose=PaymentCardRule.PURPOSE,
                    scopes=tuple(self._pool.payment_card_config.scopes),
                )
            )
        if self._pool.private_key_config is not None:
            rule_capabilities.append(
                RuleCapability(
                    rule_id=PrivateKeyRule.RULE_ID,
                    purpose=PrivateKeyRule.PURPOSE,
                    scopes=tuple(self._pool.private_key_config.scopes),
                )
            )
        if self._pool.jwt_token_config is not None:
            rule_capabilities.append(
                RuleCapability(
                    rule_id=JWTTokenRule.RULE_ID,
                    purpose=JWTTokenRule.PURPOSE,
                    scopes=tuple(self._pool.jwt_token_config.scopes),
                )
            )
        self._capabilities = FirewallCapabilities(
            rules=tuple(rule_capabilities),
            secret_catalog=SecretCatalogCapability(
                catalog_id=catalog.catalog_id,
                version=catalog.version,
                signature_count=len(catalog.signatures),
                prefix_count=sum(
                    len(signature.prefixes) for signature in catalog.signatures
                ),
                providers=tuple(
                    signature.provider for signature in catalog.signatures
                ),
            ),
            policy_id=self._pool.policy.policy_id,
            policy_version=self._pool.policy.version,
            banned_substring_catalog=(
                BannedSubstringCatalogCapability(
                    catalog_id=literal_catalog.catalog_id,
                    version=literal_catalog.version,
                    pattern_count=len(literal_catalog.patterns),
                )
                if literal_catalog is not None
                else None
            ),
            json_output=(
                JSONOutputCapability(
                    max_document_chars=(
                        self._pool.json_output_config.max_document_chars
                    ),
                    max_depth=self._pool.json_output_config.max_depth,
                    max_structure_tokens=(
                        self._pool.json_output_config.max_structure_tokens
                    ),
                    max_number_chars=(
                        self._pool.json_output_config.max_number_chars
                    ),
                    reject_duplicate_keys=(
                        self._pool.json_output_config.reject_duplicate_keys
                    ),
                )
                if self._pool.json_output_config is not None
                else None
            ),
            unsafe_url=(
                UnsafeURLCapability(
                    max_candidates=(
                        self._pool.unsafe_url_config.max_candidates
                    ),
                    max_url_chars=self._pool.unsafe_url_config.max_url_chars,
                )
                if self._pool.unsafe_url_config is not None
                else None
            ),
            ip_address=(
                IPAddressCapability(
                    max_candidates=(
                        self._pool.ip_address_config.max_candidates
                    ),
                    include_ipv4=self._pool.ip_address_config.include_ipv4,
                    include_ipv6=self._pool.ip_address_config.include_ipv6,
                )
                if self._pool.ip_address_config is not None
                else None
            ),
            mac_address=(
                MACAddressCapability(
                    max_candidates=(
                        self._pool.mac_address_config.max_candidates
                    ),
                )
                if self._pool.mac_address_config is not None
                else None
            ),
            iban=(
                IBANCapability(
                    max_candidates=self._pool.iban_config.max_candidates,
                    registry_release=IBAN_REGISTRY_RELEASE,
                    registry_issued=IBAN_REGISTRY_ISSUED,
                )
                if self._pool.iban_config is not None
                else None
            ),
            email_address=(
                EmailAddressCapability(
                    max_candidates=(
                        self._pool.email_address_config.max_candidates
                    ),
                )
                if self._pool.email_address_config is not None
                else None
            ),
            payment_card=(
                PaymentCardCapability(
                    max_candidates=(
                        self._pool.payment_card_config.max_candidates
                    ),
                )
                if self._pool.payment_card_config is not None
                else None
            ),
            private_key=(
                PrivateKeyCapability(
                    max_candidates=(
                        self._pool.private_key_config.max_candidates
                    ),
                    max_block_chars=(
                        self._pool.private_key_config.max_block_chars
                    ),
                )
                if self._pool.private_key_config is not None
                else None
            ),
            jwt_token=(
                JWTTokenCapability(
                    max_candidates=self._pool.jwt_token_config.max_candidates,
                    max_token_chars=self._pool.jwt_token_config.max_token_chars,
                    max_json_depth=self._pool.jwt_token_config.max_json_depth,
                    max_json_structure_tokens=(
                        self._pool.jwt_token_config.max_json_structure_tokens
                    ),
                )
                if self._pool.jwt_token_config is not None
                else None
            ),
        )

    @property
    def state(self) -> ProcessPoolState:
        """Return the underlying lifecycle state for readiness checks."""

        return self._pool.state

    def capabilities(self) -> FirewallCapabilities:
        """Return an immutable summary without prefixes or source locations."""

        return self._capabilities

    def start(self) -> "LLMFirewall":
        """Start workers once during application startup."""

        failure: FirewallUnavailableError | None = None
        with self._lifecycle_lock:
            if self._pool.state is ProcessPoolState.RUNNING:
                return self
            try:
                self._pool.start()
            except Exception as exc:
                failure = self._unavailable_error(exc)
        if failure is not None:
            raise failure
        return self

    def close(self) -> None:
        """Stop admission and close workers during graceful shutdown."""

        failure: FirewallUnavailableError | None = None
        with self._lifecycle_lock:
            try:
                self._pool.shutdown(cancel_pending=True)
            except Exception as exc:
                failure = self._unavailable_error(exc)
        if failure is not None:
            raise failure

    def terminate(self) -> None:
        """Terminate workers at the service's graceful-shutdown deadline."""

        failure: FirewallUnavailableError | None = None
        with self._lifecycle_lock:
            try:
                self._pool.terminate()
            except Exception as exc:
                failure = self._unavailable_error(exc)
        if failure is not None:
            raise failure

    def kill(self) -> None:
        """Kill workers at the service's final hard-stop deadline."""

        failure: FirewallUnavailableError | None = None
        with self._lifecycle_lock:
            try:
                self._pool.kill()
            except Exception as exc:
                failure = self._unavailable_error(exc)
        if failure is not None:
            raise failure

    def sanitize_input(self, text: str) -> str:
        """Return input text after applying the configured firewall policy."""

        self._validate_text(text, "text")
        result = self._forwardable_result(text, scope=ScanScope.INPUT)
        return cast(str, result.processed_text)

    def sanitize_input_result(self, text: str) -> SanitizationResult:
        """Return sanitized input with safe findings and policy metadata."""

        self._validate_text(text, "text")
        result = self._forwardable_result(text, scope=ScanScope.INPUT)
        return self._sanitization_result(result)

    def sanitize_output(
        self,
        text: str,
        *,
        prompt_context: str | None = None,
    ) -> str:
        """Return output text after applying the configured firewall policy."""

        self._validate_text(text, "text")
        if prompt_context is not None:
            self._validate_text(prompt_context, "prompt_context")
        result = self._forwardable_result(
            text,
            scope=ScanScope.OUTPUT,
            prompt_context=prompt_context,
        )
        return cast(str, result.processed_text)

    def sanitize_output_result(
        self,
        text: str,
        *,
        prompt_context: str | None = None,
    ) -> SanitizationResult:
        """Return sanitized output with safe findings and policy metadata."""

        self._validate_text(text, "text")
        if prompt_context is not None:
            self._validate_text(prompt_context, "prompt_context")
        result = self._forwardable_result(
            text,
            scope=ScanScope.OUTPUT,
            prompt_context=prompt_context,
        )
        return self._sanitization_result(result)

    def _forwardable_result(
        self,
        text: str,
        *,
        scope: ScanScope,
        prompt_context: str | None = None,
    ) -> FirewallResult:
        failure: FirewallUnavailableError | None = None
        result: FirewallResult | None = None
        try:
            result = self._pool.process(
                text,
                scope=scope,
                prompt_context=prompt_context,
                timeout=self._request_timeout_seconds,
            )
        except Exception as exc:
            failure = self._unavailable_error(exc)
        if failure is not None:
            raise failure
        if result is None:
            raise FirewallUnavailableError("InternalInspectionError")
        if result.blocked:
            raise ContentBlockedError(result)
        if result.processed_text is None:
            raise FirewallUnavailableError("InternalInspectionError")
        return result

    @staticmethod
    def _sanitization_result(result: FirewallResult) -> SanitizationResult:
        return SanitizationResult(
            text=cast(str, result.processed_text),
            policy_id=result.policy_id,
            policy_version=result.policy_version,
            scope=result.scope,
            decision=result.decision,
            findings=result.findings,
        )

    def _validate_text(self, value: object, field_name: str) -> None:
        if not isinstance(value, str):
            raise TypeError(f"{field_name} must be a string")
        if len(value) > self._pool.scanner_config.max_input_chars:
            raise ValueError(
                f"{field_name} exceeds max_input_chars="
                f"{self._pool.scanner_config.max_input_chars}"
            )

    def _secret_catalog_snapshot(self) -> SecretCatalog:
        """Return the immutable catalog pinned to this generation."""

        return self._pool.secret_catalog

    @staticmethod
    def _unavailable_error(exc: Exception) -> FirewallUnavailableError:
        known = (
            BrokenProcessPool,
            ProcessPoolNotRunningError,
            ProcessPoolSaturatedError,
            TimeoutError,
        )
        cause_type = type(exc).__name__
        if not isinstance(exc, known):
            cause_type = "InternalInspectionError"
        return FirewallUnavailableError(cause_type)

    def __enter__(self) -> "LLMFirewall":
        return self.start()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        try:
            self.close()
        except FirewallUnavailableError:
            if exc_type is None:
                raise


__all__ = [
    "ContentBlockedError",
    "FirewallUnavailableError",
    "LLMFirewall",
    "SanitizationResult",
]
