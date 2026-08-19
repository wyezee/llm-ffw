"""Immutable high-level configuration and explicit deployment presets."""

from dataclasses import dataclass, field
import math
from typing import TypedDict

from .authorization_header import AuthorizationHeaderConfig
from .banned_substring_catalog import BannedSubstringCatalog
from .config import RuleScannerConfig
from .email_address import EmailAddressConfig
from .phone_number import PhoneNumberConfig
from .iban import IBANConfig
from .ip_address import IPAddressConfig
from .json_output import JSONOutputConfig
from .jwt_token import JWTTokenConfig
from .mac_address import MACAddressConfig
from .payment_card import PaymentCardConfig
from .policy import BALANCED_POLICY, FirewallPolicy
from .private_key import PrivateKeyConfig
from .process_pool import ProcessScannerPoolConfig
from .repetition import RepetitionConfig
from .secret_catalog import SecretCatalog
from .unsafe_url import UnsafeURLConfig


class _FacadeKwargs(TypedDict):
    scanner_config: RuleScannerConfig
    pool_config: ProcessScannerPoolConfig
    additional_secret_catalog: SecretCatalog | None
    replacement_secret_catalog: SecretCatalog | None
    banned_substring_catalog: BannedSubstringCatalog | None
    json_output_config: JSONOutputConfig | None
    unsafe_url_config: UnsafeURLConfig | None
    ip_address_config: IPAddressConfig | None
    mac_address_config: MACAddressConfig | None
    iban_config: IBANConfig | None
    authorization_header_config: AuthorizationHeaderConfig | None
    email_address_config: EmailAddressConfig | None
    phone_number_config: PhoneNumberConfig | None
    payment_card_config: PaymentCardConfig | None
    private_key_config: PrivateKeyConfig | None
    jwt_token_config: JWTTokenConfig | None
    repetition_config: RepetitionConfig | None
    policy: FirewallPolicy
    request_timeout_seconds: float


@dataclass(frozen=True, slots=True)
class FirewallConfig:
    """One validated configuration shared by every high-level facade."""

    scanner_config: RuleScannerConfig = field(default_factory=RuleScannerConfig)
    pool_config: ProcessScannerPoolConfig = field(
        default_factory=ProcessScannerPoolConfig
    )
    additional_secret_catalog: SecretCatalog | None = field(
        default=None,
        repr=False,
    )
    replacement_secret_catalog: SecretCatalog | None = field(
        default=None,
        repr=False,
    )
    banned_substring_catalog: BannedSubstringCatalog | None = field(
        default=None,
        repr=False,
    )
    json_output_config: JSONOutputConfig | None = None
    unsafe_url_config: UnsafeURLConfig | None = None
    ip_address_config: IPAddressConfig | None = None
    mac_address_config: MACAddressConfig | None = None
    iban_config: IBANConfig | None = None
    authorization_header_config: AuthorizationHeaderConfig | None = None
    email_address_config: EmailAddressConfig | None = None
    phone_number_config: PhoneNumberConfig | None = None
    payment_card_config: PaymentCardConfig | None = None
    private_key_config: PrivateKeyConfig | None = None
    jwt_token_config: JWTTokenConfig | None = None
    repetition_config: RepetitionConfig | None = None
    policy: FirewallPolicy = BALANCED_POLICY
    request_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        required: tuple[tuple[str, object, type[object]], ...] = (
            ("scanner_config", self.scanner_config, RuleScannerConfig),
            ("pool_config", self.pool_config, ProcessScannerPoolConfig),
            ("policy", self.policy, FirewallPolicy),
        )
        for name, value, expected_type in required:
            if not isinstance(value, expected_type):
                raise TypeError(f"{name} must be a {expected_type.__name__}")
        optional: tuple[tuple[str, object, type[object]], ...] = (
            (
                "additional_secret_catalog",
                self.additional_secret_catalog,
                SecretCatalog,
            ),
            (
                "replacement_secret_catalog",
                self.replacement_secret_catalog,
                SecretCatalog,
            ),
            (
                "banned_substring_catalog",
                self.banned_substring_catalog,
                BannedSubstringCatalog,
            ),
            ("json_output_config", self.json_output_config, JSONOutputConfig),
            ("unsafe_url_config", self.unsafe_url_config, UnsafeURLConfig),
            ("ip_address_config", self.ip_address_config, IPAddressConfig),
            ("mac_address_config", self.mac_address_config, MACAddressConfig),
            ("iban_config", self.iban_config, IBANConfig),
            (
                "authorization_header_config",
                self.authorization_header_config,
                AuthorizationHeaderConfig,
            ),
            ("email_address_config", self.email_address_config, EmailAddressConfig),
            ("phone_number_config", self.phone_number_config, PhoneNumberConfig),
            ("payment_card_config", self.payment_card_config, PaymentCardConfig),
            ("private_key_config", self.private_key_config, PrivateKeyConfig),
            ("jwt_token_config", self.jwt_token_config, JWTTokenConfig),
            ("repetition_config", self.repetition_config, RepetitionConfig),
        )
        for name, value, expected_type in optional:
            if value is not None and not isinstance(value, expected_type):
                raise TypeError(
                    f"{name} must be a {expected_type.__name__} or None"
                )
        if (
            self.additional_secret_catalog is not None
            and self.replacement_secret_catalog is not None
        ):
            raise ValueError(
                "additional_secret_catalog and replacement_secret_catalog "
                "are mutually exclusive"
            )
        timeout = self.request_timeout_seconds
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise TypeError("request_timeout_seconds must be numeric")
        if timeout <= 0 or not math.isfinite(timeout):
            raise ValueError(
                "request_timeout_seconds must be finite and positive"
            )
        object.__setattr__(self, "request_timeout_seconds", float(timeout))

    @classmethod
    def default(cls) -> "FirewallConfig":
        """Return the secure baseline used by ``Firewall()``."""

        return cls()

    @classmethod
    def privacy_input(cls) -> "FirewallConfig":
        """Enable conservative input PII rules in addition to the baseline."""

        return cls(
            ip_address_config=IPAddressConfig(),
            mac_address_config=MACAddressConfig(),
            iban_config=IBANConfig(),
            email_address_config=EmailAddressConfig(),
            phone_number_config=PhoneNumberConfig(),
        )

    @classmethod
    def json_api(cls) -> "FirewallConfig":
        """Require JSON output and inspect unsafe URLs in both directions."""

        return cls(
            json_output_config=JSONOutputConfig(),
            unsafe_url_config=UnsafeURLConfig(),
        )

    @classmethod
    def all_text_rules(
        cls,
        *,
        banned_substring_catalog: BannedSubstringCatalog,
    ) -> "FirewallConfig":
        """Enable every text rule with an explicit deployment-owned catalog."""

        if not isinstance(banned_substring_catalog, BannedSubstringCatalog):
            raise TypeError(
                "banned_substring_catalog must be a BannedSubstringCatalog"
            )
        return cls(
            banned_substring_catalog=banned_substring_catalog,
            json_output_config=JSONOutputConfig(),
            unsafe_url_config=UnsafeURLConfig(),
            ip_address_config=IPAddressConfig(),
            mac_address_config=MACAddressConfig(),
            iban_config=IBANConfig(),
            authorization_header_config=AuthorizationHeaderConfig(),
            email_address_config=EmailAddressConfig(),
            phone_number_config=PhoneNumberConfig(),
            repetition_config=RepetitionConfig(),
            request_timeout_seconds=30.0,
        )

    def _facade_kwargs(self) -> _FacadeKwargs:
        """Return constructor arguments without serialization or copying."""

        return {
            "scanner_config": self.scanner_config,
            "pool_config": self.pool_config,
            "additional_secret_catalog": self.additional_secret_catalog,
            "replacement_secret_catalog": self.replacement_secret_catalog,
            "banned_substring_catalog": self.banned_substring_catalog,
            "json_output_config": self.json_output_config,
            "unsafe_url_config": self.unsafe_url_config,
            "ip_address_config": self.ip_address_config,
            "mac_address_config": self.mac_address_config,
            "iban_config": self.iban_config,
            "authorization_header_config": self.authorization_header_config,
            "email_address_config": self.email_address_config,
            "phone_number_config": self.phone_number_config,
            "payment_card_config": self.payment_card_config,
            "private_key_config": self.private_key_config,
            "jwt_token_config": self.jwt_token_config,
            "repetition_config": self.repetition_config,
            "policy": self.policy,
            "request_timeout_seconds": self.request_timeout_seconds,
        }


__all__ = ["FirewallConfig"]
