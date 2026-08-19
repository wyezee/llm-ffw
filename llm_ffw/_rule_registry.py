"""Private fixed registry for configuration-backed text rules."""

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol, cast

from .authorization_header import AuthorizationHeaderConfig
from .banned_substring_catalog import BannedSubstringCatalog
from .capabilities import RuleCapability
from .email_address import EmailAddressConfig
from .iban import IBANConfig
from .inspection import ScanScope
from .ip_address import IPAddressConfig
from .json_output import JSONOutputConfig
from .jwt_token import JWTTokenConfig
from .mac_address import MACAddressConfig
from .payment_card import PaymentCardConfig
from .phone_number import PhoneNumberConfig
from .private_key import PrivateKeyConfig
from .repetition import RepetitionConfig
from .rules.authorization_header import AuthorizationHeaderRule
from .rules.banned_substrings import BannedSubstringsRule
from .rules.base import Rule
from .rules.email_address import EmailAddressRule
from .rules.iban import IBANRule
from .rules.ip_address import IPAddressRule
from .rules.json_output import JSONOutputRule
from .rules.jwt_token import JWTTokenRule
from .rules.mac_address import MACAddressRule
from .rules.payment_card import PaymentCardRule
from .rules.phone_number import PhoneNumberRule
from .rules.private_key import PrivateKeyRule
from .rules.repetition import RepetitionRule
from .rules.unsafe_url import UnsafeURLRule
from .unsafe_url import UnsafeURLConfig


class _ScopedConfig(Protocol):
    scopes: tuple[ScanScope, ...]


ConfiguredRuleConfigs = tuple[tuple[str, object], ...]


@dataclass(frozen=True, slots=True)
class RuleSpec:
    """Trusted metadata for one statically registered built-in rule."""

    config_field: str
    config_type: type[object]
    rule_type: type[Rule]
    rule_id: str
    purpose: str
    supported_scopes: frozenset[ScanScope]
    configured_scopes: bool = True

    def __post_init__(self) -> None:
        if not self.config_field.isidentifier():
            raise ValueError("config_field must be a Python identifier")
        if not isinstance(self.rule_id, str) or not self.rule_id:
            raise ValueError("rule_id must be non-empty")
        if not isinstance(self.purpose, str) or not self.purpose:
            raise ValueError("purpose must be non-empty")
        if not self.supported_scopes:
            raise ValueError("supported_scopes must not be empty")
        if getattr(self.rule_type, "RULE_ID", None) != self.rule_id:
            raise ValueError("rule_type RULE_ID does not match rule_id")
        if getattr(self.rule_type, "PURPOSE", None) != self.purpose:
            raise ValueError("rule_type PURPOSE does not match purpose")
        declared_scopes = getattr(self.rule_type, "SCOPES", None)
        if declared_scopes is not None and declared_scopes != self.supported_scopes:
            raise ValueError("rule_type SCOPES do not match supported_scopes")
        if declared_scopes is None and not self.configured_scopes:
            raise ValueError("fixed-scope rules must declare SCOPES")

    def validate_config(self, value: object) -> None:
        if not isinstance(value, self.config_type):
            raise TypeError(
                f"{self.config_field} must be a {self.config_type.__name__} or None"
            )

    def build(self, value: object) -> Rule:
        self.validate_config(value)
        constructor = cast(Callable[[object], Rule], self.rule_type)
        return constructor(value)

    def capability(self, value: object) -> RuleCapability:
        self.validate_config(value)
        scopes = (
            cast(_ScopedConfig, value).scopes
            if self.configured_scopes
            else tuple(self.supported_scopes)
        )
        return RuleCapability(
            rule_id=self.rule_id,
            purpose=self.purpose,
            scopes=tuple(scopes),
        )


RULE_SPECS: tuple[RuleSpec, ...] = (
    RuleSpec(
        "banned_substring_catalog",
        BannedSubstringCatalog,
        BannedSubstringsRule,
        BannedSubstringsRule.RULE_ID,
        BannedSubstringsRule.PURPOSE,
        frozenset((ScanScope.INPUT, ScanScope.OUTPUT)),
    ),
    RuleSpec(
        "json_output_config",
        JSONOutputConfig,
        JSONOutputRule,
        JSONOutputRule.RULE_ID,
        JSONOutputRule.PURPOSE,
        JSONOutputRule.SCOPES,
        configured_scopes=False,
    ),
    RuleSpec(
        "unsafe_url_config",
        UnsafeURLConfig,
        UnsafeURLRule,
        UnsafeURLRule.RULE_ID,
        UnsafeURLRule.PURPOSE,
        UnsafeURLRule.SCOPES,
    ),
    RuleSpec(
        "ip_address_config",
        IPAddressConfig,
        IPAddressRule,
        IPAddressRule.RULE_ID,
        IPAddressRule.PURPOSE,
        IPAddressRule.SCOPES,
    ),
    RuleSpec(
        "mac_address_config",
        MACAddressConfig,
        MACAddressRule,
        MACAddressRule.RULE_ID,
        MACAddressRule.PURPOSE,
        MACAddressRule.SCOPES,
    ),
    RuleSpec(
        "iban_config",
        IBANConfig,
        IBANRule,
        IBANRule.RULE_ID,
        IBANRule.PURPOSE,
        IBANRule.SCOPES,
    ),
    RuleSpec(
        "authorization_header_config",
        AuthorizationHeaderConfig,
        AuthorizationHeaderRule,
        AuthorizationHeaderRule.RULE_ID,
        AuthorizationHeaderRule.PURPOSE,
        AuthorizationHeaderRule.SCOPES,
    ),
    RuleSpec(
        "email_address_config",
        EmailAddressConfig,
        EmailAddressRule,
        EmailAddressRule.RULE_ID,
        EmailAddressRule.PURPOSE,
        EmailAddressRule.SCOPES,
    ),
    RuleSpec(
        "phone_number_config",
        PhoneNumberConfig,
        PhoneNumberRule,
        PhoneNumberRule.RULE_ID,
        PhoneNumberRule.PURPOSE,
        PhoneNumberRule.SCOPES,
    ),
    RuleSpec(
        "payment_card_config",
        PaymentCardConfig,
        PaymentCardRule,
        PaymentCardRule.RULE_ID,
        PaymentCardRule.PURPOSE,
        PaymentCardRule.SCOPES,
    ),
    RuleSpec(
        "private_key_config",
        PrivateKeyConfig,
        PrivateKeyRule,
        PrivateKeyRule.RULE_ID,
        PrivateKeyRule.PURPOSE,
        PrivateKeyRule.SCOPES,
    ),
    RuleSpec(
        "jwt_token_config",
        JWTTokenConfig,
        JWTTokenRule,
        JWTTokenRule.RULE_ID,
        JWTTokenRule.PURPOSE,
        JWTTokenRule.SCOPES,
    ),
    RuleSpec(
        "repetition_config",
        RepetitionConfig,
        RepetitionRule,
        RepetitionRule.RULE_ID,
        RepetitionRule.PURPOSE,
        RepetitionRule.SCOPES,
    ),
)

_SPECS_BY_FIELD = MappingProxyType(
    {spec.config_field: spec for spec in RULE_SPECS}
)
if len(_SPECS_BY_FIELD) != len(RULE_SPECS):
    raise RuntimeError("rule registry config fields must be unique")
if len({spec.rule_id for spec in RULE_SPECS}) != len(RULE_SPECS):
    raise RuntimeError("rule registry IDs must be unique")

REGISTERED_RULE_IDS = frozenset(spec.rule_id for spec in RULE_SPECS)


def normalize_rule_configs(
    values: Iterable[tuple[str, object | None]],
) -> ConfiguredRuleConfigs:
    """Validate trusted config pairs and return fixed registry order."""

    provided: dict[str, object] = {}
    seen: set[str] = set()
    for field_name, value in values:
        if field_name in seen:
            raise ValueError(f"duplicate configured rule field: {field_name}")
        seen.add(field_name)
        spec = _SPECS_BY_FIELD.get(field_name)
        if spec is None:
            raise ValueError(f"unknown configured rule field: {field_name}")
        if value is not None:
            spec.validate_config(value)
            provided[field_name] = value
    return tuple(
        (spec.config_field, provided[spec.config_field])
        for spec in RULE_SPECS
        if spec.config_field in provided
    )


def build_registered_rules(values: ConfiguredRuleConfigs) -> tuple[Rule, ...]:
    normalized = normalize_rule_configs(values)
    return tuple(
        _SPECS_BY_FIELD[field_name].build(value)
        for field_name, value in normalized
    )


def registered_rule_capabilities(
    values: ConfiguredRuleConfigs,
) -> tuple[RuleCapability, ...]:
    normalized = normalize_rule_configs(values)
    return tuple(
        _SPECS_BY_FIELD[field_name].capability(value)
        for field_name, value in normalized
    )


def registered_rule_ids(values: ConfiguredRuleConfigs) -> frozenset[str]:
    normalized = normalize_rule_configs(values)
    return frozenset(
        _SPECS_BY_FIELD[field_name].rule_id for field_name, _ in normalized
    )


__all__ = [
    "ConfiguredRuleConfigs",
    "REGISTERED_RULE_IDS",
    "RULE_SPECS",
    "RuleSpec",
    "build_registered_rules",
    "normalize_rule_configs",
    "registered_rule_capabilities",
    "registered_rule_ids",
]
