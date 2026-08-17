"""Immutable, disclosure-safe descriptions of configured firewall behavior."""

from dataclasses import dataclass

from .inspection import ScanScope


def _non_empty(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


@dataclass(frozen=True, slots=True)
class RuleCapability:
    """Stable rule identity and direction without implementation details."""

    rule_id: str
    purpose: str
    scopes: tuple[ScanScope, ...]

    def __post_init__(self) -> None:
        _non_empty(self.rule_id, "rule_id")
        _non_empty(self.purpose, "purpose")
        try:
            scopes = tuple(self.scopes)
        except TypeError as exc:
            raise TypeError("scopes must be iterable") from exc
        if not scopes or any(not isinstance(scope, ScanScope) for scope in scopes):
            raise ValueError("scopes must contain ScanScope values")
        object.__setattr__(
            self,
            "scopes",
            tuple(sorted(set(scopes), key=lambda scope: scope.value)),
        )


@dataclass(frozen=True, slots=True)
class SecretCatalogCapability:
    """Catalog summary that intentionally omits prefixes and source locations."""

    catalog_id: str
    version: str
    signature_count: int
    prefix_count: int
    providers: tuple[str, ...]

    def __post_init__(self) -> None:
        _non_empty(self.catalog_id, "catalog_id")
        _non_empty(self.version, "version")
        for field_name in ("signature_count", "prefix_count"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{field_name} must be a positive integer")
        try:
            providers = tuple(self.providers)
        except TypeError as exc:
            raise TypeError("providers must be iterable") from exc
        if not providers or any(
            not isinstance(provider, str) or not provider
            for provider in providers
        ):
            raise ValueError("providers must contain non-empty strings")
        object.__setattr__(self, "providers", tuple(sorted(set(providers))))


@dataclass(frozen=True, slots=True)
class BannedSubstringCatalogCapability:
    """Disclosure-safe literal catalog coordinates and count."""

    catalog_id: str
    version: str
    pattern_count: int

    def __post_init__(self) -> None:
        _non_empty(self.catalog_id, "catalog_id")
        _non_empty(self.version, "version")
        if (
            isinstance(self.pattern_count, bool)
            or not isinstance(self.pattern_count, int)
            or self.pattern_count <= 0
        ):
            raise ValueError("pattern_count must be a positive integer")


@dataclass(frozen=True, slots=True)
class JSONOutputCapability:
    """Disclosure-safe JSON validation limits pinned to the facade."""

    max_document_chars: int
    max_depth: int
    max_structure_tokens: int
    max_number_chars: int
    reject_duplicate_keys: bool

    def __post_init__(self) -> None:
        for field_name in (
            "max_document_chars",
            "max_depth",
            "max_structure_tokens",
            "max_number_chars",
        ):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{field_name} must be a positive integer")
        if not isinstance(self.reject_duplicate_keys, bool):
            raise TypeError("reject_duplicate_keys must be a boolean")


@dataclass(frozen=True, slots=True)
class UnsafeURLCapability:
    """Disclosure-safe URL inspection limits pinned to the facade."""

    max_candidates: int
    max_url_chars: int

    def __post_init__(self) -> None:
        for field_name in ("max_candidates", "max_url_chars"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{field_name} must be a positive integer")


@dataclass(frozen=True, slots=True)
class PaymentCardCapability:
    """Disclosure-safe payment-card inspection limits pinned to the facade."""

    max_candidates: int

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_candidates, bool)
            or not isinstance(self.max_candidates, int)
            or self.max_candidates <= 0
        ):
            raise ValueError("max_candidates must be a positive integer")


@dataclass(frozen=True, slots=True)
class IPAddressCapability:
    """Disclosure-safe IP-address inspection configuration."""

    max_candidates: int
    include_ipv4: bool
    include_ipv6: bool

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_candidates, bool)
            or not isinstance(self.max_candidates, int)
            or self.max_candidates <= 0
        ):
            raise ValueError("max_candidates must be a positive integer")
        for field_name in ("include_ipv4", "include_ipv6"):
            if not isinstance(getattr(self, field_name), bool):
                raise TypeError(f"{field_name} must be a boolean")
        if not self.include_ipv4 and not self.include_ipv6:
            raise ValueError("at least one address family must be enabled")


@dataclass(frozen=True, slots=True)
class MACAddressCapability:
    """Disclosure-safe MAC-address inspection configuration."""

    max_candidates: int

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_candidates, bool)
            or not isinstance(self.max_candidates, int)
            or self.max_candidates <= 0
        ):
            raise ValueError("max_candidates must be a positive integer")


@dataclass(frozen=True, slots=True)
class IBANCapability:
    """Disclosure-safe IBAN inspection configuration and registry pin."""

    max_candidates: int
    registry_release: str
    registry_issued: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_candidates, bool)
            or not isinstance(self.max_candidates, int)
            or self.max_candidates <= 0
        ):
            raise ValueError("max_candidates must be a positive integer")
        _non_empty(self.registry_release, "registry_release")
        _non_empty(self.registry_issued, "registry_issued")


@dataclass(frozen=True, slots=True)
class AuthorizationHeaderCapability:
    """Disclosure-safe Authorization-header inspection limits."""

    max_candidates: int
    max_credential_chars: int
    schemes: tuple[str, ...] = ("basic", "bearer")

    def __post_init__(self) -> None:
        for field_name in ("max_candidates", "max_credential_chars"):
            value = getattr(self, field_name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
            ):
                raise ValueError(f"{field_name} must be a positive integer")
        try:
            schemes = tuple(self.schemes)
        except TypeError as exc:
            raise TypeError("schemes must be iterable") from exc
        if schemes != ("basic", "bearer"):
            raise ValueError("schemes must be the supported Basic and Bearer set")
        object.__setattr__(self, "schemes", schemes)


@dataclass(frozen=True, slots=True)
class EmailAddressCapability:
    """Disclosure-safe email-address inspection configuration."""

    max_candidates: int

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_candidates, bool)
            or not isinstance(self.max_candidates, int)
            or self.max_candidates <= 0
        ):
            raise ValueError("max_candidates must be a positive integer")


@dataclass(frozen=True, slots=True)
class PrivateKeyCapability:
    """Disclosure-safe private-key inspection limits pinned to the facade."""

    max_candidates: int
    max_block_chars: int

    def __post_init__(self) -> None:
        for field_name in ("max_candidates", "max_block_chars"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{field_name} must be a positive integer")


@dataclass(frozen=True, slots=True)
class JWTTokenCapability:
    """Disclosure-safe JWT inspection limits pinned to the facade."""

    max_candidates: int
    max_token_chars: int
    max_json_depth: int
    max_json_structure_tokens: int

    def __post_init__(self) -> None:
        for field_name in (
            "max_candidates",
            "max_token_chars",
            "max_json_depth",
            "max_json_structure_tokens",
        ):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{field_name} must be a positive integer")


@dataclass(frozen=True, slots=True)
class FirewallCapabilities:
    """Safe summary of the rules, catalog, and policy pinned to one facade."""

    rules: tuple[RuleCapability, ...]
    secret_catalog: SecretCatalogCapability
    policy_id: str
    policy_version: str
    banned_substring_catalog: BannedSubstringCatalogCapability | None = None
    json_output: JSONOutputCapability | None = None
    unsafe_url: UnsafeURLCapability | None = None
    ip_address: IPAddressCapability | None = None
    mac_address: MACAddressCapability | None = None
    iban: IBANCapability | None = None
    authorization_header: AuthorizationHeaderCapability | None = None
    email_address: EmailAddressCapability | None = None
    payment_card: PaymentCardCapability | None = None
    private_key: PrivateKeyCapability | None = None
    jwt_token: JWTTokenCapability | None = None

    def __post_init__(self) -> None:
        try:
            rules = tuple(self.rules)
        except TypeError as exc:
            raise TypeError("rules must be iterable") from exc
        if not rules or any(not isinstance(rule, RuleCapability) for rule in rules):
            raise ValueError("rules must contain RuleCapability values")
        if len({rule.rule_id for rule in rules}) != len(rules):
            raise ValueError("rule IDs must be unique")
        if not isinstance(self.secret_catalog, SecretCatalogCapability):
            raise TypeError("secret_catalog must be a SecretCatalogCapability")
        _non_empty(self.policy_id, "policy_id")
        _non_empty(self.policy_version, "policy_version")
        if self.banned_substring_catalog is not None and not isinstance(
            self.banned_substring_catalog,
            BannedSubstringCatalogCapability,
        ):
            raise TypeError(
                "banned_substring_catalog must be a "
                "BannedSubstringCatalogCapability or None"
            )
        if self.json_output is not None and not isinstance(
            self.json_output, JSONOutputCapability
        ):
            raise TypeError(
                "json_output must be a JSONOutputCapability or None"
            )
        if self.unsafe_url is not None and not isinstance(
            self.unsafe_url, UnsafeURLCapability
        ):
            raise TypeError("unsafe_url must be an UnsafeURLCapability or None")
        if self.ip_address is not None and not isinstance(
            self.ip_address, IPAddressCapability
        ):
            raise TypeError(
                "ip_address must be an IPAddressCapability or None"
            )
        if self.mac_address is not None and not isinstance(
            self.mac_address, MACAddressCapability
        ):
            raise TypeError(
                "mac_address must be a MACAddressCapability or None"
            )
        if self.iban is not None and not isinstance(self.iban, IBANCapability):
            raise TypeError("iban must be an IBANCapability or None")
        if self.authorization_header is not None and not isinstance(
            self.authorization_header, AuthorizationHeaderCapability
        ):
            raise TypeError(
                "authorization_header must be an AuthorizationHeaderCapability "
                "or None"
            )
        if self.email_address is not None and not isinstance(
            self.email_address, EmailAddressCapability
        ):
            raise TypeError(
                "email_address must be an EmailAddressCapability or None"
            )
        if self.payment_card is not None and not isinstance(
            self.payment_card, PaymentCardCapability
        ):
            raise TypeError(
                "payment_card must be a PaymentCardCapability or None"
            )
        if self.private_key is not None and not isinstance(
            self.private_key, PrivateKeyCapability
        ):
            raise TypeError("private_key must be a PrivateKeyCapability or None")
        if self.jwt_token is not None and not isinstance(
            self.jwt_token, JWTTokenCapability
        ):
            raise TypeError("jwt_token must be a JWTTokenCapability or None")
        object.__setattr__(
            self,
            "rules",
            tuple(sorted(rules, key=lambda rule: rule.rule_id)),
        )

    @property
    def rule_count(self) -> int:
        return len(self.rules)


__all__ = [
    "BannedSubstringCatalogCapability",
    "FirewallCapabilities",
    "EmailAddressCapability",
    "JSONOutputCapability",
    "IPAddressCapability",
    "MACAddressCapability",
    "IBANCapability",
    "AuthorizationHeaderCapability",
    "PaymentCardCapability",
    "PrivateKeyCapability",
    "JWTTokenCapability",
    "RuleCapability",
    "SecretCatalogCapability",
    "UnsafeURLCapability",
]
