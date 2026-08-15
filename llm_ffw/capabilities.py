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
class FirewallCapabilities:
    """Safe summary of the rules, catalog, and policy pinned to one facade."""

    rules: tuple[RuleCapability, ...]
    secret_catalog: SecretCatalogCapability
    policy_id: str
    policy_version: str
    banned_substring_catalog: BannedSubstringCatalogCapability | None = None
    json_output: JSONOutputCapability | None = None
    unsafe_url: UnsafeURLCapability | None = None
    payment_card: PaymentCardCapability | None = None

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
        if self.payment_card is not None and not isinstance(
            self.payment_card, PaymentCardCapability
        ):
            raise TypeError(
                "payment_card must be a PaymentCardCapability or None"
            )
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
    "JSONOutputCapability",
    "PaymentCardCapability",
    "RuleCapability",
    "SecretCatalogCapability",
    "UnsafeURLCapability",
]
