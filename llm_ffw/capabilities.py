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
class FirewallCapabilities:
    """Safe summary of the rules, catalog, and policy pinned to one facade."""

    rules: tuple[RuleCapability, ...]
    secret_catalog: SecretCatalogCapability
    policy_id: str
    policy_version: str

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
        object.__setattr__(
            self,
            "rules",
            tuple(sorted(rules, key=lambda rule: rule.rule_id)),
        )

    @property
    def rule_count(self) -> int:
        return len(self.rules)


__all__ = [
    "FirewallCapabilities",
    "RuleCapability",
    "SecretCatalogCapability",
]
