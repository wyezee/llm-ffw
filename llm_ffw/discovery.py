"""Public disclosure-safe metadata for built-in rules and named presets."""

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType

from ._rule_registry import RULE_SPECS
from .facade_config import FirewallConfig
from .inspection import ScanScope
from .rules.bidi_control import BidiControlRule
from .rules.invisible_characters import InvisibleCharactersRule
from .rules.secrets import SecretsRule
from .rules.tool_call import ToolCallRule
from .rules.tool_result import ToolResultRule
from .rules.unicode_tag_smuggling import UnicodeTagSmugglingRule


class RuleActivation(str, Enum):
    """How a built-in rule becomes active in the public API."""

    DEFAULT = "default"
    OPT_IN = "opt_in"
    EXPLICIT = "explicit"


def _normalized_scopes(
    scopes: Iterable[ScanScope],
    *,
    field_name: str,
) -> tuple[ScanScope, ...]:
    try:
        values = tuple(scopes)
    except TypeError as exc:
        raise TypeError(f"{field_name} must be iterable") from exc
    if not values or any(not isinstance(scope, ScanScope) for scope in values):
        raise ValueError(f"{field_name} must contain ScanScope values")
    return tuple(sorted(set(values), key=lambda scope: scope.value))


def _non_empty(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


@dataclass(frozen=True, slots=True)
class RuleDescriptor:
    """Disclosure-safe metadata for one supported built-in rule."""

    rule_id: str
    purpose: str
    supported_scopes: tuple[ScanScope, ...]
    activation: RuleActivation
    requires_deployment_value: bool = False

    def __post_init__(self) -> None:
        _non_empty(self.rule_id, "rule_id")
        _non_empty(self.purpose, "purpose")
        object.__setattr__(
            self,
            "supported_scopes",
            _normalized_scopes(
                self.supported_scopes,
                field_name="supported_scopes",
            ),
        )
        if not isinstance(self.activation, RuleActivation):
            raise TypeError("activation must be a RuleActivation")
        if not isinstance(self.requires_deployment_value, bool):
            raise TypeError("requires_deployment_value must be a boolean")


@dataclass(frozen=True, slots=True)
class PresetRuleDescriptor:
    """One rule and its enabled scopes within a named preset."""

    rule_id: str
    scopes: tuple[ScanScope, ...]

    def __post_init__(self) -> None:
        _non_empty(self.rule_id, "rule_id")
        object.__setattr__(
            self,
            "scopes",
            _normalized_scopes(self.scopes, field_name="scopes"),
        )


@dataclass(frozen=True, slots=True)
class PresetDescriptor:
    """Disclosure-safe metadata for one self-contained named preset."""

    preset_id: str
    purpose: str
    rules: tuple[PresetRuleDescriptor, ...]

    def __post_init__(self) -> None:
        _non_empty(self.preset_id, "preset_id")
        _non_empty(self.purpose, "purpose")
        try:
            rules = tuple(self.rules)
        except TypeError as exc:
            raise TypeError("rules must be iterable") from exc
        if not rules or any(
            not isinstance(rule, PresetRuleDescriptor) for rule in rules
        ):
            raise ValueError("rules must contain PresetRuleDescriptor values")
        if len({rule.rule_id for rule in rules}) != len(rules):
            raise ValueError("preset rule IDs must be unique")
        object.__setattr__(
            self,
            "rules",
            tuple(sorted(rules, key=lambda rule: rule.rule_id)),
        )


_DEFAULT_RULE_IDS = frozenset(
    {
        "pii.payment_card",
        "secrets.detected",
        "secrets.jwt_token",
        "secrets.private_key",
        "unicode.bidi_controls",
        "unicode.invisible_characters",
        "unicode.tag_smuggling",
    }
)
_EXPLICIT_RULE_IDS = frozenset(
    {
        ToolCallRule.RULE_ID,
        ToolResultRule.RULE_ID,
    }
)
_DEPLOYMENT_VALUE_RULE_IDS = frozenset(
    {
        "content.banned_substrings",
        ToolCallRule.RULE_ID,
    }
)


def _rule_descriptor(
    rule_id: str,
    purpose: str,
    scopes: Iterable[ScanScope],
) -> RuleDescriptor:
    if rule_id in _DEFAULT_RULE_IDS:
        activation = RuleActivation.DEFAULT
    elif rule_id in _EXPLICIT_RULE_IDS:
        activation = RuleActivation.EXPLICIT
    else:
        activation = RuleActivation.OPT_IN
    return RuleDescriptor(
        rule_id=rule_id,
        purpose=purpose,
        supported_scopes=tuple(scopes),
        activation=activation,
        requires_deployment_value=rule_id in _DEPLOYMENT_VALUE_RULE_IDS,
    )


def _build_rule_descriptors() -> tuple[RuleDescriptor, ...]:
    fixed_rules = (
        SecretsRule,
        BidiControlRule,
        InvisibleCharactersRule,
        UnicodeTagSmugglingRule,
    )
    structured_rules = (ToolCallRule, ToolResultRule)
    descriptors = [
        _rule_descriptor(
            rule_type.RULE_ID,
            rule_type.PURPOSE,
            rule_type.SCOPES,
        )
        for rule_type in fixed_rules + structured_rules
    ]
    descriptors.extend(
        _rule_descriptor(
            spec.rule_id,
            spec.purpose,
            spec.supported_scopes,
        )
        for spec in RULE_SPECS
    )
    if len({item.rule_id for item in descriptors}) != len(descriptors):
        raise RuntimeError("built-in discovery rule IDs must be unique")
    return tuple(sorted(descriptors, key=lambda item: item.rule_id))


_RULE_DESCRIPTORS = _build_rule_descriptors()
_RULES_BY_ID: Mapping[str, RuleDescriptor] = MappingProxyType(
    {item.rule_id: item for item in _RULE_DESCRIPTORS}
)


def _preset_rules(
    rule_ids: Iterable[str],
    *,
    scope_overrides: Mapping[str, tuple[ScanScope, ...]] | None = None,
) -> tuple[PresetRuleDescriptor, ...]:
    overrides = scope_overrides if scope_overrides is not None else {}
    result: list[PresetRuleDescriptor] = []
    for rule_id in rule_ids:
        descriptor = _RULES_BY_ID[rule_id]
        result.append(
            PresetRuleDescriptor(
                rule_id=rule_id,
                scopes=overrides.get(rule_id, descriptor.supported_scopes),
            )
        )
    return tuple(sorted(result, key=lambda item: item.rule_id))


_PRIVACY_RULE_IDS = frozenset(
    {
        "pii.email_address",
        "pii.iban",
        "pii.ip_address",
        "pii.mac_address",
        "pii.phone_number",
    }
)
_INPUT_ONLY_PRIVACY_SCOPES: Mapping[str, tuple[ScanScope, ...]] = (
    MappingProxyType(
        {
            rule_id: (ScanScope.INPUT,)
            for rule_id in _PRIVACY_RULE_IDS
        }
    )
)
_ALL_TEXT_RULE_IDS = frozenset(
    item.rule_id
    for item in _RULE_DESCRIPTORS
    if item.activation is not RuleActivation.EXPLICIT
    and not item.requires_deployment_value
)

_PRESET_DESCRIPTORS = tuple(
    sorted(
        (
            PresetDescriptor(
                preset_id="default",
                purpose="Enable the seven-rule deterministic baseline.",
                rules=_preset_rules(_DEFAULT_RULE_IDS),
            ),
            PresetDescriptor(
                preset_id="privacy-input",
                purpose=(
                    "Add conservative input-only IP, MAC, IBAN, email, and "
                    "phone inspection to the baseline."
                ),
                rules=_preset_rules(
                    _DEFAULT_RULE_IDS | _PRIVACY_RULE_IDS,
                    scope_overrides=_INPUT_ONLY_PRIVACY_SCOPES,
                ),
            ),
            PresetDescriptor(
                preset_id="json-api",
                purpose=(
                    "Require strict JSON output and inspect unsafe URLs in "
                    "both directions in addition to the baseline."
                ),
                rules=_preset_rules(
                    _DEFAULT_RULE_IDS
                    | frozenset({"output.json.validity", "url.unsafe"})
                ),
            ),
            PresetDescriptor(
                preset_id="all-text",
                purpose=(
                    "Enable all 19 self-contained text rules across their "
                    "supported scopes with balanced policy and require valid "
                    "JSON output."
                ),
                rules=_preset_rules(_ALL_TEXT_RULE_IDS),
            ),
        ),
        key=lambda item: item.preset_id,
    )
)

_PRESET_FACTORIES: Mapping[str, Callable[[], FirewallConfig]] = MappingProxyType(
    {
        "all-text": FirewallConfig.all_text_rules,
        "default": FirewallConfig.default,
        "json-api": FirewallConfig.json_api,
        "privacy-input": FirewallConfig.privacy_input,
    }
)
if frozenset(_PRESET_FACTORIES) != frozenset(
    item.preset_id for item in _PRESET_DESCRIPTORS
):
    raise RuntimeError("preset descriptors and factories must use identical IDs")


def available_rules() -> tuple[RuleDescriptor, ...]:
    """Return safe metadata for every supported built-in rule."""

    return _RULE_DESCRIPTORS


def available_presets() -> tuple[PresetDescriptor, ...]:
    """Return safe metadata for every self-contained named preset."""

    return _PRESET_DESCRIPTORS


def config_from_preset(preset_id: str) -> FirewallConfig:
    """Construct a named immutable preset or reject an unknown identifier."""

    if not isinstance(preset_id, str):
        raise TypeError("preset_id must be a string")
    factory = _PRESET_FACTORIES.get(preset_id)
    if factory is None:
        raise ValueError("unknown preset_id")
    return factory()


__all__ = [
    "PresetDescriptor",
    "PresetRuleDescriptor",
    "RuleActivation",
    "RuleDescriptor",
    "available_presets",
    "available_rules",
    "config_from_preset",
]
