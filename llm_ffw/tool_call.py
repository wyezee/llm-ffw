"""Provider-neutral, bounded tool-call data and schema configuration."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
import math
import string
from types import MappingProxyType
from typing import cast, Protocol, TypeAlias


JSONScalar: TypeAlias = None | bool | int | float | str
FrozenJSON: TypeAlias = (
    JSONScalar | tuple["FrozenJSON", ...] | Mapping[str, "FrozenJSON"]
)

_NAME_CHARS = frozenset(string.ascii_letters + string.digits + "_.-")
_HARD_MAX_DEPTH = 64
_HARD_MAX_NODES = 100_000
_HARD_MAX_STRING_CHARS = 1_000_000
_HARD_MAX_CONTAINER_ITEMS = 10_000
_HARD_MAX_TOOLS = 1_024


class _JSONLimits(Protocol):
    max_depth: int
    max_nodes: int
    max_total_string_chars: int
    max_object_properties: int
    max_array_items: int


def _validate_name(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")
    if len(value) > 128 or any(character not in _NAME_CHARS for character in value):
        raise ValueError(
            f"{field_name} must contain at most 128 ASCII letters, digits, "
            "'_', '.', or '-'"
        )
    return value


def _validate_call_id(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("call_id must be a non-empty string")
    if len(value) > 256 or not value.isascii() or any(
        character.isspace() or not character.isprintable() for character in value
    ):
        raise ValueError(
            "call_id must contain at most 256 printable ASCII characters "
            "without whitespace"
        )
    return value


def _freeze_json(
    value: object,
    *,
    field_name: str,
    limits: _JSONLimits | None = None,
) -> FrozenJSON:
    """Copy JSON-compatible built-ins into an immutable, hard-bounded tree."""

    nodes = 0
    string_chars = 0

    def freeze(item: object, depth: int) -> FrozenJSON:
        nonlocal nodes, string_chars
        nodes += 1
        max_nodes = _HARD_MAX_NODES if limits is None else limits.max_nodes
        max_depth = _HARD_MAX_DEPTH if limits is None else limits.max_depth
        max_string_chars = (
            _HARD_MAX_STRING_CHARS
            if limits is None
            else limits.max_total_string_chars
        )
        if nodes > max_nodes:
            raise ValueError(f"{field_name} contains too many values")
        if depth > max_depth:
            raise ValueError(f"{field_name} is nested too deeply")
        if item is None or type(item) is bool or type(item) is int:
            return item
        if type(item) is float:
            if not math.isfinite(item):
                raise ValueError(f"{field_name} must not contain non-finite numbers")
            return item
        if type(item) is str:
            string_chars += len(item)
            if string_chars > max_string_chars:
                raise ValueError(f"{field_name} contains too much string data")
            return item
        if type(item) in (list, tuple):
            sequence = cast(list[object] | tuple[object, ...], item)
            max_items = (
                _HARD_MAX_CONTAINER_ITEMS
                if limits is None
                else limits.max_array_items
            )
            if len(sequence) > max_items:
                raise ValueError(f"{field_name} contains an oversized array")
            return tuple(freeze(child, depth + 1) for child in sequence)
        if type(item) is dict:
            source = cast(dict[object, object], item)
            max_properties = (
                _HARD_MAX_CONTAINER_ITEMS
                if limits is None
                else limits.max_object_properties
            )
            if len(source) > max_properties:
                raise ValueError(f"{field_name} contains an oversized object")
            frozen: dict[str, FrozenJSON] = {}
            for key, child in source.items():
                if type(key) is not str:
                    raise TypeError(f"{field_name} object keys must be strings")
                string_chars += len(key)
                if string_chars > max_string_chars:
                    raise ValueError(f"{field_name} contains too much string data")
                frozen[key] = freeze(child, depth + 1)
            return MappingProxyType(frozen)
        raise TypeError(
            f"{field_name} must contain only JSON-compatible built-in values"
        )

    return freeze(value, 0)


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    """One allowed tool and its constrained JSON-Schema subset."""

    name: str
    parameters: Mapping[str, object] | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        _validate_name(self.name, "name")
        if self.parameters is not None and type(self.parameters) is not dict:
            raise TypeError("parameters must be a dict or None")
        frozen = (
            None
            if self.parameters is None
            else _freeze_json(self.parameters, field_name="parameters")
        )
        object.__setattr__(self, "parameters", frozen)


@dataclass(frozen=True, slots=True)
class ToolCall:
    """An immutable provider-neutral tool invocation."""

    name: str
    arguments: Mapping[str, object] | None = field(default=None, repr=False)
    call_id: str | None = field(default=None, repr=False)
    limits: "ToolCallConfig | None" = field(
        default=None,
        repr=False,
        compare=False,
        kw_only=True,
    )

    def __post_init__(self) -> None:
        _validate_name(self.name, "name")
        if self.call_id is not None:
            _validate_call_id(self.call_id)
        if self.arguments is not None and type(self.arguments) is not dict:
            raise TypeError("arguments must be a dict or None")
        limits = self.limits if self.limits is not None else ToolCallConfig()
        if not isinstance(limits, ToolCallConfig):
            raise TypeError("limits must be a ToolCallConfig or None")
        frozen = (
            None
            if self.arguments is None
            else _freeze_json(
                self.arguments,
                field_name="arguments",
                limits=limits,
            )
        )
        object.__setattr__(self, "arguments", frozen)
        object.__setattr__(self, "limits", limits)


@dataclass(frozen=True, slots=True)
class ToolCallConfig:
    """Resource limits for one tool-call validation."""

    max_depth: int = 16
    max_nodes: int = 10_000
    max_total_string_chars: int = 100_000
    max_object_properties: int = 256
    max_array_items: int = 1_024
    inspect_content: bool = True

    def __post_init__(self) -> None:
        limits = (
            ("max_depth", self.max_depth, _HARD_MAX_DEPTH),
            ("max_nodes", self.max_nodes, _HARD_MAX_NODES),
            (
                "max_total_string_chars",
                self.max_total_string_chars,
                _HARD_MAX_STRING_CHARS,
            ),
            (
                "max_object_properties",
                self.max_object_properties,
                _HARD_MAX_CONTAINER_ITEMS,
            ),
            ("max_array_items", self.max_array_items, _HARD_MAX_CONTAINER_ITEMS),
        )
        for name, value, hard_maximum in limits:
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an integer")
            if value <= 0 or value > hard_maximum:
                raise ValueError(f"{name} must be between 1 and {hard_maximum}")
        if not isinstance(self.inspect_content, bool):
            raise TypeError("inspect_content must be a boolean")


def _validate_definitions(
    definitions: object,
) -> tuple[ToolDefinition, ...]:
    if isinstance(definitions, (str, bytes)):
        raise TypeError("definitions must be an iterable of ToolDefinition values")
    try:
        values: tuple[object, ...] = tuple(
            cast(Iterable[object], definitions)
        )
    except TypeError as exc:
        raise TypeError(
            "definitions must be an iterable of ToolDefinition values"
        ) from exc
    if not values or len(values) > _HARD_MAX_TOOLS:
        raise ValueError("definitions must contain between 1 and 1024 tools")
    if any(not isinstance(item, ToolDefinition) for item in values):
        raise TypeError("definitions must contain ToolDefinition values")
    typed_values = cast(tuple[ToolDefinition, ...], values)
    names = tuple(item.name for item in typed_values)
    if len(set(names)) != len(names):
        raise ValueError("tool names must be unique")
    return tuple(sorted(typed_values, key=lambda item: item.name))


__all__ = [
    "JSONScalar",
    "FrozenJSON",
    "ToolCall",
    "ToolCallConfig",
    "ToolDefinition",
]
