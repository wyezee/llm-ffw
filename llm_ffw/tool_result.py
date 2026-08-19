"""Provider-neutral, bounded tool-result data and batch configuration."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import cast, TypeAlias

from .tool_call import (
    FrozenJSON,
    ToolCall,
    _freeze_json,
    _validate_call_id,
    _validate_name,
)


_HARD_MAX_BATCH_ITEMS = 1_024
_HARD_MAX_DEPTH = 64
_HARD_MAX_NODES = 100_000
_HARD_MAX_STRING_CHARS = 1_000_000
_HARD_MAX_CONTAINER_ITEMS = 10_000

ToolResultContent: TypeAlias = (
    str
    | list[dict[str, object]]
    | tuple[Mapping[str, FrozenJSON], ...]
)


@dataclass(frozen=True, slots=True)
class ToolResult:
    """One immutable provider-neutral tool result."""

    call_id: str | None = field(repr=False)
    content: ToolResultContent = field(repr=False)
    name: str | None = field(default=None, repr=False)
    limits: "ToolResultConfig | None" = field(
        default=None,
        repr=False,
        compare=False,
        kw_only=True,
    )

    def __post_init__(self) -> None:
        if self.call_id is not None:
            _validate_call_id(self.call_id)
        if self.name is not None:
            _validate_name(self.name, "name")
        limits = self.limits if self.limits is not None else ToolResultConfig()
        if not isinstance(limits, ToolResultConfig):
            raise TypeError("limits must be a ToolResultConfig or None")
        if type(self.content) is str:
            if len(self.content) > limits.max_total_string_chars:
                raise ValueError("content contains too much string data")
            object.__setattr__(self, "limits", limits)
            return
        if type(self.content) not in (list, tuple):
            raise TypeError("content must be a string or list of JSON objects")
        frozen = _freeze_json(
            self.content,
            field_name="content",
            limits=limits,
        )
        if not isinstance(frozen, tuple) or any(
            not isinstance(item, Mapping) for item in frozen
        ):
            raise TypeError("content blocks must be JSON objects")
        object.__setattr__(self, "content", frozen)
        object.__setattr__(self, "limits", limits)


@dataclass(frozen=True, slots=True)
class ToolResultBatch:
    """Expected calls and returned results validated as one request unit."""

    expected_calls: tuple[ToolCall, ...] = field(repr=False)
    results: tuple[ToolResult, ...] = field(repr=False)
    limits: "ToolResultConfig | None" = field(
        default=None,
        repr=False,
        compare=False,
        kw_only=True,
    )

    def __post_init__(self) -> None:
        limits = self.limits if self.limits is not None else ToolResultConfig()
        if not isinstance(limits, ToolResultConfig):
            raise TypeError("limits must be a ToolResultConfig or None")
        expected_calls = _bounded_tuple(
            self.expected_calls,
            field_name="expected_calls",
            expected_type=ToolCall,
            maximum=limits.max_expected_calls,
        )
        results = _bounded_tuple(
            self.results,
            field_name="results",
            expected_type=ToolResult,
            maximum=limits.max_results,
        )
        resource_error = _validate_tool_result_resources(results, limits)
        if resource_error is not None:
            raise ValueError(
                "tool result batch exceeds configured resource limits: "
                f"{resource_error}"
            )
        object.__setattr__(self, "expected_calls", expected_calls)
        object.__setattr__(self, "results", results)
        object.__setattr__(self, "limits", limits)


def _bounded_tuple[ValueT](
    values: object,
    *,
    field_name: str,
    expected_type: type[ValueT],
    maximum: int = _HARD_MAX_BATCH_ITEMS,
) -> tuple[ValueT, ...]:
    if type(values) not in (list, tuple):
        raise TypeError(f"{field_name} must be a list or tuple")
    source = cast(list[object] | tuple[object, ...], values)
    result: tuple[object, ...] = tuple(source)
    if not result or len(result) > maximum:
        raise ValueError(
            f"{field_name} must contain between 1 and {maximum} values"
        )
    if any(not isinstance(item, expected_type) for item in result):
        raise TypeError(
            f"{field_name} must contain {expected_type.__name__} values"
        )
    return cast(tuple[ValueT, ...], result)


@dataclass(frozen=True, slots=True)
class ToolResultConfig:
    """Resource limits for one tool-result batch validation."""

    max_expected_calls: int = 128
    max_results: int = 128
    max_depth: int = 16
    max_nodes: int = 10_000
    max_total_string_chars: int = 100_000
    max_object_properties: int = 256
    max_array_items: int = 1_024
    inspect_content: bool = True

    def __post_init__(self) -> None:
        limits = (
            ("max_expected_calls", self.max_expected_calls, _HARD_MAX_BATCH_ITEMS),
            ("max_results", self.max_results, _HARD_MAX_BATCH_ITEMS),
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


def _validate_tool_result_resources(
    results: tuple[ToolResult, ...],
    config: ToolResultConfig,
) -> str | None:
    nodes = 0
    string_chars = 0
    stack: list[tuple[object, int]] = [
        (result.content, 0) for result in reversed(results)
    ]
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > config.max_nodes:
            return "node_limit_exceeded"
        if depth > config.max_depth:
            return "depth_limit_exceeded"
        if type(value) is str:
            string_chars += len(value)
            if string_chars > config.max_total_string_chars:
                return "string_limit_exceeded"
        elif isinstance(value, Mapping):
            string_chars += sum(len(key) for key in value)
            if string_chars > config.max_total_string_chars:
                return "string_limit_exceeded"
            if len(value) > config.max_object_properties:
                return "object_limit_exceeded"
            stack.extend(
                (child, depth + 1)
                for child in reversed(tuple(value.values()))
            )
        elif isinstance(value, tuple):
            if len(value) > config.max_array_items:
                return "array_limit_exceeded"
            stack.extend((child, depth + 1) for child in reversed(value))
    return None


__all__ = [
    "ToolResult",
    "ToolResultBatch",
    "ToolResultConfig",
    "ToolResultContent",
]
