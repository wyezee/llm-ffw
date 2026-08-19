"""Deterministic validation of provider-neutral tool calls."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import cast, TYPE_CHECKING

from ..findings import Action, Finding, Severity, Span
from ..inspection import ScanScope
from ..structured_content import first_structured_content_violation
from ..tool_call import (
    FrozenJSON,
    ToolCall,
    ToolCallConfig,
    ToolDefinition,
    _validate_definitions,
)
from .base import StructuredRule

if TYPE_CHECKING:
    from ..engine import RuleScanner


_SCHEMA_TYPES = frozenset(
    ("object", "array", "string", "number", "integer", "boolean", "null")
)
_COMMON_KEYWORDS = frozenset(("type", "enum"))
_TYPE_KEYWORDS = {
    "object": frozenset(("properties", "required", "additionalProperties")),
    "array": frozenset(("items",)),
    "string": frozenset(),
    "number": frozenset(),
    "integer": frozenset(),
    "boolean": frozenset(),
    "null": frozenset(),
}
_MAX_SCHEMA_DEPTH = 16
_MAX_SCHEMA_NODES = 2_048
_MAX_ENUM_VALUES = 64


@dataclass(frozen=True, slots=True)
class _CompiledSchema:
    value_type: str
    properties: Mapping[str, "_CompiledSchema"]
    required: frozenset[str]
    additional_properties: bool
    items: "_CompiledSchema | None"
    enum: tuple[object, ...] | None


@dataclass(frozen=True, slots=True)
class _ValidationError:
    reason: str
    location: str


class ToolCallBlockedError(RuntimeError):
    """Raised when a tool call is not safe to execute."""

    def __init__(self, findings: tuple[Finding, ...]) -> None:
        if not findings or any(not isinstance(item, Finding) for item in findings):
            raise ValueError("findings must contain blocked Finding values")
        if any(item.action is not Action.BLOCK for item in findings):
            raise ValueError("findings must contain blocked Finding values")
        super().__init__("tool call blocked by deterministic validation")
        self.findings = findings


def _enum_value_matches_type(value: object, expected: str) -> bool:
    if expected == "string":
        return type(value) is str
    if expected == "integer":
        return type(value) is int
    if expected == "number":
        return type(value) in (int, float)
    if expected == "boolean":
        return type(value) is bool
    if expected == "null":
        return value is None
    return False


def _compile_schema(schema: object) -> _CompiledSchema:
    nodes = 0

    def compile_node(value: object, depth: int, location: str) -> _CompiledSchema:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_SCHEMA_NODES:
            raise ValueError("tool schema contains too many nodes")
        if depth > _MAX_SCHEMA_DEPTH:
            raise ValueError("tool schema is nested too deeply")
        if not isinstance(value, Mapping):
            raise TypeError(f"schema at {location} must be an object")
        value_type = value.get("type")
        if value_type not in _SCHEMA_TYPES:
            raise ValueError(f"schema at {location} must declare one supported type")
        allowed = _COMMON_KEYWORDS | _TYPE_KEYWORDS[value_type]
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"schema at {location} contains unsupported keywords")

        enum_value = value.get("enum")
        enum: tuple[object, ...] | None = None
        if enum_value is not None:
            if not isinstance(enum_value, tuple) or not enum_value:
                raise ValueError(f"enum at {location} must be a non-empty array")
            if len(enum_value) > _MAX_ENUM_VALUES:
                raise ValueError(f"enum at {location} contains too many values")
            if any(
                type(item) not in (type(None), bool, int, float, str)
                for item in enum_value
            ):
                raise ValueError(f"enum at {location} must contain only scalar values")
            if any(
                not _enum_value_matches_type(item, value_type)
                for item in enum_value
            ):
                raise ValueError(
                    f"enum at {location} must match the declared scalar type"
                )
            enum = enum_value

        properties: dict[str, _CompiledSchema] = {}
        required: frozenset[str] = frozenset()
        additional_properties = True
        items = None
        if value_type == "object":
            if "additionalProperties" not in value:
                raise ValueError(
                    f"object schema at {location} must explicitly declare "
                    "additionalProperties"
                )
            raw_properties = value.get("properties", {})
            if not isinstance(raw_properties, Mapping):
                raise TypeError(f"properties at {location} must be an object")
            for name, child in raw_properties.items():
                properties[name] = compile_node(
                    child,
                    depth + 1,
                    f"{location}/properties/{name}",
                )
            raw_required = value.get("required", ())
            if not isinstance(raw_required, tuple) or any(
                type(item) is not str for item in raw_required
            ):
                raise TypeError(f"required at {location} must be an array of strings")
            if len(set(raw_required)) != len(raw_required):
                raise ValueError(f"required at {location} must not contain duplicates")
            required = frozenset(raw_required)
            if not required <= properties.keys():
                raise ValueError(
                    f"required at {location} must name declared properties"
                )
            raw_additional = value["additionalProperties"]
            if type(raw_additional) is not bool:
                raise TypeError(f"additionalProperties at {location} must be a boolean")
            additional_properties = raw_additional
        elif value_type == "array":
            if "items" not in value:
                raise ValueError(f"array schema at {location} must declare items")
            items = compile_node(value["items"], depth + 1, f"{location}/items")

        return _CompiledSchema(
            value_type=value_type,
            properties=properties,
            required=required,
            additional_properties=additional_properties,
            items=items,
            enum=enum,
        )

    return compile_node(schema, 0, "parameters")


def _matches_type(value: FrozenJSON, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, Mapping)
    if expected == "array":
        return isinstance(value, tuple)
    if expected == "string":
        return type(value) is str
    if expected == "integer":
        return type(value) is int
    if expected == "number":
        return type(value) in (int, float)
    if expected == "boolean":
        return type(value) is bool
    return value is None


class ToolCallRule(StructuredRule[ToolCall]):
    """Allow only declared tools whose arguments satisfy a safe schema subset."""

    RULE_ID = "tools.call.validity"
    PURPOSE = "Validate tool allowlisting and bounded typed arguments before execution."
    SCOPES = frozenset((ScanScope.TOOL_CALL,))

    def __init__(
        self,
        definitions: Iterable[ToolDefinition],
        config: ToolCallConfig | None = None,
        *,
        content_scanner: "RuleScanner | None" = None,
    ) -> None:
        from ..engine import RuleScanner

        self._definitions = _validate_definitions(definitions)
        if config is not None and not isinstance(config, ToolCallConfig):
            raise TypeError("config must be a ToolCallConfig or None")
        self._config = config if config is not None else ToolCallConfig()
        if content_scanner is not None and not isinstance(
            content_scanner, RuleScanner
        ):
            raise TypeError("content_scanner must be a RuleScanner or None")
        if not self._config.inspect_content and content_scanner is not None:
            raise ValueError(
                "content_scanner requires inspect_content=True"
            )
        self._content_scanner = (
            content_scanner if content_scanner is not None else RuleScanner()
        ) if self._config.inspect_content else None
        if (
            self._content_scanner is not None
            and self._content_scanner.config.max_input_chars
            < self._config.max_total_string_chars
        ):
            raise ValueError(
                "content_scanner max_input_chars must cover "
                "max_total_string_chars"
            )
        self._schemas = {
            definition.name: (
                None
                if definition.parameters is None
                else _compile_schema(definition.parameters)
            )
            for definition in self._definitions
        }

    @property
    def rule_id(self) -> str:
        return self.RULE_ID

    @property
    def purpose(self) -> str:
        return self.PURPOSE

    @property
    def scopes(self) -> frozenset[ScanScope]:
        return self.SCOPES

    @property
    def definitions(self) -> tuple[ToolDefinition, ...]:
        return self._definitions

    @property
    def config(self) -> ToolCallConfig:
        return self._config

    def validate(self, call: ToolCall) -> tuple[Finding, ...]:
        """Return no findings for an executable call, otherwise one safe finding."""

        if not isinstance(call, ToolCall):
            raise TypeError("call must be a ToolCall")
        if call.name not in self._schemas:
            return self._finding("tool_not_allowed", "tool")
        schema = self._schemas[call.name]
        if schema is None:
            if call.arguments is not None:
                return self._finding("arguments_not_allowed", "arguments")
            return ()
        if call.arguments is None:
            return self._finding("arguments_required", "arguments")

        error = self._validate_value(cast(FrozenJSON, call.arguments), schema)
        if error is not None:
            return self._finding(error.reason, error.location)
        if self._content_scanner is not None:
            violation = first_structured_content_violation(
                (call.arguments,),
                scanner=self._content_scanner,
                scope=ScanScope.OUTPUT,
            )
            if violation is not None:
                return self._finding(
                    "content_policy_violation",
                    "arguments",
                    content_rule_id=violation.rule_id,
                    content_action=violation.action.value,
                )
        return ()

    def enforce(self, call: ToolCall) -> ToolCall:
        """Return an executable call or raise without retaining its arguments."""

        findings = self.validate(call)
        if findings:
            raise ToolCallBlockedError(findings)
        return call

    def _validate_value(
        self,
        root: FrozenJSON,
        root_schema: _CompiledSchema,
    ) -> _ValidationError | None:
        nodes = 0
        string_chars = 0
        stack: list[tuple[FrozenJSON, _CompiledSchema | None, int, str]] = [
            (root, root_schema, 0, "arguments")
        ]
        while stack:
            value, schema, depth, location = stack.pop()
            nodes += 1
            if nodes > self._config.max_nodes:
                return _ValidationError("node_limit_exceeded", location)
            if depth > self._config.max_depth:
                return _ValidationError("depth_limit_exceeded", location)
            if schema is not None:
                if not _matches_type(value, schema.value_type):
                    return _ValidationError("type_mismatch", location)
                if schema.enum is not None and value not in schema.enum:
                    return _ValidationError("enum_mismatch", location)
            if type(value) is str:
                string_chars += len(value)
                if string_chars > self._config.max_total_string_chars:
                    return _ValidationError("string_limit_exceeded", location)
            elif isinstance(value, Mapping):
                string_chars += sum(len(key) for key in value)
                if string_chars > self._config.max_total_string_chars:
                    return _ValidationError("string_limit_exceeded", location)
                if len(value) > self._config.max_object_properties:
                    return _ValidationError("object_limit_exceeded", location)
                if schema is not None:
                    missing = schema.required - value.keys()
                    if missing:
                        return _ValidationError("required_property_missing", location)
                    if (
                        not schema.additional_properties
                        and not value.keys() <= schema.properties.keys()
                    ):
                        return _ValidationError(
                            "additional_property_forbidden", location
                        )
                for name in reversed(tuple(value)):
                    child_schema = (
                        None if schema is None else schema.properties.get(name)
                    )
                    child_location = (
                        f"{location}/{name}"
                        if child_schema is not None
                        else f"{location}/<additional>"
                    )
                    stack.append(
                        (value[name], child_schema, depth + 1, child_location)
                    )
            elif isinstance(value, tuple):
                if len(value) > self._config.max_array_items:
                    return _ValidationError("array_limit_exceeded", location)
                if schema is not None and schema.items is None:
                    raise RuntimeError("compiled array schema has no items")
                for index in range(len(value) - 1, -1, -1):
                    stack.append(
                        (
                            value[index],
                            None if schema is None else schema.items,
                            depth + 1,
                            f"{location}/{index}",
                        )
                    )
        return None

    def _finding(
        self,
        reason: str,
        location: str,
        *,
        content_rule_id: str | None = None,
        content_action: str | None = None,
    ) -> tuple[Finding, ...]:
        metadata = {
            "reason": reason,
            "location": location,
            "detector": "bounded_typed_tool_call",
            "span_basis": "structured",
        }
        if content_rule_id is not None and content_action is not None:
            metadata["content_rule_id"] = content_rule_id
            metadata["content_action"] = content_action
        return (
            Finding(
                rule_id=self.RULE_ID,
                severity=Severity.HIGH,
                action=Action.BLOCK,
                span=Span(0, 0),
                message="Tool call failed deterministic validation.",
                metadata=metadata,
            ),
        )


__all__ = ["ToolCallBlockedError", "ToolCallRule"]
