"""Deterministic validation of provider-neutral tool results."""

from collections.abc import Mapping

from ..findings import Action, Finding, Severity, Span
from ..inspection import ScanScope
from ..tool_result import ToolResultBatch, ToolResultConfig
from .base import StructuredRule


class ToolResultBlockedError(RuntimeError):
    """Raised when tool results are not safe to consume."""

    def __init__(self, findings: tuple[Finding, ...]) -> None:
        if not findings or any(not isinstance(item, Finding) for item in findings):
            raise ValueError("findings must contain blocked Finding values")
        if any(item.action is not Action.BLOCK for item in findings):
            raise ValueError("findings must contain blocked Finding values")
        super().__init__("tool results blocked by deterministic validation")
        self.findings = findings


class ToolResultRule(StructuredRule[ToolResultBatch]):
    """Validate result linkage, uniqueness, names, shape, and resource use."""

    RULE_ID = "tools.result.validity"
    PURPOSE = "Validate bounded tool-result batches before model consumption."
    SCOPES = frozenset((ScanScope.TOOL_RESULT,))

    def __init__(self, config: ToolResultConfig | None = None) -> None:
        if config is not None and not isinstance(config, ToolResultConfig):
            raise TypeError("config must be a ToolResultConfig or None")
        self._config = config if config is not None else ToolResultConfig()

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
    def config(self) -> ToolResultConfig:
        return self._config

    def validate(self, batch: ToolResultBatch) -> tuple[Finding, ...]:
        """Return no findings for a consistent batch, otherwise one finding."""

        if not isinstance(batch, ToolResultBatch):
            raise TypeError("batch must be a ToolResultBatch")
        if len(batch.expected_calls) > self._config.max_expected_calls:
            return self._finding("expected_call_limit_exceeded", "expected_calls")
        if len(batch.results) > self._config.max_results:
            return self._finding("result_limit_exceeded", "results")

        expected: dict[str, str] = {}
        for call in batch.expected_calls:
            if call.call_id is None:
                return self._finding("expected_call_id_missing", "expected_calls")
            if call.call_id in expected:
                return self._finding("expected_call_id_duplicate", "expected_calls")
            expected[call.call_id] = call.name

        seen_results: set[str] = set()
        for result in batch.results:
            if result.call_id is None:
                return self._finding("result_call_id_missing", "results")
            if result.call_id in seen_results:
                return self._finding("result_call_id_duplicate", "results")
            seen_results.add(result.call_id)
            expected_name = expected.get(result.call_id)
            if expected_name is None:
                return self._finding("result_call_id_unmatched", "results")
            if result.name is None:
                return self._finding("result_name_missing", "results")
            if result.name != expected_name:
                return self._finding("result_name_mismatch", "results")

        resource_error = self._validate_resources(batch)
        if resource_error is not None:
            return self._finding(resource_error, "content")
        return ()

    def enforce(self, batch: ToolResultBatch) -> ToolResultBatch:
        """Return a consumable batch or raise without retaining its content."""

        findings = self.validate(batch)
        if findings:
            raise ToolResultBlockedError(findings)
        return batch

    def _validate_resources(self, batch: ToolResultBatch) -> str | None:
        nodes = 0
        string_chars = 0
        stack: list[tuple[object, int]] = [
            (result.content, 0) for result in reversed(batch.results)
        ]
        while stack:
            value, depth = stack.pop()
            nodes += 1
            if nodes > self._config.max_nodes:
                return "node_limit_exceeded"
            if depth > self._config.max_depth:
                return "depth_limit_exceeded"
            if type(value) is str:
                string_chars += len(value)
                if string_chars > self._config.max_total_string_chars:
                    return "string_limit_exceeded"
            elif isinstance(value, Mapping):
                string_chars += sum(len(key) for key in value)
                if string_chars > self._config.max_total_string_chars:
                    return "string_limit_exceeded"
                if len(value) > self._config.max_object_properties:
                    return "object_limit_exceeded"
                stack.extend(
                    (child, depth + 1)
                    for child in reversed(tuple(value.values()))
                )
            elif isinstance(value, tuple):
                if len(value) > self._config.max_array_items:
                    return "array_limit_exceeded"
                stack.extend((child, depth + 1) for child in reversed(value))
        return None

    def _finding(self, reason: str, location: str) -> tuple[Finding, ...]:
        return (
            Finding(
                rule_id=self.RULE_ID,
                severity=Severity.HIGH,
                action=Action.BLOCK,
                span=Span(0, 0),
                message="Tool result batch failed deterministic validation.",
                metadata={
                    "reason": reason,
                    "location": location,
                    "detector": "bounded_typed_tool_result",
                    "span_basis": "structured",
                },
            ),
        )


__all__ = ["ToolResultBlockedError", "ToolResultRule"]
