"""Deterministic validation of provider-neutral tool results."""

from typing import TYPE_CHECKING

from ..findings import Action, Finding, Severity, Span
from ..inspection import ScanScope
from ..structured_content import first_structured_content_violation
from ..tool_call import ToolCall
from ..tool_result import (
    ToolResult,
    ToolResultBatch,
    ToolResultConfig,
    ToolResultContent,
    _validate_tool_result_resources,
)
from .base import StructuredRule

if TYPE_CHECKING:
    from ..engine import RuleScanner


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

    def __init__(
        self,
        config: ToolResultConfig | None = None,
        *,
        content_scanner: "RuleScanner | None" = None,
    ) -> None:
        from ..engine import RuleScanner

        if config is not None and not isinstance(config, ToolResultConfig):
            raise TypeError("config must be a ToolResultConfig or None")
        self._config = config if config is not None else ToolResultConfig()
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
        if self._content_scanner is not None:
            violation = first_structured_content_violation(
                tuple(result.content for result in batch.results),
                scanner=self._content_scanner,
                scope=ScanScope.INPUT,
            )
            if violation is not None:
                return self._finding(
                    "content_policy_violation",
                    "content",
                    content_rule_id=violation.rule_id,
                    content_action=violation.action.value,
                )
        return ()

    def enforce(self, batch: ToolResultBatch) -> ToolResultBatch:
        """Return a consumable batch or raise without retaining its content."""

        findings = self.validate(batch)
        if findings:
            raise ToolResultBlockedError(findings)
        return batch

    def build_result(
        self,
        call_id: str | None,
        content: ToolResultContent,
        name: str | None = None,
    ) -> ToolResult:
        """Copy untrusted result content under this rule's limits."""

        return ToolResult(call_id, content, name, limits=self._config)

    def build_batch(
        self,
        expected_calls: list[ToolCall] | tuple[ToolCall, ...],
        results: list[ToolResult] | tuple[ToolResult, ...],
    ) -> ToolResultBatch:
        """Assemble a batch under this rule's aggregate limits."""

        return ToolResultBatch(
            tuple(expected_calls),
            tuple(results),
            limits=self._config,
        )

    def _validate_resources(self, batch: ToolResultBatch) -> str | None:
        return _validate_tool_result_resources(batch.results, self._config)

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
            "detector": "bounded_typed_tool_result",
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
                message="Tool result batch failed deterministic validation.",
                metadata=metadata,
            ),
        )


__all__ = ["ToolResultBlockedError", "ToolResultRule"]
