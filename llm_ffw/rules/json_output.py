"""Strict, bounded validation of an expected JSON output document."""

import json
import re
from typing import Any

from ..findings import Action, Severity, Span
from ..inspection import Inspection, ScanScope
from ..json_output import JSONOutputConfig
from .base import Rule, RuleMatch


_RAW_SURROGATE = re.compile("[\ud800-\udfff]")
_ESCAPED_SURROGATE = re.compile(
    r"\\u([dD][89a-fA-F][0-9a-fA-F]{2})"
)


class _JSONPolicyError(ValueError):
    """Internal control flow carrying only a disclosure-safe reason code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _reject_constant(_: str) -> None:
    raise _JSONPolicyError("non_finite_number")


class JSONOutputRule(Rule):
    """Require output to be one strict JSON document within fixed limits."""

    RULE_ID = "output.json.validity"
    PURPOSE = "Validate one bounded strict JSON output document."
    SCOPES = frozenset((ScanScope.OUTPUT,))

    def __init__(self, config: JSONOutputConfig | None = None) -> None:
        if config is not None and not isinstance(config, JSONOutputConfig):
            raise TypeError("config must be a JSONOutputConfig or None")
        self._config = config or JSONOutputConfig()

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
    def config(self) -> JSONOutputConfig:
        return self._config

    def scan(self, inspection: Inspection) -> tuple[RuleMatch, ...]:
        if not isinstance(inspection, Inspection):
            raise TypeError("inspection must be an Inspection")
        return self.scan_text(inspection.text)

    def scan_text(self, text: str) -> tuple[RuleMatch, ...]:
        """Validate text directly for conditional post-policy enforcement."""

        if not isinstance(text, str):
            raise TypeError("text must be a string")
        if len(text) > self._config.max_document_chars:
            return self._finding(
                text,
                reason="document_too_large",
                position=self._config.max_document_chars,
                limit_name="max_document_chars",
                limit_value=self._config.max_document_chars,
            )

        bounded_error = self._preflight(text)
        if bounded_error is not None:
            return bounded_error

        object_pairs_hook = (
            self._unique_object
            if self._config.reject_duplicate_keys
            else None
        )
        try:
            json.loads(
                text,
                object_pairs_hook=object_pairs_hook,
                parse_constant=_reject_constant,
                parse_float=self._discard_number,
                parse_int=self._discard_number,
            )
        except json.JSONDecodeError as exc:
            return self._finding(
                text,
                reason="invalid_syntax",
                position=exc.pos,
            )
        except _JSONPolicyError as exc:
            return self._finding(text, reason=exc.reason, position=0)
        except (RecursionError, ValueError):
            # This is a defensive boundary for decoder failures that do not use
            # JSONDecodeError. Never publish exception text derived from input.
            return self._finding(
                text,
                reason="decoder_limit_exceeded",
                position=0,
            )
        return ()

    def _discard_number(self, value: str) -> None:
        # The decoder has already validated the JSON number grammar. Bound the
        # downstream token and avoid allocating attacker-sized Python numbers.
        if len(value) > self._config.max_number_chars:
            raise _JSONPolicyError("number_too_long")
        return None

    def _preflight(self, text: str) -> tuple[RuleMatch, ...] | None:
        surrogate_error = self._surrogate_error(text)
        if surrogate_error is not None:
            return surrogate_error
        depth = 0
        structure_tokens = 0
        in_string = False
        escaped = False
        for position, character in enumerate(text):
            if in_string:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    in_string = False
                continue
            if character == '"':
                in_string = True
                continue
            if character in "[{":
                depth += 1
                structure_tokens += 1
                if depth > self._config.max_depth:
                    return self._finding(
                        text,
                        reason="max_depth_exceeded",
                        position=position,
                        limit_name="max_depth",
                        limit_value=self._config.max_depth,
                    )
            elif character in "]}":
                depth -= 1
            elif character in ",:":
                structure_tokens += 1
            if structure_tokens > self._config.max_structure_tokens:
                return self._finding(
                    text,
                    reason="max_structure_tokens_exceeded",
                    position=position,
                    limit_name="max_structure_tokens",
                    limit_value=self._config.max_structure_tokens,
                )
        return None

    def _surrogate_error(self, text: str) -> tuple[RuleMatch, ...] | None:
        raw = _RAW_SURROGATE.search(text)
        if raw is not None:
            return self._finding(
                text,
                reason="unpaired_unicode_surrogate",
                position=raw.start(),
            )

        pending_high_position: int | None = None
        pending_low_position = -1
        for match in _ESCAPED_SURROGATE.finditer(text):
            if not self._escape_is_active(text, match.start()):
                continue
            code_point = int(match.group(1), 16)
            if pending_high_position is not None:
                if (
                    match.start() == pending_low_position
                    and 0xDC00 <= code_point <= 0xDFFF
                ):
                    pending_high_position = None
                    pending_low_position = -1
                    continue
                return self._finding(
                    text,
                    reason="unpaired_unicode_surrogate",
                    position=pending_high_position,
                )
            if 0xD800 <= code_point <= 0xDBFF:
                pending_high_position = match.start()
                pending_low_position = match.end()
            else:
                return self._finding(
                    text,
                    reason="unpaired_unicode_surrogate",
                    position=match.start(),
                )
        if pending_high_position is not None:
            return self._finding(
                text,
                reason="unpaired_unicode_surrogate",
                position=pending_high_position,
            )
        return None

    @staticmethod
    def _escape_is_active(text: str, position: int) -> bool:
        preceding_backslashes = 0
        cursor = position - 1
        while cursor >= 0 and text[cursor] == "\\":
            preceding_backslashes += 1
            cursor -= 1
        return preceding_backslashes % 2 == 0

    @staticmethod
    def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _JSONPolicyError("duplicate_object_key")
            result[key] = value
        return result

    @staticmethod
    def _span(text: str, position: int) -> Span:
        bounded = min(max(position, 0), len(text))
        if bounded < len(text):
            return Span(bounded, bounded + 1)
        return Span(bounded, bounded)

    def _finding(
        self,
        text: str,
        *,
        reason: str,
        position: int,
        limit_name: str | None = None,
        limit_value: int | None = None,
    ) -> tuple[RuleMatch, ...]:
        metadata = {
            "detector": "stdlib_json_decoder",
            "reason": reason,
            "span_basis": "characters",
        }
        if limit_name is not None and limit_value is not None:
            metadata["limit_name"] = limit_name
            metadata["limit"] = str(limit_value)
        return (
            RuleMatch(
                span=self._span(text, position),
                severity=Severity.HIGH,
                action=Action.BLOCK,
                message="Output is not an acceptable JSON document.",
                metadata=metadata,
            ),
        )


__all__ = ["JSONOutputRule"]
