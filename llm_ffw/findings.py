"""Stable public data types returned by the scanner."""

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Mapping


class Severity(str, Enum):
    """Impact level assigned by a deterministic rule."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(str, Enum):
    """Recommended handling for a finding."""

    ALLOW = "allow"
    REVIEW = "review"
    REMOVE = "remove"
    REDACT = "redact"
    BLOCK = "block"


@dataclass(frozen=True, order=True, slots=True)
class Span:
    """A half-open character span in the caller's original string."""

    start: int
    end: int

    def __post_init__(self) -> None:
        if isinstance(self.start, bool) or not isinstance(self.start, int):
            raise TypeError("span start must be an integer")
        if isinstance(self.end, bool) or not isinstance(self.end, int):
            raise TypeError("span end must be an integer")
        if self.start < 0:
            raise ValueError("span start must not be negative")
        if self.end <= self.start:
            raise ValueError("span end must be greater than start")


@dataclass(frozen=True, slots=True)
class Finding:
    """An immutable, explainable scanner result."""

    rule_id: str
    severity: Severity
    action: Action
    span: Span
    message: str
    redacted_preview: str | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, str) or not self.rule_id:
            raise ValueError("rule_id must be a non-empty string")
        if not isinstance(self.severity, Severity):
            raise TypeError("severity must be a Severity")
        if not isinstance(self.action, Action):
            raise TypeError("action must be an Action")
        if not isinstance(self.span, Span):
            raise TypeError("span must be a Span")
        if not isinstance(self.message, str) or not self.message:
            raise ValueError("message must be a non-empty string")
        if self.redacted_preview is not None and not isinstance(
            self.redacted_preview, str
        ):
            raise TypeError("redacted_preview must be a string or None")
        try:
            metadata = dict(self.metadata)
        except (TypeError, ValueError) as exc:
            raise TypeError("metadata must be a mapping") from exc
        if any(not isinstance(key, str) or not isinstance(value, str) for key, value in metadata.items()):
            raise TypeError("metadata keys and values must be strings")
        object.__setattr__(self, "metadata", MappingProxyType(metadata))

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible representation without matched text."""

        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "action": self.action.value,
            "span": {"start": self.span.start, "end": self.span.end},
            "message": self.message,
            "redacted_preview": self.redacted_preview,
            "metadata": dict(self.metadata),
        }
