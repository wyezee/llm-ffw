"""Contract implemented by every scanner rule."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

from ..findings import Action, Severity, Span
from ..inspection import Inspection, InspectionFeature, ScanScope


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """Internal match whose span refers to normalized text."""

    span: Span
    severity: Severity
    action: Action
    message: str
    redacted_preview: str | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.span, Span):
            raise TypeError("span must be a Span")
        if not isinstance(self.severity, Severity):
            raise TypeError("severity must be a Severity")
        if not isinstance(self.action, Action):
            raise TypeError("action must be an Action")
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
        if any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in metadata.items()
        ):
            raise TypeError("metadata keys and values must be strings")
        object.__setattr__(self, "metadata", MappingProxyType(metadata))


class Rule(ABC):
    """Side-effect-free deterministic rule interface."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Return the stable identity for this rule's semantics."""

    @property
    @abstractmethod
    def purpose(self) -> str:
        """Return a concise description of the rule's behavior."""

    @property
    @abstractmethod
    def scopes(self) -> frozenset[ScanScope]:
        """Return the input/output directions where this rule applies."""

    @property
    def inspection_features(self) -> frozenset[InspectionFeature]:
        """Return shared derived data required by this rule."""

        return frozenset()

    @abstractmethod
    def scan(self, inspection: Inspection) -> tuple[RuleMatch, ...]:
        """Return normalized-text matches without retaining matched values."""
