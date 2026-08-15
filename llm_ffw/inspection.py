"""Immutable, capability-planned inspection data shared by scanner rules."""

from dataclasses import dataclass
from enum import Enum

from .findings import Span
from .normalizers import NormalizedText, normalize_text


class ScanScope(str, Enum):
    """Direction of text crossing the language-model boundary."""

    INPUT = "input"
    OUTPUT = "output"


class InspectionFeature(str, Enum):
    """Derived inspection data a rule can request during construction."""

    ASCII = "ascii"
    PROMPT_CONTEXT = "prompt_context"


class InspectionFeatureUnavailableError(RuntimeError):
    """Raised when a rule reads inspection data it did not declare."""


@dataclass(frozen=True, slots=True)
class Inspection:
    """One immutable normalized view and its explicitly planned features."""

    scope: ScanScope
    _normalized: NormalizedText
    _features: frozenset[InspectionFeature]
    _is_ascii: bool | None
    _prompt_context: NormalizedText | None

    @property
    def text(self) -> str:
        """Return normalized text shared by all applicable rules."""

        return self._normalized.text

    @property
    def features(self) -> frozenset[InspectionFeature]:
        """Return the immutable feature plan for this scan."""

        return self._features

    @property
    def is_ascii(self) -> bool:
        """Return the shared ASCII classification requested by active rules."""

        if InspectionFeature.ASCII not in self._features:
            raise InspectionFeatureUnavailableError(
                "ASCII inspection was not requested for this scan"
            )
        if self._is_ascii is None:
            raise RuntimeError("planned ASCII inspection was not computed")
        return self._is_ascii

    @property
    def prompt_text(self) -> str | None:
        """Return normalized prompt context when requested and supplied."""

        if InspectionFeature.PROMPT_CONTEXT not in self._features:
            raise InspectionFeatureUnavailableError(
                "prompt context was not requested for this scan"
            )
        if self._prompt_context is None:
            return None
        return self._prompt_context.text

    def original_span(self, start: int, end: int) -> Span:
        """Translate a normalized match span to the caller's text offsets."""

        return self._normalized.original_span(start, end)


def _compute_ascii(text: str) -> bool:
    return text.isascii()


def build_inspection(
    text: str,
    *,
    scope: ScanScope,
    features: frozenset[InspectionFeature],
    prompt_context: str | None,
) -> Inspection:
    """Build exactly the shared features requested by applicable rules."""

    normalized = normalize_text(text)
    is_ascii = (
        _compute_ascii(normalized.text)
        if InspectionFeature.ASCII in features
        else None
    )
    normalized_prompt = (
        normalize_text(prompt_context)
        if prompt_context is not None
        and InspectionFeature.PROMPT_CONTEXT in features
        else None
    )
    return Inspection(
        scope=scope,
        _normalized=normalized,
        _features=features,
        _is_ascii=is_ascii,
        _prompt_context=normalized_prompt,
    )


__all__ = [
    "Inspection",
    "InspectionFeature",
    "InspectionFeatureUnavailableError",
    "ScanScope",
]
