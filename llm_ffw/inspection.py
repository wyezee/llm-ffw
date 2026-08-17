"""Immutable, capability-planned inspection data shared by scanner rules."""

from dataclasses import dataclass
from enum import Enum
import re

from .findings import Span
from .normalizers import NormalizedText, normalize_text


class ScanScope(str, Enum):
    """Kind of content crossing the language-model boundary."""

    INPUT = "input"
    OUTPUT = "output"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"


class InspectionFeature(str, Enum):
    """Derived inspection data a rule can request during construction."""

    ASCII = "ascii"
    PROMPT_CONTEXT = "prompt_context"
    UNICODE_SECURITY = "unicode_security"


@dataclass(frozen=True, slots=True)
class UnicodeSecurityCandidates:
    """Bounded candidates and overflow state from one shared search."""

    tag_runs: tuple[Span, ...]
    zero_width_space_runs: tuple[Span, ...]
    tag_runs_overflowed: bool
    zero_width_space_runs_overflowed: bool


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
    _unicode_security: UnicodeSecurityCandidates | None

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

    @property
    def unicode_security(self) -> UnicodeSecurityCandidates:
        """Return bounded Unicode candidates requested by active rules."""

        if InspectionFeature.UNICODE_SECURITY not in self._features:
            raise InspectionFeatureUnavailableError(
                "Unicode security inspection was not requested for this scan"
            )
        if self._unicode_security is None:
            raise RuntimeError("planned Unicode security inspection was not computed")
        return self._unicode_security

    def original_span(self, start: int, end: int) -> Span:
        """Translate a normalized match span to the caller's text offsets."""

        return self._normalized.original_span(start, end)


def _compute_ascii(text: str) -> bool:
    return text.isascii()


_MAX_UNICODE_RUNS_PER_KIND = 65
_BLACK_FLAG = "\U0001f3f4"
_CANCEL_TAG = "\U000e007f"


def _tagged(value: str) -> str:
    return "".join(chr(0xE0000 + ord(character)) for character in value)


_RGI_FLAG_TAG_RUNS = tuple(
    _tagged(value) + _CANCEL_TAG
    for value in ("gbeng", "gbsct", "gbwls")
)
_TAG_RUN_START_CLASS = "[\U000e0001\U000e0020-\U000e007f]"
_TAG_PAYLOAD = (
    "(?:\U000e0001[\U000e0020-\U000e007f]*"
    "|[\U000e0020-\U000e007f]+)"
)
_RGI_FLAG_ALTERNATION = "|".join(
    re.escape(value) for value in _RGI_FLAG_TAG_RUNS
)
_ASCII_TOKEN_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
)
_ZERO_WIDTH_SPACE_RUN = re.compile("\u200b+")
_TAG_RUN = re.compile(_TAG_PAYLOAD)
_INVALID_FLAG_TAG_RUN = re.compile(
    f"(?<!{_TAG_RUN_START_CLASS})"
    f"(?:"
    f"(?<!{_BLACK_FLAG}){_TAG_PAYLOAD}"
    f"|(?<={_BLACK_FLAG})"
    f"(?!(?:{_RGI_FLAG_ALTERNATION})(?!{_TAG_RUN_START_CLASS}))"
    f"{_TAG_PAYLOAD}"
    f")"
)
_UNICODE_SECURITY_RUN = re.compile(
    f"\u200b+|{_TAG_PAYLOAD}"
)
_UNICODE_SECURITY_RUN_EXCLUDING_RGI = re.compile(
    f"\u200b+|{_INVALID_FLAG_TAG_RUN.pattern}"
)


def _compute_unicode_security(text: str) -> UnicodeSecurityCandidates:
    """Collect bounded candidate runs without attacker-sized allocation."""

    # Every U+E0000..U+E0FFF code point begins with F3 A0 in UTF-8. This
    # allocation is short-lived and avoids a much slower range regex for the
    # overwhelmingly common non-tag path, including text containing U+200B.
    search_tags = b"\xf3\xa0" in text.encode("utf-8", "surrogatepass")
    tag_runs: list[Span] = []
    zero_width_space_runs: list[Span] = []
    search_from = 0
    skip_rgi_in_matcher = False
    while search_from < len(text):
        if not search_tags or len(tag_runs) >= _MAX_UNICODE_RUNS_PER_KIND:
            pattern = _ZERO_WIDTH_SPACE_RUN
        elif len(zero_width_space_runs) >= _MAX_UNICODE_RUNS_PER_KIND:
            pattern = (
                _INVALID_FLAG_TAG_RUN
                if skip_rgi_in_matcher
                else _TAG_RUN
            )
        else:
            pattern = (
                _UNICODE_SECURITY_RUN_EXCLUDING_RGI
                if skip_rgi_in_matcher
                else _UNICODE_SECURITY_RUN
            )
        match = pattern.search(text, search_from)
        if match is None:
            break
        start, end = match.span()
        if text[start] == "\u200b":
            if (
                start == 0
                or end == len(text)
                or text[start - 1] not in _ASCII_TOKEN_CHARS
                or text[end] not in _ASCII_TOKEN_CHARS
            ):
                search_from = end
                continue
            zero_width_space_runs.append(Span(start, end))
        else:
            if start > 0 and text[start - 1] == _BLACK_FLAG and any(
                end - start == len(rgi_run)
                and text.startswith(rgi_run, start, end)
                for rgi_run in _RGI_FLAG_TAG_RUNS
            ):
                search_from = end
                skip_rgi_in_matcher = True
                continue
            skip_rgi_in_matcher = False
            tag_runs.append(Span(start, end))
        search_from = end
        if (
            len(tag_runs) >= _MAX_UNICODE_RUNS_PER_KIND
            and len(zero_width_space_runs) >= _MAX_UNICODE_RUNS_PER_KIND
        ):
            break
    return UnicodeSecurityCandidates(
        tag_runs=tuple(tag_runs),
        zero_width_space_runs=tuple(zero_width_space_runs),
        tag_runs_overflowed=len(tag_runs) >= _MAX_UNICODE_RUNS_PER_KIND,
        zero_width_space_runs_overflowed=(
            len(zero_width_space_runs) >= _MAX_UNICODE_RUNS_PER_KIND
        ),
    )


def build_inspection(
    text: str,
    *,
    scope: ScanScope,
    features: frozenset[InspectionFeature],
    prompt_context: str | None,
) -> Inspection:
    """Build exactly the shared features requested by applicable rules."""

    normalized = normalize_text(text)
    needs_ascii = (
        InspectionFeature.ASCII in features
        or InspectionFeature.UNICODE_SECURITY in features
    )
    computed_ascii = _compute_ascii(normalized.text) if needs_ascii else None
    is_ascii = (
        computed_ascii if InspectionFeature.ASCII in features else None
    )
    normalized_prompt = (
        normalize_text(prompt_context)
        if prompt_context is not None
        and InspectionFeature.PROMPT_CONTEXT in features
        else None
    )
    unicode_security = None
    if InspectionFeature.UNICODE_SECURITY in features:
        unicode_security = (
            UnicodeSecurityCandidates((), (), False, False)
            if computed_ascii is True
            else _compute_unicode_security(normalized.text)
        )
    return Inspection(
        scope=scope,
        _normalized=normalized,
        _features=features,
        _is_ascii=is_ascii,
        _prompt_context=normalized_prompt,
        _unicode_security=unicode_security,
    )


__all__ = [
    "Inspection",
    "InspectionFeature",
    "InspectionFeatureUnavailableError",
    "ScanScope",
    "UnicodeSecurityCandidates",
]
