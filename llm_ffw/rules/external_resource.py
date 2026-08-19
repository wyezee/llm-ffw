"""Bounded inspection of auto-loaded external image references."""

from dataclasses import dataclass
from html import unescape
import re
from urllib.parse import urlsplit

from ..external_resource import ExternalResourceConfig
from ..findings import Action, Severity, Span
from ..inspection import Inspection, ScanScope
from ..unsafe_url import _matches_hostname_suffix, _normalize_hostname
from .base import Rule, RuleMatch


_RESOURCE_START = re.compile(
    r"(?P<markdown>!\[)|(?P<html><img(?=[\t\n\f\r />]))",
    re.IGNORECASE | re.ASCII,
)
_COMMONMARK_ESCAPE = re.compile(
    r"\\([!\"#$%&'()*+,\-./:;<=>?@\[\]\\^_`{|}~])",
    re.ASCII,
)
_ASCII_WHITESPACE = frozenset("\t\n\f\r ")


@dataclass(frozen=True, slots=True)
class _ResourceCandidate:
    span: Span
    syntax: str


@dataclass(frozen=True, slots=True)
class _InspectionFailure:
    span: Span
    reason: str
    limit: int


def _is_backslash_escaped(text: str, start: int) -> bool:
    cursor = start - 1
    backslashes = 0
    while cursor >= 0 and text[cursor] == "\\":
        backslashes += 1
        cursor -= 1
    return backslashes % 2 == 1


def _markdown_tail_is_valid(text: str, cursor: int, boundary: int) -> bool:
    while cursor < boundary and text[cursor] in _ASCII_WHITESPACE:
        cursor += 1
    if cursor >= boundary:
        return False
    if text[cursor] == ")":
        return True
    opening = text[cursor]
    closing = {"'": "'", '"': '"', "(": ")"}.get(opening)
    if closing is None:
        return False
    cursor += 1
    while cursor < boundary:
        if text[cursor] == "\\" and cursor + 1 < boundary:
            cursor += 2
            continue
        if text[cursor] == closing:
            cursor += 1
            break
        if text[cursor] in "\n\r" and opening != "(":
            return False
        cursor += 1
    else:
        return False
    while cursor < boundary and text[cursor] in _ASCII_WHITESPACE:
        cursor += 1
    return cursor < boundary and text[cursor] == ")"


def _find_markdown_destination(
    text: str,
    start: int,
    limit: int,
) -> tuple[Span | None, _InspectionFailure | None]:
    boundary = min(len(text), start + limit)
    cursor = start + 2
    depth = 1
    while cursor < boundary:
        character = text[cursor]
        if character == "\\" and cursor + 1 < boundary:
            cursor += 2
            continue
        if character == "[":
            depth += 1
        elif character == "]":
            depth -= 1
            if depth == 0:
                break
        cursor += 1
    if depth != 0:
        failure = (
            _InspectionFailure(
                Span(start, boundary),
                "markup_limit_exceeded",
                limit,
            )
            if boundary < len(text)
            else None
        )
        return None, failure
    cursor += 1
    if cursor >= boundary or text[cursor] != "(":
        return None, None
    cursor += 1
    while cursor < boundary and text[cursor] in _ASCII_WHITESPACE:
        cursor += 1
    if cursor >= boundary:
        return None, None

    if text[cursor] == "<":
        destination_start = cursor + 1
        cursor += 1
        while cursor < boundary:
            if text[cursor] in "\n\r":
                return None, None
            if text[cursor] == "\\" and cursor + 1 < boundary:
                cursor += 2
                continue
            if text[cursor] == ">":
                span = Span(destination_start, cursor)
                return (
                    (span, None)
                    if _markdown_tail_is_valid(text, cursor + 1, boundary)
                    else (None, None)
                )
            cursor += 1
        return None, (
            _InspectionFailure(
                Span(start, boundary),
                "markup_limit_exceeded",
                limit,
            )
            if boundary < len(text)
            else None
        )

    destination_start = cursor
    parenthesis_depth = 0
    while cursor < boundary:
        character = text[cursor]
        if character == "\\" and cursor + 1 < boundary:
            cursor += 2
            continue
        if character in _ASCII_WHITESPACE:
            break
        if character == "(":
            parenthesis_depth += 1
        elif character == ")":
            if parenthesis_depth == 0:
                break
            parenthesis_depth -= 1
        cursor += 1
    if cursor == destination_start or parenthesis_depth != 0:
        return None, None
    if not _markdown_tail_is_valid(text, cursor, boundary):
        return None, None
    return Span(destination_start, cursor), None


def _find_html_tag_end(text: str, start: int, limit: int) -> int | None:
    boundary = min(len(text), start + limit)
    quote: str | None = None
    cursor = start + 4
    while cursor < boundary:
        character = text[cursor]
        if quote is not None:
            if character == quote:
                quote = None
        elif character in ("'", '"'):
            quote = character
        elif character == ">":
            return cursor
        cursor += 1
    return None


def _find_html_src(text: str, start: int, end: int) -> Span | None:
    cursor = start + 4
    while cursor < end:
        while cursor < end and (
            text[cursor] in _ASCII_WHITESPACE or text[cursor] == "/"
        ):
            cursor += 1
        name_start = cursor
        while cursor < end and (
            text[cursor].isalnum() or text[cursor] in ("-", "_", ":")
        ):
            cursor += 1
        if cursor == name_start:
            cursor += 1
            continue
        name = text[name_start:cursor].lower()
        while cursor < end and text[cursor] in _ASCII_WHITESPACE:
            cursor += 1
        if cursor >= end or text[cursor] != "=":
            continue
        cursor += 1
        while cursor < end and text[cursor] in _ASCII_WHITESPACE:
            cursor += 1
        if cursor >= end:
            return None
        quote = text[cursor] if text[cursor] in ("'", '"') else None
        if quote is not None:
            value_start = cursor + 1
            value_end = text.find(quote, value_start, end)
            if value_end < 0:
                return None
            cursor = value_end + 1
        else:
            value_start = cursor
            while cursor < end and text[cursor] not in _ASCII_WHITESPACE:
                cursor += 1
            value_end = cursor
        while value_start < value_end and text[value_start] in _ASCII_WHITESPACE:
            value_start += 1
        while value_end > value_start and text[value_end - 1] in _ASCII_WHITESPACE:
            value_end -= 1
        if name == "src" and value_start < value_end:
            return Span(value_start, value_end)
    return None


def _find_candidates(
    text: str,
    config: ExternalResourceConfig,
) -> tuple[
    tuple[_ResourceCandidate, ...],
    _InspectionFailure | None,
]:
    candidates: list[_ResourceCandidate] = []
    for marker in _RESOURCE_START.finditer(text):
        failure: _InspectionFailure | None = None
        if marker.group("markdown") is not None:
            if _is_backslash_escaped(text, marker.start()):
                continue
            span, failure = _find_markdown_destination(
                text,
                marker.start(),
                config.max_markup_chars,
            )
            syntax = "markdown_image"
        else:
            tag_end = _find_html_tag_end(
                text,
                marker.start(),
                config.max_markup_chars,
            )
            if tag_end is None:
                boundary = min(
                    len(text), marker.start() + config.max_markup_chars
                )
                span = None
                failure = _InspectionFailure(
                    Span(marker.start(), boundary),
                    (
                        "markup_limit_exceeded"
                        if boundary < len(text)
                        else "unterminated_markup"
                    ),
                    config.max_markup_chars,
                )
            else:
                span = _find_html_src(text, marker.start(), tag_end)
            syntax = "html_img_src"
        if failure is not None:
            return tuple(candidates), failure
        if span is None:
            continue
        if len(candidates) >= config.max_candidates:
            return tuple(candidates), _InspectionFailure(
                Span(span.start, len(text)),
                "candidate_limit_exceeded",
                config.max_candidates,
            )
        candidates.append(_ResourceCandidate(span, syntax))
    return tuple(candidates), None


def _decoded_url(raw: str, syntax: str) -> str:
    decoded = unescape(raw)
    if syntax == "markdown_image":
        decoded = _COMMONMARK_ESCAPE.sub(r"\1", decoded)
    return decoded.strip()


def _is_allowed_hostname(
    hostname: str,
    allowed_hostnames: frozenset[str],
    allowed_hostname_suffixes: frozenset[str],
) -> bool:
    try:
        normalized = _normalize_hostname(hostname, allow_ip=True)
    except (TypeError, ValueError):
        return False
    return normalized in allowed_hostnames or _matches_hostname_suffix(
        normalized,
        allowed_hostname_suffixes,
    )


def _resource_risk(
    raw: str,
    syntax: str,
    allowed_hostnames: frozenset[str],
    allowed_hostname_suffixes: frozenset[str],
) -> tuple[str, str] | None:
    value = _decoded_url(raw, syntax)
    value = value.replace("\t", "").replace("\n", "").replace("\r", "")
    had_backslash = "\\" in value
    canonical_value = value.replace("\\", "/")
    scheme_relative = canonical_value.startswith("//")
    lowered = canonical_value.lower()
    if scheme_relative:
        scheme = "scheme_relative"
    elif lowered.startswith("https://"):
        scheme = "https"
    elif lowered.startswith("http://"):
        scheme = "http"
    else:
        return None
    parse_value = (
        "https:" + canonical_value if scheme_relative else canonical_value
    )
    try:
        parsed = urlsplit(parse_value)
    except ValueError:
        return "ambiguous_authority", scheme
    if not parsed.netloc:
        return "ambiguous_authority", scheme
    ambiguous_authority = had_backslash or "%" in parsed.netloc
    try:
        hostname = parsed.hostname
        parsed.port
    except ValueError:
        ambiguous_authority = True
        hostname = None
    if ambiguous_authority or hostname is None:
        return "ambiguous_authority", scheme
    if _is_allowed_hostname(
        hostname,
        allowed_hostnames,
        allowed_hostname_suffixes,
    ):
        return None
    return "hostname_not_allowed", scheme


class ExternalResourceRule(Rule):
    """Detect auto-loaded image URLs outside the trusted hostname policy."""

    RULE_ID = "output.external_resource"
    PURPOSE = "Detect Markdown or HTML image URLs outside the hostname allowlist."
    SCOPES = frozenset((ScanScope.OUTPUT,))

    def __init__(self, config: ExternalResourceConfig | None = None) -> None:
        if config is not None and not isinstance(config, ExternalResourceConfig):
            raise TypeError("config must be an ExternalResourceConfig or None")
        self._config = config if config is not None else ExternalResourceConfig()
        self._allowed_hostnames = frozenset(self._config.allowed_hostnames)
        self._allowed_hostname_suffixes = frozenset(
            self._config.allowed_hostname_suffixes
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
    def config(self) -> ExternalResourceConfig:
        return self._config

    def scan(self, inspection: Inspection) -> tuple[RuleMatch, ...]:
        if not isinstance(inspection, Inspection):
            raise TypeError("inspection must be an Inspection")
        text = inspection.text
        candidates, failure = _find_candidates(text, self._config)
        matches: list[RuleMatch] = []
        for candidate in candidates:
            if candidate.span.end - candidate.span.start > self._config.max_url_chars:
                matches.append(
                    RuleMatch(
                        span=candidate.span,
                        severity=Severity.HIGH,
                        action=Action.BLOCK,
                        message="External resource URL exceeds the inspection limit.",
                        metadata={
                            "reason": "url_limit_exceeded",
                            "limit": str(self._config.max_url_chars),
                            "resource_syntax": candidate.syntax,
                            "detector": "bounded_external_resource",
                            "span_basis": "characters",
                        },
                    )
                )
                continue
            risk = _resource_risk(
                text[candidate.span.start : candidate.span.end],
                candidate.syntax,
                self._allowed_hostnames,
                self._allowed_hostname_suffixes,
            )
            if risk is None:
                continue
            reason, scheme = risk
            matches.append(
                RuleMatch(
                    span=candidate.span,
                    severity=Severity.HIGH,
                    action=Action.REDACT,
                    message="External image resource can transmit output data.",
                    redacted_preview="[REDACTED:external_resource]",
                    metadata={
                        "reason": reason,
                        "resource_syntax": candidate.syntax,
                        "scheme": scheme,
                        "detector": "bounded_external_resource",
                        "span_basis": "characters",
                    },
                )
            )
        if failure is not None:
            matches.append(
                RuleMatch(
                    span=failure.span,
                    severity=Severity.HIGH,
                    action=Action.BLOCK,
                    message="External resource inspection limit exceeded.",
                    metadata={
                        "reason": failure.reason,
                        "limit": str(failure.limit),
                        "detector": "bounded_external_resource",
                        "span_basis": "characters",
                    },
                )
            )
        return tuple(matches)


__all__ = ["ExternalResourceRule"]
