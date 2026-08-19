"""Deterministic credential-assignment detection."""

from dataclasses import dataclass
import re

from ..credential_assignment import (
    CredentialAssignmentConfig,
    _matches_builtin_keyword,
)
from ..findings import Action, Severity, Span
from ..inspection import Inspection, ScanScope
from .base import Rule, RuleMatch


# Discovery is anchored to assignment-like line starts or JSON/object field
# separators. All quantifiers are bounded or simple whitespace runs; values are
# parsed with explicit bounds instead of regex quantifiers.
_ASSIGNMENT_PREFIX = re.compile(
    r"(?P<lead>^[ \t]*(?:export[ \t]+)?|[{,][ \t\r\n]*)"
    r"(?:"
    r"(?P<key_quote>[\"'])(?P<quoted_key>[A-Za-z][A-Za-z0-9_.-]{1,127})"
    r"(?P=key_quote)"
    r"|(?P<plain_key>[A-Za-z][A-Za-z0-9_.-]{1,127})"
    r")"
    r"[ \t]*(?P<delimiter>[:=])[ \t]*",
    re.ASCII | re.IGNORECASE | re.MULTILINE,
)
_PLACEHOLDERS = frozenset(
    (
        "change-me",
        "change_me",
        "changeme",
        "dummy",
        "example",
        "false",
        "masked",
        "none",
        "null",
        "password",
        "redacted",
        "sample",
        "secret",
        "test",
        "token",
        "true",
        "xxx",
        "xxxx",
        "your key here",
        "your password",
        "your-key-here",
        "your-password",
        "your_key_here",
        "your_password",
    )
)


@dataclass(frozen=True, slots=True)
class _ValueSpan:
    start: int
    end: int
    candidate_end: int
    closed: bool
    oversized: bool
    quoted: bool


def _normalized_key(value: str) -> str:
    return value.lower().replace("-", "_").replace(".", "_")


def _is_placeholder(value: str) -> bool:
    candidate = value.strip().lower()
    if candidate in _PLACEHOLDERS:
        return True
    wrappers = (("<", ">"), ("${", "}"), ("{{", "}}"), ("%", "%"))
    return any(
        len(candidate) > len(start) + len(end)
        and candidate.startswith(start)
        and candidate.endswith(end)
        for start, end in wrappers
    )


def _line_end(text: str, start: int) -> int:
    newline = text.find("\n", start)
    end = len(text) if newline < 0 else newline
    return end - 1 if end > start and text[end - 1] == "\r" else end


def _quoted_value_span(
    text: str,
    start: int,
    line_end: int,
    quote: str,
    maximum: int,
) -> _ValueSpan:
    cursor = start + 1
    value_start = cursor
    scan_end = min(line_end, value_start + maximum + 1)
    while cursor < scan_end:
        character = text[cursor]
        if character == "\\" and quote == '"' and cursor + 1 < scan_end:
            cursor += 2
            continue
        if character == quote:
            if quote == "'" and cursor + 1 < scan_end and text[cursor + 1] == quote:
                cursor += 2
                continue
            return _ValueSpan(
                value_start,
                cursor,
                cursor + 1,
                True,
                False,
                True,
            )
        cursor += 1
    return _ValueSpan(
        value_start,
        line_end,
        line_end,
        False,
        line_end - value_start > maximum,
        True,
    )


def _unquoted_value_span(
    text: str,
    start: int,
    line_end: int,
    maximum: int,
) -> _ValueSpan:
    scan_end = min(line_end, start + maximum + 1)
    cursor = start
    while cursor < scan_end and text[cursor] not in " \t,;#":
        cursor += 1
    oversized = (
        cursor - start > maximum
        or (cursor == scan_end and scan_end < line_end)
    )
    return _ValueSpan(
        start,
        line_end if oversized else cursor,
        line_end if oversized else cursor,
        True,
        oversized,
        False,
    )


def _value_span(text: str, start: int, maximum: int) -> _ValueSpan:
    line_end = _line_end(text, start)
    if start >= line_end:
        return _ValueSpan(start, start, start, True, False, False)
    quote = text[start]
    if quote in "\"'":
        return _quoted_value_span(text, start, line_end, quote, maximum)
    return _unquoted_value_span(text, start, line_end, maximum)


class CredentialAssignmentRule(Rule):
    """Find credentials assigned to high-confidence field names."""

    RULE_ID = "secrets.credential_assignment"
    PURPOSE = "Detect credentials assigned to high-confidence field names."
    SCOPES = frozenset((ScanScope.INPUT, ScanScope.OUTPUT))

    def __init__(self, config: CredentialAssignmentConfig | None = None) -> None:
        if config is not None and not isinstance(
            config, CredentialAssignmentConfig
        ):
            raise TypeError(
                "config must be a CredentialAssignmentConfig or None"
            )
        self._config = config or CredentialAssignmentConfig()
        self._additional_keywords = frozenset(self._config.additional_keywords)

    @property
    def rule_id(self) -> str:
        return self.RULE_ID

    @property
    def purpose(self) -> str:
        return self.PURPOSE

    @property
    def scopes(self) -> frozenset[ScanScope]:
        return frozenset(self._config.scopes)

    @property
    def config(self) -> CredentialAssignmentConfig:
        return self._config

    def scan(self, inspection: Inspection) -> tuple[RuleMatch, ...]:
        if not isinstance(inspection, Inspection):
            raise TypeError("inspection must be an Inspection")
        text = inspection.text
        matches: list[RuleMatch] = []
        candidate_count = 0
        for prefix in _ASSIGNMENT_PREFIX.finditer(text):
            raw_key = prefix.group("quoted_key") or prefix.group("plain_key")
            key = _normalized_key(raw_key)
            custom = key in self._additional_keywords
            if not custom and not _matches_builtin_keyword(key):
                continue
            candidate_count += 1
            if candidate_count > self._config.max_candidates:
                matches.append(
                    RuleMatch(
                        span=Span(prefix.start(), len(text)),
                        severity=Severity.HIGH,
                        action=Action.BLOCK,
                        message=(
                            "Credential-assignment inspection limit exceeded."
                        ),
                        metadata={
                            "reason": "candidate_limit_exceeded",
                            "limit": str(self._config.max_candidates),
                            "detector": "bounded_credential_assignment",
                            "span_basis": "characters",
                        },
                    )
                )
                break

            value = _value_span(
                text,
                prefix.end(),
                self._config.max_value_chars,
            )
            if value.end <= value.start:
                continue
            if not value.quoted and text[value.start] in "[{":
                continue
            if value.oversized:
                matches.append(
                    RuleMatch(
                        span=Span(value.start, value.candidate_end),
                        severity=Severity.HIGH,
                        action=Action.BLOCK,
                        message="Assigned credential exceeds inspection limit.",
                        metadata={
                            "reason": "credential_limit_exceeded",
                            "limit": str(self._config.max_value_chars),
                            "syntax": (
                                "quoted" if value.quoted else "unquoted"
                            ),
                            "custom_keyword": str(custom).lower(),
                            "detector": "bounded_credential_assignment",
                            "span_basis": "characters",
                        },
                    )
                )
                continue
            candidate = text[value.start : value.end]
            if len(candidate) < 4 or _is_placeholder(candidate):
                continue
            matches.append(
                RuleMatch(
                    span=Span(value.start, value.end),
                    severity=Severity.HIGH,
                    action=Action.REDACT,
                    message="Assigned credential detected.",
                    redacted_preview="[REDACTED:assigned_credential]",
                    metadata={
                        "reason": (
                            "assigned_credential"
                            if value.closed
                            else "malformed_assigned_credential"
                        ),
                        "syntax": "quoted" if value.quoted else "unquoted",
                        "delimiter": prefix.group("delimiter"),
                        "custom_keyword": str(custom).lower(),
                        "detector": "bounded_credential_assignment",
                        "span_basis": "characters",
                    },
                )
            )
        return tuple(matches)


__all__ = ["CredentialAssignmentRule"]
