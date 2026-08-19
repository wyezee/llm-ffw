"""Deterministic connection-string credential detection."""

from collections import deque
from dataclasses import dataclass
import re
from urllib.parse import unquote

from ..connection_string import ConnectionStringConfig
from ..findings import Action, Severity, Span
from ..inspection import Inspection, ScanScope
from .base import Rule, RuleMatch


# Fixed literal alternatives and bounded lookbehind. There are no nested or
# ambiguous quantifiers. Candidate validation uses bounded explicit parsing.
_URI_PREFIX = re.compile(
    r"(?<![A-Za-z0-9+._:-])"
    r"(?P<scheme>amqps?|mongodb(?:\+srv)?|postgres(?:ql)?|rediss?|sqlserver)"
    r"://",
    re.ASCII | re.IGNORECASE,
)
_URI_AUTHORITY_END = re.compile(r"[/?#\s\"'<>`]", re.ASCII)
_KEYWORD_FIELD = re.compile(
    r"(?P<context>"
    r"(?<![A-Za-z0-9_])(?:server|data[ \t]+source)[ \t]*="
    r")"
    r"|(?P<password>"
    r"(?<![A-Za-z0-9_])(?:password|pwd)[ \t]*="
    r")",
    re.ASCII | re.IGNORECASE,
)
_HEX = frozenset("0123456789abcdefABCDEF")
_PLACEHOLDERS = frozenset(
    (
        "<password>",
        "<pwd>",
        "${password}",
        "${pwd}",
        "{{password}}",
        "{{pwd}}",
        "%password%",
        "%pwd%",
        "your password",
        "your_password",
        "your-password",
    )
)


def _valid_percent_encoding(value: str) -> bool:
    index = value.find("%")
    while index >= 0:
        if (
            index + 2 >= len(value)
            or value[index + 1] not in _HEX
            or value[index + 2] not in _HEX
        ):
            return False
        index = value.find("%", index + 3)
    return True


def _is_placeholder(value: str, *, percent_encoded: bool) -> bool:
    candidate = unquote(value) if percent_encoded else value
    return candidate.strip().lower() in _PLACEHOLDERS


def _uri_credential_span(
    text: str,
    prefix: re.Match[str],
) -> tuple[int, int] | None:
    authority_start = prefix.end()
    boundary = _URI_AUTHORITY_END.search(text, authority_start)
    authority_end = len(text) if boundary is None else boundary.start()
    userinfo_end = text.rfind("@", authority_start, authority_end)
    if userinfo_end < 0:
        return None
    separator = text.find(":", authority_start, userinfo_end)
    if separator < 0 or separator + 1 >= userinfo_end:
        return None
    return separator + 1, userinfo_end


def _quoted_value_end(
    text: str,
    start: int,
    quote: str,
    scan_end: int,
) -> tuple[int, bool]:
    cursor = start
    while cursor < scan_end:
        character = text[cursor]
        if character in "\r\n":
            return cursor, False
        if character == quote:
            if cursor + 1 < scan_end and text[cursor + 1] == quote:
                cursor += 2
                continue
            return cursor, True
        cursor += 1
    return scan_end, False


def _braced_value_end(
    text: str,
    start: int,
    scan_end: int,
) -> tuple[int, bool]:
    cursor = start
    while cursor < scan_end:
        character = text[cursor]
        if character in "\r\n":
            return cursor, False
        if character == "}":
            if cursor + 1 < scan_end and text[cursor + 1] == "}":
                cursor += 2
                continue
            return cursor, True
        cursor += 1
    return scan_end, False


def _unquoted_value_end(text: str, start: int, scan_end: int) -> int:
    cursor = start
    while cursor < scan_end and text[cursor] not in ";\r\n\"'<>`":
        cursor += 1
    end = cursor
    while end > start and text[end - 1] in " \t":
        end -= 1
    return end


def _keyword_credential_span(
    text: str,
    prefix: re.Match[str],
    max_credential_chars: int,
) -> tuple[int, int, bool, int | None, int]:
    start = prefix.end()
    while start < len(text) and text[start] in " \t":
        start += 1
    if start >= len(text) or text[start] in ";\r\n":
        return start, start, True, None, start
    opener = text[start]
    value_start = start + 1 if opener in ('"', "{") else start
    scan_end = min(len(text), value_start + max_credential_chars + 1)
    if opener == '"':
        end, closed = _quoted_value_end(text, value_start, '"', scan_end)
    elif opener == "{":
        end, closed = _braced_value_end(text, value_start, scan_end)
    else:
        end = _unquoted_value_end(text, value_start, scan_end)
        closed = end < scan_end or scan_end == len(text)
    if not closed and end >= scan_end and scan_end < len(text):
        line_end = text.find("\n", end)
        end = len(text) if line_end < 0 else line_end
        if end > value_start and text[end - 1] == "\r":
            end -= 1
    after = end
    if opener in ('"', "{") and closed:
        after += 1
    while after < len(text) and text[after] in " \t":
        after += 1
    separator = after if after < len(text) and text[after] == ";" else None
    field_end = separator + 1 if separator is not None else after
    return value_start, end, closed, separator, field_end


def _field_boundary(
    text: str,
    start: int,
    max_field_chars: int,
) -> tuple[int | None, int]:
    while start < len(text) and text[start] in " \t":
        start += 1
    scan_end = min(len(text), start + max_field_chars + 1)
    if start >= scan_end or text[start] in "\r\n":
        return None, start
    opener = text[start]
    if opener == '"':
        end, closed = _quoted_value_end(text, start + 1, '"', scan_end)
        after = end + 1 if closed else end
    elif opener == "{":
        end, closed = _braced_value_end(text, start + 1, scan_end)
        after = end + 1 if closed else end
    else:
        after = _unquoted_value_end(text, start, scan_end)
    while after < len(text) and text[after] in " \t":
        after += 1
    separator = after if after < len(text) and text[after] == ";" else None
    return separator, separator + 1 if separator is not None else after


@dataclass(frozen=True, slots=True)
class _CredentialCandidate:
    prefix_start: int
    start: int
    end: int
    scheme: str
    credential_form: str
    valid: bool


def _uri_candidates(
    text: str,
    config: ConnectionStringConfig,
    limit: int,
) -> tuple[_CredentialCandidate, ...]:
    candidates: list[_CredentialCandidate] = []
    for prefix in _URI_PREFIX.finditer(text):
        span = _uri_credential_span(text, prefix)
        if span is None:
            continue
        start, end = span
        valid = True
        if end - start <= config.max_credential_chars:
            value = text[start:end]
            if _is_placeholder(value, percent_encoded=True):
                continue
            valid = _valid_percent_encoding(value)
        candidates.append(
            _CredentialCandidate(
                prefix_start=prefix.start(),
                start=start,
                end=end,
                scheme=prefix.group("scheme").lower(),
                credential_form="uri_userinfo",
                valid=valid,
            )
        )
        if len(candidates) >= limit:
            break
    return tuple(candidates)


def _keyword_candidates(
    text: str,
    config: ConnectionStringConfig,
    limit: int,
) -> tuple[_CredentialCandidate, ...]:
    candidates: list[_CredentialCandidate] = []
    pending: deque[tuple[_CredentialCandidate, int]] = deque()
    last_context_separator: int | None = None
    previous_end = 0
    skip_until = 0
    for field in _KEYWORD_FIELD.finditer(text):
        if text.find("\n", previous_end, field.start()) >= 0:
            pending.clear()
            last_context_separator = None
            skip_until = 0
        previous_end = field.end()
        if field.start() < skip_until:
            continue
        minimum = field.start() - config.max_connection_chars
        while pending and pending[0][0].prefix_start < minimum:
            pending.popleft()
        if field.group("context") is not None:
            for candidate, pending_separator in pending:
                if pending_separator < field.start():
                    candidates.append(candidate)
                    if len(candidates) >= limit:
                        return tuple(candidates)
            pending.clear()
            last_context_separator, skip_until = _field_boundary(
                text,
                field.end(),
                config.max_connection_chars,
            )
            continue

        has_prior_context = (
            last_context_separator is not None
            and last_context_separator < field.start()
            and last_context_separator >= minimum
        )
        if not has_prior_context and len(pending) >= limit:
            continue
        start, end, valid, separator, skip_until = _keyword_credential_span(
            text,
            field,
            config.max_credential_chars,
        )
        if end <= start:
            continue
        if end - start <= config.max_credential_chars:
            value = text[start:end]
            if _is_placeholder(value, percent_encoded=False):
                continue
        candidate = _CredentialCandidate(
            prefix_start=field.start(),
            start=start,
            end=end,
            scheme="keyword",
            credential_form="keyword_pair",
            valid=valid,
        )
        if has_prior_context:
            candidates.append(candidate)
            if len(candidates) >= limit:
                return tuple(candidates)
        elif separator is not None:
            pending.append((candidate, separator))
    return tuple(candidates)


class ConnectionStringRule(Rule):
    """Find credentials in explicit URI and ADO/ODBC connection strings."""

    RULE_ID = "secrets.connection_string"
    PURPOSE = "Detect credentials embedded in connection strings."
    SCOPES = frozenset((ScanScope.INPUT, ScanScope.OUTPUT))

    def __init__(self, config: ConnectionStringConfig | None = None) -> None:
        if config is not None and not isinstance(config, ConnectionStringConfig):
            raise TypeError("config must be a ConnectionStringConfig or None")
        self._config = config if config is not None else ConnectionStringConfig()

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
    def config(self) -> ConnectionStringConfig:
        return self._config

    def _match(
        self,
        *,
        start: int,
        end: int,
        scheme: str,
        credential_form: str,
        valid: bool,
    ) -> RuleMatch:
        length = end - start
        if length > self._config.max_credential_chars or not valid:
            return RuleMatch(
                span=Span(start, end),
                severity=Severity.HIGH,
                action=(
                    Action.BLOCK
                    if length > self._config.max_credential_chars
                    else Action.REDACT
                ),
                message=(
                    "Connection-string credential exceeds inspection limit."
                    if length > self._config.max_credential_chars
                    else "Connection-string credential detected."
                ),
                redacted_preview=(
                    None
                    if length > self._config.max_credential_chars
                    else "[REDACTED:connection_string_credential]"
                ),
                metadata={
                    "reason": (
                        "credential_limit_exceeded"
                        if length > self._config.max_credential_chars
                        else "malformed_connection_string_credential"
                    ),
                    "scheme": scheme,
                    "credential_form": credential_form,
                    "detector": "bounded_connection_string",
                    "span_basis": "characters",
                },
            )
        return RuleMatch(
            span=Span(start, end),
            severity=Severity.HIGH,
            action=Action.REDACT,
            message="Connection-string credential detected.",
            redacted_preview="[REDACTED:connection_string_credential]",
            metadata={
                "reason": "connection_string_credential",
                "scheme": scheme,
                "credential_form": credential_form,
                "detector": "bounded_connection_string",
                "span_basis": "characters",
            },
        )

    def scan(self, inspection: Inspection) -> tuple[RuleMatch, ...]:
        if not isinstance(inspection, Inspection):
            raise TypeError("inspection must be an Inspection")
        text = inspection.text
        collection_limit = self._config.max_candidates + 1
        candidates = tuple(
            sorted(
                (
                    *_uri_candidates(text, self._config, collection_limit),
                    *_keyword_candidates(
                        text,
                        self._config,
                        collection_limit,
                    ),
                ),
                key=lambda candidate: (
                    candidate.prefix_start,
                    candidate.start,
                    candidate.end,
                ),
            )
        )
        matches: list[RuleMatch] = []
        for index, candidate in enumerate(candidates):
            if index >= self._config.max_candidates:
                matches.append(
                    RuleMatch(
                        span=Span(candidate.prefix_start, len(text)),
                        severity=Severity.HIGH,
                        action=Action.BLOCK,
                        message=(
                            "Connection-string credential inspection limit "
                            "exceeded."
                        ),
                        metadata={
                            "reason": "candidate_limit_exceeded",
                            "limit": str(self._config.max_candidates),
                            "detector": "bounded_connection_string",
                            "span_basis": "characters",
                        },
                    )
                )
                break
            matches.append(
                self._match(
                    start=candidate.start,
                    end=candidate.end,
                    scheme=candidate.scheme,
                    credential_form=candidate.credential_form,
                    valid=candidate.valid,
                )
            )
        return tuple(matches)


__all__ = ["ConnectionStringRule"]
