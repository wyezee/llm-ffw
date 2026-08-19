"""Deterministic Basic and Bearer Authorization credential detection."""

from base64 import b64decode, b64encode
from binascii import Error as Base64Error
import re

from ..authorization_header import AuthorizationHeaderConfig
from ..findings import Action, Severity, Span
from ..inspection import Inspection, ScanScope
from .base import Rule, RuleMatch


# Fixed literals, disjoint syntax alternatives, and simple whitespace runs.
# There are no nested or ambiguous quantifiers. Credential parsing is performed
# by explicit bounded character checks after one combined discovery pass.
_AUTHORIZATION_PREFIX = re.compile(
    r"(?P<header>"
    r"^[ \t]*authorization:[ \t]*"
    r"(?P<header_scheme>basic|bearer)[ \t]+"
    r")"
    r"|(?P<curl>"
    r"^[ \t]*curl[ \t]+(?:-H|--header)[ \t]+"
    r"(?P<curl_quote>[\"'])authorization:[ \t]*"
    r"(?P<curl_scheme>basic|bearer)[ \t]+"
    r")"
    r"|(?P<json>"
    r"[{,][ \t\r\n]*\"authorization\"[ \t\r\n]*:"
    r"[ \t\r\n]*\"(?P<json_scheme>basic|bearer)[ \t]+"
    r")",
    re.ASCII | re.IGNORECASE | re.MULTILINE,
)
_BEARER_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/"
)
_BASIC_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
)
_PLACEHOLDERS = frozenset(("<token>", "your token"))


def _line_credential_end(text: str, start: int) -> tuple[int, int]:
    newline = text.find("\n", start)
    line_end = len(text) if newline < 0 else newline
    end = line_end
    if end > start and text[end - 1] == "\r":
        end -= 1
    while end > start and text[end - 1] in " \t":
        end -= 1
    return end, line_end


def _quoted_credential_end(
    text: str,
    start: int,
    quote: str,
) -> tuple[int, int]:
    newline = text.find("\n", start)
    line_end = len(text) if newline < 0 else newline
    quote_end = text.find(quote, start, line_end)
    boundary = line_end if quote_end < 0 else quote_end
    end = boundary
    if end > start and text[end - 1] == "\r":
        end -= 1
    while end > start and text[end - 1] in " \t":
        end -= 1
    return end, boundary


def _prefix_details(prefix: re.Match[str]) -> tuple[str, str, str | None]:
    if prefix.group("header") is not None:
        return "header", prefix.group("header_scheme").lower(), None
    if prefix.group("curl") is not None:
        return (
            "curl",
            prefix.group("curl_scheme").lower(),
            prefix.group("curl_quote"),
        )
    return "json", prefix.group("json_scheme").lower(), '"'


def _valid_bearer(value: str) -> bool:
    padding = value.find("=")
    body = value if padding < 0 else value[:padding]
    return (
        bool(body)
        and all(character in _BEARER_CHARS for character in body)
        and (
            padding < 0
            or all(character == "=" for character in value[padding:])
        )
    )


def _valid_basic(value: str) -> bool:
    if not value or len(value) % 4 or any(
        character not in _BASIC_CHARS for character in value
    ):
        return False
    try:
        decoded = b64decode(value, validate=True)
    except (Base64Error, ValueError):
        return False
    return b":" in decoded and b64encode(decoded).decode("ascii") == value


def _is_placeholder(value: str) -> bool:
    return value.lower() in _PLACEHOLDERS


class AuthorizationHeaderRule(Rule):
    """Find credentials in explicit HTTP Authorization syntaxes."""

    RULE_ID = "secrets.authorization_header"
    PURPOSE = "Detect Basic and Bearer Authorization-header credentials."
    SCOPES = frozenset((ScanScope.INPUT, ScanScope.OUTPUT))

    def __init__(self, config: AuthorizationHeaderConfig | None = None) -> None:
        if config is not None and not isinstance(
            config, AuthorizationHeaderConfig
        ):
            raise TypeError("config must be an AuthorizationHeaderConfig or None")
        self._config = (
            config if config is not None else AuthorizationHeaderConfig()
        )

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
    def config(self) -> AuthorizationHeaderConfig:
        return self._config

    def scan(self, inspection: Inspection) -> tuple[RuleMatch, ...]:
        if not isinstance(inspection, Inspection):
            raise TypeError("inspection must be an Inspection")
        text = inspection.text
        matches: list[RuleMatch] = []
        candidate_count = 0
        for prefix in _AUTHORIZATION_PREFIX.finditer(text):
            candidate_count += 1
            if candidate_count > self._config.max_candidates:
                matches.append(
                    RuleMatch(
                        span=Span(prefix.start(), len(text)),
                        severity=Severity.HIGH,
                        action=Action.BLOCK,
                        message=(
                            "Authorization-header candidate inspection limit "
                            "exceeded."
                        ),
                        metadata={
                            "reason": "candidate_limit_exceeded",
                            "limit": str(self._config.max_candidates),
                            "detector": "bounded_authorization_header",
                            "span_basis": "characters",
                        },
                    )
                )
                break

            syntax, scheme, quote = _prefix_details(prefix)
            start = prefix.end()
            end, candidate_end = (
                _line_credential_end(text, start)
                if quote is None
                else _quoted_credential_end(text, start, quote)
            )
            credential_length = end - start
            if credential_length > self._config.max_credential_chars:
                matches.append(
                    RuleMatch(
                        span=Span(start, candidate_end),
                        severity=Severity.HIGH,
                        action=Action.BLOCK,
                        message="Authorization credential exceeds inspection limit.",
                        metadata={
                            "reason": "credential_limit_exceeded",
                            "limit": str(self._config.max_credential_chars),
                            "scheme": scheme,
                            "syntax": syntax,
                            "detector": "bounded_authorization_header",
                            "span_basis": "characters",
                        },
                    )
                )
                continue
            if credential_length <= 0:
                continue
            value = text[start:end]
            valid = (
                _valid_basic(value)
                if scheme == "basic"
                else _valid_bearer(value)
            )
            if not valid and _is_placeholder(value):
                continue
            reason = (
                "authorization_credential"
                if valid
                else "malformed_authorization_credential"
            )
            matches.append(
                RuleMatch(
                    span=Span(start, end),
                    severity=Severity.HIGH,
                    action=Action.REDACT,
                    message="Authorization-header credential detected.",
                    redacted_preview="[REDACTED:authorization_credential]",
                    metadata={
                        "reason": reason,
                        "scheme": scheme,
                        "syntax": syntax,
                        "detector": "bounded_authorization_header",
                        "span_basis": "characters",
                    },
                )
            )
        return tuple(matches)


__all__ = ["AuthorizationHeaderRule"]
