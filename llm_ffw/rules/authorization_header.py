"""Deterministic Basic and Bearer Authorization-header detection."""

from base64 import b64decode, b64encode
from binascii import Error as Base64Error
import re

from ..authorization_header import AuthorizationHeaderConfig
from ..findings import Action, Severity, Span
from ..inspection import Inspection, ScanScope
from .base import Rule, RuleMatch


# Fixed literals and bounded alternatives anchored to the start of a line.
# Credential parsing is performed by explicit bounded character checks.
_HEADER_PREFIX = re.compile(
    r"^[ \t]*authorization:[ \t]*(?P<scheme>basic|bearer)[ \t]+",
    re.ASCII | re.IGNORECASE | re.MULTILINE,
)
_BEARER_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/"
)
_BASIC_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
)
_PLACEHOLDERS = frozenset(("<token>", "your token"))


def _credential_end(text: str, start: int) -> tuple[int, int]:
    newline = text.find("\n", start)
    line_end = len(text) if newline < 0 else newline
    end = line_end
    if end > start and text[end - 1] == "\r":
        end -= 1
    while end > start and text[end - 1] in " \t":
        end -= 1
    return end, line_end


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
    """Find credentials in line-oriented HTTP Authorization headers."""

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
        for prefix in _HEADER_PREFIX.finditer(text):
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

            start = prefix.end()
            end, line_end = _credential_end(text, start)
            credential_length = end - start
            scheme = prefix.group("scheme").lower()
            if credential_length > self._config.max_credential_chars:
                matches.append(
                    RuleMatch(
                        span=Span(start, line_end),
                        severity=Severity.HIGH,
                        action=Action.BLOCK,
                        message="Authorization credential exceeds inspection limit.",
                        metadata={
                            "reason": "credential_limit_exceeded",
                            "limit": str(self._config.max_credential_chars),
                            "scheme": scheme,
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
                        "detector": "bounded_authorization_header",
                        "span_basis": "characters",
                    },
                )
            )
        return tuple(matches)


__all__ = ["AuthorizationHeaderRule"]
