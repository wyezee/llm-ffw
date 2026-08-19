"""Deterministic conservative ASCII email-address detection."""

from dataclasses import dataclass
import re

from ..email_address import EmailAddressConfig
from ..findings import Action, Severity, Span
from ..inspection import Inspection, ScanScope
from .base import Rule, RuleMatch


_LOCAL_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789._%+-"
)
_DOMAIN_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-."
)
_MAX_LOCAL_CHARS = 64
_MAX_DOMAIN_CHARS = 253
_MAX_ADDRESS_CHARS = 254
_EMAIL_MARKER = re.compile(r"(?<=[A-Za-z0-9_%+.-])@", re.ASCII)


@dataclass(frozen=True, slots=True)
class _EmailCandidate:
    start: int
    end: int


def _is_ascii_identifier_char(character: str) -> bool:
    return character == "_" or (
        character.isascii() and character.isalnum()
    )


def _candidate_at(text: str, marker: int) -> _EmailCandidate | None:
    start = marker
    while (
        start > 0
        and marker - start < _MAX_LOCAL_CHARS + 1
        and text[start - 1] in _LOCAL_CHARS
    ):
        start -= 1
    while start < marker and text[start] == ".":
        start += 1
    if start == marker or (
        start > 0
        and (
            text[start - 1] == "@"
            or _is_ascii_identifier_char(text[start - 1])
        )
    ):
        return None

    domain_start = marker + 1
    end = domain_start
    text_length = len(text)
    while (
        end < text_length
        and end - domain_start < _MAX_DOMAIN_CHARS + 1
        and text[end] in _DOMAIN_CHARS
    ):
        end += 1
    while end > domain_start and text[end - 1] == ".":
        end -= 1
    if end == domain_start or (
        end < text_length
        and (
            text[end] == "@"
            or _is_ascii_identifier_char(text[end])
        )
    ):
        return None
    return _EmailCandidate(start, end)


def _valid_local_part(local_part: str) -> bool:
    return (
        0 < len(local_part) <= _MAX_LOCAL_CHARS
        and local_part[0] != "."
        and local_part[-1] != "."
        and ".." not in local_part
        and all(character in _LOCAL_CHARS for character in local_part)
    )


def _valid_domain(domain: str) -> tuple[bool, bool]:
    if not 0 < len(domain) <= _MAX_DOMAIN_CHARS or "." not in domain:
        return False, False
    labels = domain.split(".")
    for label in labels:
        if (
            not 0 < len(label) <= 63
            or label[0] == "-"
            or label[-1] == "-"
            or not all(
                (
                    character.isascii()
                    and (character.isalnum() or character == "-")
                )
                for character in label
            )
        ):
            return False, False
    final_label = labels[-1]
    has_punycode = any(label.lower().startswith("xn--") for label in labels)
    if final_label.lower().startswith("xn--"):
        return len(final_label) > 4, has_punycode
    return (
        len(final_label) >= 2
        and final_label.isascii()
        and final_label.isalpha(),
        has_punycode,
    )


class EmailAddressRule(Rule):
    """Find conservative ASCII Internet mailboxes for privacy redaction."""

    RULE_ID = "pii.email_address"
    PURPOSE = "Detect conservative ASCII email addresses for privacy redaction."
    SCOPES = frozenset((ScanScope.INPUT, ScanScope.OUTPUT))

    def __init__(self, config: EmailAddressConfig | None = None) -> None:
        if config is not None and not isinstance(config, EmailAddressConfig):
            raise TypeError("config must be an EmailAddressConfig or None")
        self._config = config if config is not None else EmailAddressConfig()

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
    def config(self) -> EmailAddressConfig:
        return self._config

    def scan(self, inspection: Inspection) -> tuple[RuleMatch, ...]:
        if not isinstance(inspection, Inspection):
            raise TypeError("inspection must be an Inspection")
        text = inspection.text
        if "@" not in text:
            return ()

        matches: list[RuleMatch] = []
        candidate_count = 0
        for marker_match in _EMAIL_MARKER.finditer(text):
            marker = marker_match.start()
            candidate = _candidate_at(text, marker)
            if candidate is None:
                continue
            if candidate_count >= self._config.max_candidates:
                matches.append(
                    RuleMatch(
                        span=Span(marker, len(text)),
                        severity=Severity.HIGH,
                        action=Action.BLOCK,
                        message="Email-address candidate inspection limit exceeded.",
                        metadata={
                            "reason": "candidate_limit_exceeded",
                            "limit": str(self._config.max_candidates),
                            "detector": "bounded_ascii_mailbox",
                            "span_basis": "characters",
                        },
                    )
                )
                break
            candidate_count += 1
            value = text[candidate.start : candidate.end]
            if len(value) > _MAX_ADDRESS_CHARS:
                continue
            local_part, domain = value.rsplit("@", 1)
            if not _valid_local_part(local_part):
                continue
            valid_domain, is_punycode = _valid_domain(domain)
            if not valid_domain:
                continue
            matches.append(
                RuleMatch(
                    span=Span(candidate.start, candidate.end),
                    severity=Severity.MEDIUM,
                    action=Action.REDACT,
                    message="Potentially sensitive email address detected.",
                    redacted_preview="[REDACTED:email_address]",
                    metadata={
                        "reason": "conservative_email_address",
                        "address_syntax": "conservative_ascii",
                        "domain_kind": (
                            "punycode_dns_syntax"
                            if is_punycode
                            else "ascii_dns_syntax"
                        ),
                        "detector": "bounded_ascii_mailbox",
                        "span_basis": "characters",
                    },
                )
            )
        return tuple(matches)


__all__ = ["EmailAddressRule"]
