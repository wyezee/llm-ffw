"""Deterministic conservative E.164-style phone-number detection."""

import re

from ..findings import Action, Severity, Span
from ..inspection import Inspection, ScanScope
from ..phone_number import PhoneNumberConfig
from .base import Rule, RuleMatch


# Fixed ASCII boundaries and a bounded quantifier keep discovery linear. The
# leading plus is presentation syntax. Seven digits is a conservative product
# floor; 15 is the E.164 maximum. Assignment and country codes are not checked.
_CANONICAL_GLOBAL_NUMBER = re.compile(
    r"(?<![+0-9A-Za-z_])\+[1-9][0-9]{6,14}(?![0-9A-Za-z_])",
    re.ASCII,
)
_VISUAL_SEPARATORS = frozenset(" .-()")
_MAX_CONTINUATION_LOOKAHEAD = 8


def _has_formatted_continuation(text: str, end: int) -> bool:
    """Reject a canonical-looking prefix of a visually separated number."""

    cursor = end
    stop = min(len(text), end + _MAX_CONTINUATION_LOOKAHEAD)
    while cursor < stop and text[cursor] in _VISUAL_SEPARATORS:
        cursor += 1
    return cursor > end and cursor < len(text) and text[cursor] in "0123456789"


class PhoneNumberRule(Rule):
    """Find conservative E.164-style values for privacy redaction."""

    RULE_ID = "pii.phone_number"
    PURPOSE = "Detect conservative E.164-style phone numbers for redaction."
    SCOPES = frozenset((ScanScope.INPUT, ScanScope.OUTPUT))

    def __init__(self, config: PhoneNumberConfig | None = None) -> None:
        if config is not None and not isinstance(config, PhoneNumberConfig):
            raise TypeError("config must be a PhoneNumberConfig or None")
        self._config = config if config is not None else PhoneNumberConfig()

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
    def config(self) -> PhoneNumberConfig:
        return self._config

    def scan(self, inspection: Inspection) -> tuple[RuleMatch, ...]:
        if not isinstance(inspection, Inspection):
            raise TypeError("inspection must be an Inspection")
        text = inspection.text
        if "+" not in text:
            return ()

        matches: list[RuleMatch] = []
        candidate_count = 0
        for candidate in _CANONICAL_GLOBAL_NUMBER.finditer(text):
            if _has_formatted_continuation(text, candidate.end()):
                continue
            if candidate_count >= self._config.max_candidates:
                matches.append(
                    RuleMatch(
                        span=Span(candidate.start(), len(text)),
                        severity=Severity.HIGH,
                        action=Action.BLOCK,
                        message=(
                            "Phone-number candidate inspection limit exceeded."
                        ),
                        metadata={
                            "reason": "candidate_limit_exceeded",
                            "limit": str(self._config.max_candidates),
                            "detector": "bounded_e164_style",
                            "span_basis": "characters",
                        },
                    )
                )
                break
            candidate_count += 1
            value = candidate.group(0)
            matches.append(
                RuleMatch(
                    span=Span(candidate.start(), candidate.end()),
                    severity=Severity.MEDIUM,
                    action=Action.REDACT,
                    message="Potentially sensitive phone number detected.",
                    redacted_preview="[REDACTED:phone_number]",
                    metadata={
                        "reason": "canonical_global_phone_number",
                        "number_syntax": "conservative_e164_style",
                        "validation": "syntax_and_length_only",
                        "digit_count": str(len(value) - 1),
                        "detector": "bounded_e164_style",
                        "span_basis": "characters",
                    },
                )
            )
        return tuple(matches)


__all__ = ["PhoneNumberRule"]
