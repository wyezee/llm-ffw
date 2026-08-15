"""Deterministic detection of structurally plausible payment-card numbers."""

import re

from ..findings import Action, Severity, Span
from ..inspection import Inspection, ScanScope
from ..payment_card import PaymentCardConfig
from .base import Rule, RuleMatch


# A candidate contains 13-19 ASCII digits with at most one space or hyphen
# between adjacent digits. Both repetitions are bounded and consume a digit on
# every iteration, so attacker input cannot cause catastrophic backtracking.
# The second lookbehind/ahead prevents matching a suffix or prefix of a longer
# separated numeric run.
_CARD_CANDIDATE = re.compile(
    r"(?<![0-9])(?<![0-9][ -])"
    r"(?P<card>[0-9](?:[ -]?[0-9]){12,18})"
    r"(?![0-9])(?![ -][0-9])",
    re.ASCII,
)


def _candidate_properties(
    text: str,
    start: int,
    end: int,
) -> tuple[int, str] | None:
    digit_count = 0
    separator = ""
    first_digit = ""
    varied = False
    for character in text[start:end]:
        if "0" <= character <= "9":
            digit_count += 1
            if not first_digit:
                first_digit = character
            elif character != first_digit:
                varied = True
            continue
        if separator and character != separator:
            return None
        separator = character
    if not varied:
        return None
    format_name = {
        "": "contiguous",
        " ": "space_separated",
        "-": "hyphen_separated",
    }[separator]
    return digit_count, format_name


def _passes_luhn(text: str, start: int, end: int) -> bool:
    checksum = 0
    double = False
    for index in range(end - 1, start - 1, -1):
        character = text[index]
        if character in " -":
            continue
        value = ord(character) - ord("0")
        if double:
            value *= 2
            if value > 9:
                value -= 9
        checksum += value
        double = not double
    return checksum % 10 == 0


class PaymentCardRule(Rule):
    """Find bounded ASCII payment-card candidates that pass Luhn."""

    RULE_ID = "pii.payment_card"
    PURPOSE = "Detect structurally plausible payment-card numbers."
    SCOPES = frozenset((ScanScope.INPUT, ScanScope.OUTPUT))

    def __init__(self, config: PaymentCardConfig | None = None) -> None:
        if config is not None and not isinstance(config, PaymentCardConfig):
            raise TypeError("config must be a PaymentCardConfig or None")
        self._config = config if config is not None else PaymentCardConfig()

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
    def config(self) -> PaymentCardConfig:
        return self._config

    def scan(self, inspection: Inspection) -> tuple[RuleMatch, ...]:
        if not isinstance(inspection, Inspection):
            raise TypeError("inspection must be an Inspection")
        text = inspection.text
        matches: list[RuleMatch] = []
        candidate_count = 0
        for candidate in _CARD_CANDIDATE.finditer(text):
            if candidate_count >= self._config.max_candidates:
                matches.append(
                    RuleMatch(
                        span=Span(candidate.start(), len(text)),
                        severity=Severity.HIGH,
                        action=Action.BLOCK,
                        message="Payment-card candidate inspection limit exceeded.",
                        metadata={
                            "reason": "candidate_limit_exceeded",
                            "limit": str(self._config.max_candidates),
                            "detector": "luhn_checksum",
                            "span_basis": "characters",
                        },
                    )
                )
                break
            candidate_count += 1
            start, end = candidate.span("card")
            properties = _candidate_properties(text, start, end)
            if properties is None or not _passes_luhn(text, start, end):
                continue
            digit_count, format_name = properties
            matches.append(
                RuleMatch(
                    span=Span(start, end),
                    severity=Severity.HIGH,
                    action=Action.REDACT,
                    message="Potential payment-card number detected.",
                    redacted_preview="[REDACTED:payment_card]",
                    metadata={
                        "reason": "luhn_valid_candidate",
                        "detector": "luhn_checksum",
                        "digit_count": str(digit_count),
                        "format": format_name,
                        "span_basis": "characters",
                    },
                )
            )
        return tuple(matches)


__all__ = ["PaymentCardRule"]
