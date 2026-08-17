"""Deterministic registered-length and MOD-97 IBAN detection."""

import re

from ..findings import Action, Severity, Span
from ..iban import (
    IBANConfig,
    IBAN_LENGTHS,
    IBAN_REGISTRY_ISSUED,
    IBAN_REGISTRY_RELEASE,
)
from ..inspection import Inspection, ScanScope
from .base import Rule, RuleMatch


# Fixed-width prefix discovery with unambiguous lookarounds. Candidate parsing
# and checksum validation are explicit bounded loops.
_IBAN_PREFIX = re.compile(
    r"(?<![A-Za-z0-9_])(?P<country>[A-Z]{2})(?P<check>[0-9]{2})",
    re.ASCII,
)
_ASCII_ALNUM = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)
_DIGITS = "0123456789"


def _parse_candidate(
    text: str,
    start: int,
    compact_length: int,
) -> tuple[int, str] | None:
    compact: list[str] = []
    position = start
    spaced = False
    while len(compact) < compact_length:
        if position >= len(text):
            return None
        character = text[position]
        if character in _ASCII_ALNUM:
            if spaced and compact and len(compact) % 4 == 0:
                return None
            compact.append(character)
            position += 1
            continue
        if (
            character == " "
            and compact
            and len(compact) % 4 == 0
            and position + 1 < len(text)
            and text[position + 1] in _ASCII_ALNUM
        ):
            if not spaced and len(compact) != 4:
                return None
            spaced = True
            compact.append(text[position + 1])
            position += 2
            continue
        return None
    if position < len(text) and (
        text[position].isalnum() or text[position] == "_"
    ):
        return None
    return position, "".join(compact)


def _mod97_is_valid(compact: str) -> bool:
    remainder = 0
    for character in compact[4:] + compact[:4]:
        if "0" <= character <= "9":
            remainder = (remainder * 10 + ord(character) - ord("0")) % 97
        else:
            remainder = (remainder * 100 + ord(character) - ord("A") + 10) % 97
    return remainder == 1


class IBANRule(Rule):
    """Find checksum-valid IBANs from registered countries."""

    RULE_ID = "pii.iban"
    PURPOSE = "Detect registered-length, MOD-97-valid IBANs for redaction."
    SCOPES = frozenset((ScanScope.INPUT, ScanScope.OUTPUT))

    def __init__(self, config: IBANConfig | None = None) -> None:
        if config is not None and not isinstance(config, IBANConfig):
            raise TypeError("config must be an IBANConfig or None")
        self._config = config if config is not None else IBANConfig()

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
    def config(self) -> IBANConfig:
        return self._config

    def scan(self, inspection: Inspection) -> tuple[RuleMatch, ...]:
        if not isinstance(inspection, Inspection):
            raise TypeError("inspection must be an Inspection")
        text = inspection.text
        if len(text) < 15 or not any(digit in text for digit in _DIGITS):
            return ()

        matches: list[RuleMatch] = []
        candidate_count = 0
        for prefix in _IBAN_PREFIX.finditer(text):
            if prefix.start() > 0 and (
                text[prefix.start() - 1].isalnum()
                or text[prefix.start() - 1] == "_"
            ):
                continue
            country = prefix.group("country")
            compact_length = IBAN_LENGTHS.get(country)
            if compact_length is None:
                continue
            candidate_count += 1
            if candidate_count > self._config.max_candidates:
                matches.append(
                    RuleMatch(
                        span=Span(prefix.start(), len(text)),
                        severity=Severity.HIGH,
                        action=Action.BLOCK,
                        message="IBAN candidate inspection limit exceeded.",
                        metadata={
                            "reason": "candidate_limit_exceeded",
                            "limit": str(self._config.max_candidates),
                            "detector": "registered_length_mod97",
                            "registry_release": IBAN_REGISTRY_RELEASE,
                            "span_basis": "characters",
                        },
                    )
                )
                break
            parsed = _parse_candidate(text, prefix.start(), compact_length)
            if parsed is None:
                continue
            end, compact = parsed
            if not _mod97_is_valid(compact):
                continue
            matches.append(
                RuleMatch(
                    span=Span(prefix.start(), end),
                    severity=Severity.HIGH,
                    action=Action.REDACT,
                    message="Potentially sensitive IBAN detected.",
                    redacted_preview="[REDACTED:iban]",
                    metadata={
                        "reason": "registered_length_mod97",
                        "country_code": country,
                        "format": (
                            "print"
                            if " " in text[prefix.start() : end]
                            else "electronic"
                        ),
                        "detector": "registered_length_mod97",
                        "registry_release": IBAN_REGISTRY_RELEASE,
                        "registry_issued": IBAN_REGISTRY_ISSUED,
                        "span_basis": "characters",
                    },
                )
            )
        return tuple(matches)


__all__ = ["IBANRule"]
